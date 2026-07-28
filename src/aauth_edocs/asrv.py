"""Access Server: evaluates resource policy and issues auth tokens (§9.1).

Only PSes call the AS token endpoint (§9.3); they authenticate with the
jwks_uri Signature-Key scheme. Internal-experimentation scope: the policy
hook decides on the spot (no requirement=claims/interaction rounds — the
spec allows scope-only auth tokens), and any resolvable PS is trusted.

Module is named `asrv` because `as` is a Python keyword.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from flask import Flask, request

from .agent import RequestsTransport
from .controller import ControllerPolicy, issue_controller_decision
from .edocs import Dataflow, FunctionDescriptor, validate_function_args
from .errors import AAuthError, DENIED, INVALID_REQUEST, INVALID_TOKEN
from .deferred import PendingStore
from .headers import APPROVAL, CLAIMS, INTERACTION, build_requirement
from .httpsig import HttpRequest, verify
from .ids import DWK_ACCESS
from .keys import SigningKey, jwk_thumbprint
from .metadata import JwksResolver, build_metadata
from .tokens import issue_auth_token, verify_agent_token, verify_resource_token

# policy(ps_url, agent_claims, resource_token_claims) -> granted scope | None (deny) | deferred dict
Policy = Callable[[str, dict, dict], "str | None | dict[str, Any]"]


def create_as(
    issuer: str,
    key: SigningKey | None = None,
    policy: Policy | None = None,
    transport=None,
    app: Flask | None = None,
    token_path: str = "/token",
    jwks_path: str = "/jwks.json",
    pending_path: str = "/pending",
    sentinel: str | None = None,
    controller_policy: ControllerPolicy | None = None,
    functions: Mapping[str, FunctionDescriptor] | None = None,
) -> Flask:
    if (sentinel is None) != (controller_policy is None):
        raise ValueError("sentinel and controller_policy must be configured together")
    if sentinel is not None and functions is None:
        raise ValueError("eDocs controller mode requires registered functions")
    app = app or Flask("aauth-as")
    key = key or SigningKey.generate(kid="as")
    resolver = JwksResolver(transport or RequestsTransport())
    store = PendingStore(base_path=f"{issuer}{pending_path}")
    pending_requests: dict[str, dict] = {}
    app.extensions["aauth_as"] = {"issuer": issuer, "key": key, "store": store}

    if "aauth_as_error_handler" not in app.extensions:
        app.extensions["aauth_as_error_handler"] = True

        @app.errorhandler(AAuthError)
        def aauth_error(error: AAuthError):
            return error.body(), error.status

    @app.get("/.well-known/aauth-access.json", endpoint="aauth_as_metadata")
    def as_metadata():
        return dict(
            build_metadata(
                issuer,
                jwks_uri=f"{issuer}{jwks_path}",
                token_endpoint=f"{issuer}{token_path}",
                name="aauth-edocs demo AS",
            )
        )

    @app.get(jwks_path, endpoint="aauth_as_jwks")
    def as_jwks():
        return {"keys": [key.public_jwk]}

    @app.post(token_path, endpoint="aauth_as_token")
    def token_endpoint():
        # §9.1.1: signed POST from a PS (jwks_uri scheme), carrying the
        # resource token and the agent's agent token.
        incoming = HttpRequest(request.method, request.url, dict(request.headers.items()))
        verified = verify(incoming, resolver)
        if verified.header.get("scheme") != "jwks_uri":
            raise AAuthError(INVALID_TOKEN, 401, "AS token endpoint accepts PS (jwks_uri) calls only")
        ps_url = verified.claims["iss"]

        body = request.get_json(force=True) or {}
        if "resource_token" not in body or "agent_token" not in body:
            raise AAuthError(INVALID_REQUEST, 400, "resource_token and agent_token are required")

        agent_claims = verify_agent_token(body["agent_token"], resolver)
        edocs_request = sentinel is not None and ps_url == sentinel
        expected_aud = sentinel if edocs_request else issuer
        rt_claims = verify_resource_token(
            body["resource_token"],
            resolver,
            aud=expected_aud,
            agent=agent_claims["sub"],
            agent_jkt=jwk_thumbprint(agent_claims["cnf"]["jwk"]),
        )

        context = {"ps_url": ps_url, "agent_claims": agent_claims, "rt_claims": rt_claims}
        if edocs_request:
            scope = rt_claims.get("scope")
            if not isinstance(scope, str) or len(scope.split()) != 1:
                raise AAuthError(INVALID_TOKEN, 400, "eDocs resource token must contain exactly one scope")
            if not all(
                isinstance(rt_claims.get(name), str) and rt_claims[name]
                for name in ("source_agent", "edoc_id")
            ) or not isinstance(rt_claims.get("controllers"), list):
                raise AAuthError(INVALID_TOKEN, 400, "eDocs resource token claims are required")
            descriptor = functions.get(scope)
            if descriptor is None:
                raise AAuthError(DENIED, 403, "requested function is not registered")
            try:
                validate_function_args(descriptor, rt_claims.get("function_args"))
            except ValueError as error:
                raise AAuthError(INVALID_TOKEN, 400, str(error)) from error
            proposal = Dataflow.from_arguments(
                source=rt_claims["source_agent"],
                function=scope,
                document=rt_claims["edoc_id"],
                destination=agent_claims["sub"],
                arguments=rt_claims["function_args"],
            )
            token = issue_controller_decision(
                proposal=proposal,
                policy=controller_policy,
                issuer=issuer,
                sentinel=sentinel,
                agent_jwk=agent_claims["cnf"]["jwk"],
                controllers=rt_claims["controllers"],
                key=key,
            )
            return {"auth_token": token, "expires_in": 3600}

        granted = policy(ps_url, agent_claims, rt_claims) if policy else rt_claims.get("scope")
        if granted is None:
            raise AAuthError("denied", 403, "resource policy denied the request")
        if isinstance(granted, dict):
            return _defer(granted, context)

        return _issue(context, granted)

    @app.get(f"{pending_path}/<pid>", endpoint="aauth_as_pending")
    def pending(pid: str):
        status, headers, body = store.response(pid)
        return body, status, headers

    @app.post(f"{pending_path}/<pid>", endpoint="aauth_as_complete_pending")
    def complete_pending(pid: str):
        context = pending_requests.pop(pid, None)
        if context is None:
            raise AAuthError(INVALID_REQUEST, 404, "no such pending request")
        body = request.get_json(force=True) or {}
        requirement = context["requirement"]
        if requirement == CLAIMS:
            result = _issue(context, context["rt_claims"].get("scope"), claims=body.get("claims") or {})
            store.resolve(pid, result)
            return {"status": "recorded"}
        decision = body.get("decision")
        if decision == "grant":
            store.resolve(pid, _issue(context, context["rt_claims"].get("scope")))
        else:
            store.deny(pid, detail=f"{requirement} denied")
        return {"status": "recorded"}

    def _defer(policy_result: dict, context: dict):
        requirement = policy_result.get("requirement")
        if requirement == "payment":
            raise AAuthError("payment_required", 402, policy_result.get("detail") or "payment required")
        if requirement not in (CLAIMS, INTERACTION, APPROVAL):
            raise AAuthError(INVALID_REQUEST, 400, f"unsupported AS requirement {requirement!r}")

        pid = store.create(retry_after=0)
        params = {}
        body = {"status": "pending"}
        if requirement == CLAIMS:
            required_claims = policy_result.get("required_claims") or ["sub"]
            params["required_claims"] = " ".join(required_claims)
            body["required_claims"] = required_claims
        pending_requests[pid] = {**context, "requirement": requirement}
        store.set_requirement(pid, build_requirement(requirement, **params))
        status, headers, response_body = store.response(pid)
        response_body.update(body)
        return response_body, status, headers

    def _issue(context: dict, granted_scope: str | None, claims: dict | None = None):
        _check_scope(granted_scope, context["rt_claims"].get("scope"))
        token = issue_auth_token(
            issuer=issuer,
            dwk=DWK_ACCESS,
            aud=context["rt_claims"]["iss"],
            agent=context["agent_claims"]["sub"],
            cnf_jwk=context["agent_claims"]["cnf"]["jwk"],
            scope=granted_scope,
            sub=(claims or {}).get("sub"),
            mission=context["rt_claims"].get("mission"),
            key=key,
        )
        return {"auth_token": token, "expires_in": 3600}

    def _check_scope(granted: str | None, requested: str | None) -> None:
        if granted is None:
            return
        if not set(granted.split()) <= set((requested or "").split()):
            raise AAuthError("denied", 403, "AS granted scope broader than resource token")

    return app
