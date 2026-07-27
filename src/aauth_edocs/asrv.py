"""Access Server: evaluates resource policy and issues auth tokens (§9.1).

Only PSes call the AS token endpoint (§9.3); they authenticate with the
jwks_uri Signature-Key scheme. Internal-experimentation scope: registered
PolicyRules decide grant/deny (empty list grants), grants are dataflow
claims, and any resolvable PS is trusted. An optional `policy` callable
remains only for deferred requirements (claims/interaction/approval/payment).

Module is named `asrv` because `as` is a Python keyword.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from flask import Flask, request

from .agent import RequestsTransport
from .errors import AAuthError, INVALID_REQUEST, INVALID_TOKEN
from .deferred import PendingStore
from .headers import APPROVAL, CLAIMS, INTERACTION, build_requirement
from .httpsig import HttpRequest, verify
from .ids import DWK_ACCESS
from .keys import SigningKey, jwk_thumbprint
from .metadata import JwksResolver, build_metadata
from .tokens import issue_auth_token, verify_agent_token, verify_resource_token

# Optional override for deferred requirements:
# granted dataflow | None (deny) | deferred dict (has "requirement").
Policy = Callable[[str, dict, dict], "dict[str, Any] | None"]

WILDCARD = "*"


@dataclass(frozen=True)
class PolicyRule:
    """Lightweight access rule: who may apply which function to which data element."""

    source_agent_id: str
    function_id: str
    de_id: str
    dest_agent_id: str
    # condition_id: str = WILDCARD


def create_rule(
    source_agent_id: str,
    function_id: str,
    de_id: str,
    dest_agent_id: str,
    # condition_id: str = WILDCARD,
) -> PolicyRule:
    """Create a rule. Any field may be `"*"` (or omitted) to match anything."""
    return PolicyRule(
        source_agent_id=source_agent_id,
        function_id=function_id,
        de_id=de_id,
        dest_agent_id=dest_agent_id,
        # condition_id=condition_id,
    )


def _field_matches(allowed: str, requested: str) -> bool:
    return allowed == WILDCARD or allowed == requested


def check_policy_rule(policies: list[PolicyRule], requested: PolicyRule) -> bool:
    """Return True if `requested` matches a registered rule (or no rules are set).

    Registered rule fields set to `"*"` are wildcards and match any request
    value for that field.
    """
    if not policies:
        return True
    for rule in policies:
        if (
            _field_matches(rule.source_agent_id, requested.source_agent_id)
            and _field_matches(rule.function_id, requested.function_id)
            and _field_matches(rule.de_id, requested.de_id)
            and _field_matches(rule.dest_agent_id, requested.dest_agent_id)
        ):
            return True
    return False


def request_rule(agent_claims: dict, rt_claims: dict) -> PolicyRule:
    """Build the policy rule implied by a token request.

    Dataflow is resource → agent: source is the resource (`iss`), dest is
    the agent (`sub` / resource-token `agent`).
    """
    dataflow = rt_claims["dataflow"]
    return PolicyRule(
        source_agent_id=rt_claims["iss"],
        function_id=dataflow["function"],
        de_id=dataflow["data"],
        dest_agent_id=agent_claims["sub"],
    )


def create_as(
    issuer: str,
    key: SigningKey | None = None,
    transport=None,
    app: Flask | None = None,
    token_path: str = "/token",
    jwks_path: str = "/jwks.json",
    pending_path: str = "/pending",
) -> Flask:
    app = app or Flask("aauth-as")
    key = key or SigningKey.generate(kid="as")
    resolver = JwksResolver(transport or RequestsTransport())
    store = PendingStore(base_path=f"{issuer}{pending_path}")
    pending_requests: dict[str, dict] = {}
    policies: list[PolicyRule] = []

    def add_policy_rule(
        source_agent_id: str,
        function_id: str,
        de_id: str,
        dest_agent_id: str,
        # condition_id: str = WILDCARD,
    ) -> PolicyRule:
        rule = create_rule(
            source_agent_id=source_agent_id,
            function_id=function_id,
            de_id=de_id,
            dest_agent_id=dest_agent_id,
            # condition_id=condition_id,
        )
        policies.append(rule)
        return rule

    app.extensions["aauth_as"] = {
        "issuer": issuer,
        "key": key,
        "store": store,
        "policies": policies,
        "create_rule": add_policy_rule,
    }

    if "aauth_as_error_handler" not in app.extensions:
        app.extensions["aauth_as_error_handler"] = True

        @app.errorhandler(AAuthError)
        def aauth_error(error: AAuthError):
            return error.body(), error.status

    @app.get("/.well-known/aauth-access.json", endpoint="aauth_as_metadata")
    def as_metadata():
        """
        Metadata endpoint to get the metadata for the AS.

        Response:
        - issuer: str
        - jwks_uri: str
        - token_endpoint: str
        - name: str
        - dwk: str
        """

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
        """
        AS JWKS endpoint to get the JWKS for the AS.

        Response:
        - keys: list[dict]
        """

        return {"keys": [key.public_jwk]}

    @app.post(token_path, endpoint="aauth_as_token")
    def token_endpoint():
        """
        Endpoint that the Sentinel/PS calls to get an auth token
        for the agent to use for the resource.

        Function Logic:
        1. Verify the incoming request is signed by Sentinel/PS.
        2. Verify both resource and agent tokens are present.
        3. Verify resource and agent tokens are valid.
        4. Check policy rules (or optional policy override)
        5. Choose to deny, defer, or issue a token

        Request (HTTP-signed by the Sentinel/PS, jwks_uri):
        - resource_token: str
        - agent_token: str

        Response:
        - auth_token: str
        - expires_in: int
        """
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
        rt_claims = verify_resource_token(  # §6.7.2, aud must be this AS
            body["resource_token"],
            resolver,
            aud=issuer,
            agent=agent_claims["sub"],
            agent_jkt=jwk_thumbprint(agent_claims["cnf"]["jwk"]),
        )
        if rt_claims.get("dataflow") is None:
            raise AAuthError(INVALID_TOKEN, 400, "resource token missing dataflow")

        context = {"ps_url": ps_url, "agent_claims": agent_claims, "rt_claims": rt_claims}
        default_grant = rt_claims["dataflow"]
        granted = (
            default_grant
            if check_policy_rule(policies, request_rule(agent_claims, rt_claims))
            else None
        )
        if granted is None:
            raise AAuthError("denied", 403, "resource policy denied the request")
        if isinstance(granted, dict) and "requirement" in granted:
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
            result = _issue(context, context["rt_claims"]["dataflow"], claims=body.get("claims") or {})
            store.resolve(pid, result)
            return {"status": "recorded"}
        decision = body.get("decision")
        if decision == "grant":
            store.resolve(pid, _issue(context, context["rt_claims"]["dataflow"]))
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

    def _issue(context: dict, granted: dict, claims: dict | None = None):
        rt_claims = context["rt_claims"]
        if granted != rt_claims["dataflow"]:
            raise AAuthError("denied", 403, "AS granted dataflow does not match resource token")
        token = issue_auth_token(
            issuer=issuer,
            dwk=DWK_ACCESS,
            aud=rt_claims["iss"],
            agent=context["agent_claims"]["sub"],
            cnf_jwk=context["agent_claims"]["cnf"]["jwk"],
            dataflow=granted,
            sub=(claims or {}).get("sub"),
            mission=rt_claims.get("mission"),
            key=key,
        )
        return {"auth_token": token, "expires_in": 3600}

    return app
