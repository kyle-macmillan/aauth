"""In-process Sentinel aggregation for the eDocs demo."""

from __future__ import annotations

import time
from typing import Callable

from flask import Flask, request

from .agent import RequestsTransport
from .edocs import Dataflow, SentinelRegistry, validate_function_args
from .errors import AAuthError, DENIED, INVALID_REQUEST, INVALID_TOKEN, SERVER_ERROR
from .httpsig import HttpRequest, KeyResolver, peek_jwt, sign_server, verify
from .ids import DWK_ACCESS, DWK_PERSON
from .keys import SigningKey, jwk_thumbprint
from .metadata import JwksResolver, build_metadata, fetch_metadata
from .tokens import (
    AUTH_TYP,
    CONDITIONAL_AUTH_TYP,
    issue_auth_token,
    verify_agent_token,
    verify_auth_token,
    verify_conditional_auth_token,
    verify_resource_token,
)

Now = Callable[[], float]


def create_sentinel(
    *,
    issuer: str,
    registry: SentinelRegistry,
    key: SigningKey | None = None,
    transport=None,
    app: Flask | None = None,
    token_path: str = "/token",
    jwks_path: str = "/jwks.json",
) -> Flask:
    """Create the Sentinel's AS-facing and PS-facing HTTP adapter."""
    app = app or Flask("aauth-sentinel")
    key = key or SigningKey.generate(kid="sentinel")
    transport = transport or RequestsTransport()
    resolver = JwksResolver(transport)
    app.extensions["aauth_sentinel"] = {
        "issuer": issuer,
        "key": key,
        "registry": registry,
    }

    @app.errorhandler(AAuthError)
    def aauth_error(error: AAuthError):
        return error.body(), error.status

    @app.get("/.well-known/aauth-access.json")
    def access_metadata():
        return dict(
            build_metadata(
                issuer,
                jwks_uri=f"{issuer}{jwks_path}",
                token_endpoint=f"{issuer}{token_path}",
                name="aauth-edocs demo Sentinel",
            )
        )

    @app.get("/.well-known/aauth-person.json")
    def person_metadata():
        return dict(
            build_metadata(
                issuer,
                jwks_uri=f"{issuer}{jwks_path}",
                token_endpoint=f"{issuer}{token_path}",
                name="aauth-edocs demo Sentinel",
            )
        )

    @app.get(jwks_path)
    def jwks():
        return {"keys": [key.public_jwk]}

    @app.post(token_path)
    def token_endpoint():
        incoming = HttpRequest(request.method, request.url, dict(request.headers.items()))
        verified = verify(incoming, resolver)
        if verified.header.get("scheme") != "jwks_uri":
            raise AAuthError(INVALID_TOKEN, 401, "Sentinel token endpoint accepts PS calls only")
        ps_issuer = verified.claims["iss"]

        body = request.get_json(force=True) or {}
        if "resource_token" not in body or "agent_token" not in body:
            raise AAuthError(INVALID_REQUEST, 400, "resource_token and agent_token are required")

        agent_claims = verify_agent_token(body["agent_token"], resolver)
        if agent_claims.get("ps") != ps_issuer:
            raise AAuthError(INVALID_TOKEN, 403, "requesting PS does not match agent token ps")

        rt_header, rt_peeked = peek_jwt(body["resource_token"])
        resource_jwk = resolver(
            rt_peeked.get("iss", ""),
            rt_peeked.get("dwk", ""),
            rt_header.get("kid", ""),
        )
        rt_claims = verify_resource_token(
            body["resource_token"],
            resolver,
            aud=issuer,
            agent=agent_claims["sub"],
            agent_jkt=jwk_thumbprint(agent_claims["cnf"]["jwk"]),
        )

        scope = rt_claims.get("scope")
        if not isinstance(scope, str) or len(scope.split()) != 1:
            raise AAuthError(INVALID_TOKEN, 400, "eDocs resource token must contain exactly one scope")
        if not all(
            isinstance(rt_claims.get(name), str) and rt_claims[name]
            for name in ("source_agent", "edoc_id")
        ) or not isinstance(rt_claims.get("controllers"), list):
            raise AAuthError(INVALID_TOKEN, 400, "eDocs resource token claims are required")

        descriptor = registry.functions.get(scope)
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
        binding = registry.resource_bindings.get(proposal.source)
        if binding is None:
            raise AAuthError(DENIED, 403, "source agent has no provisioned resource binding")
        if rt_claims.get("iss") != binding.resource_issuer:
            raise AAuthError(DENIED, 403, "resource token issuer does not match its provisioned binding")
        if jwk_thumbprint(resource_jwk) != binding.resource_jkt:
            raise AAuthError(DENIED, 403, "resource token key does not match its provisioned binding")
        controller_key = (rt_claims["iss"], proposal.document)
        authoritative = registry.controllers.get(controller_key)
        discovered = authoritative is None
        if discovered:
            if rt_claims["controllers"]:
                authoritative = tuple(rt_claims["controllers"])
            else:
                owner_as = registry.resource_owner_ases.get(rt_claims["iss"])
                if owner_as is None:
                    raise AAuthError(DENIED, 403, "resource owner has no provisioned controller AS")
                authoritative = (owner_as,)

        responses = {}
        for controller in authoritative:
            try:
                metadata = fetch_metadata(controller, DWK_ACCESS, transport)
                endpoint = metadata.endpoint("token_endpoint")
                if not endpoint:
                    raise AAuthError(SERVER_ERROR, 502, "controller has no token endpoint")
                outgoing = HttpRequest("POST", endpoint, {})
                sign_server(outgoing, key, issuer, DWK_PERSON)
                response = transport.request(
                    "POST",
                    outgoing.url,
                    headers=outgoing.headers,
                    json={
                        "resource_token": body["resource_token"],
                        "agent_token": body["agent_token"],
                    },
                )
                response_body = response.json()
                if response.status_code != 200:
                    detail = response_body.get("detail") if isinstance(response_body, dict) else None
                    raise AAuthError(DENIED, 403, detail or "controller denied the request")
                if not isinstance(response_body, dict) or not isinstance(response_body.get("auth_token"), str):
                    raise AAuthError(DENIED, 403, "controller returned no auth token")
                responses[controller] = response_body["auth_token"]
            except AAuthError as error:
                raise AAuthError(DENIED, 403, f"controller {controller} did not approve: {error}") from error

        token = aggregate_controller_decisions(
            proposal=proposal,
            resource_issuer=rt_claims["iss"],
            advisory_controllers=rt_claims["controllers"],
            responses=responses,
            agent_jwk=agent_claims["cnf"]["jwk"],
            registry=registry,
            sentinel_issuer=issuer,
            sentinel_key=key,
            key_resolver=resolver,
            authoritative_controllers=authoritative,
        )
        if discovered:
            registry.controllers[controller_key] = authoritative
        return {"auth_token": token, "expires_in": 3600}

    return app


def aggregate_controller_decisions(
    *,
    proposal: Dataflow,
    resource_issuer: str,
    advisory_controllers: list[str] | tuple[str, ...],
    responses: dict[str, str],
    agent_jwk: dict,
    registry: SentinelRegistry,
    sentinel_issuer: str,
    sentinel_key: SigningKey,
    key_resolver: KeyResolver,
    authoritative_controllers: tuple[str, ...] | None = None,
    lifetime: int = 3600,
    now: Now = time.time,
) -> str:
    """Require unanimous controller approval and issue one final auth token.

    ``responses`` is keyed by the authoritative controller URL contacted by
    the caller. HTTP transport and initial agent/resource verification happen
    outside this aggregation boundary.
    """
    controllers = authoritative_controllers or registry.controllers.get(
        (resource_issuer, proposal.document)
    )
    if not controllers:
        _deny("no authoritative controllers registered for the eDoc")
    if len(set(controllers)) != len(controllers):
        _deny("authoritative controller registry contains duplicates")
    if set(responses) != set(controllers):
        _deny("controller responses do not exactly match the authoritative controller set")

    for controller in controllers:
        token = responses[controller]
        try:
            header, _ = peek_jwt(token)
            typ = header.get("typ")
            if typ == AUTH_TYP:
                claims = verify_auth_token(
                    token,
                    key_resolver,
                    aud=sentinel_issuer,
                    signing_jwk=agent_jwk,
                    source_agent=proposal.source,
                    scope=proposal.function,
                    edoc_id=proposal.document,
                    controllers=advisory_controllers,
                    function_args_hash=proposal.function_args_hash,
                    now=now,
                )
                if claims.get("iss") != controller:
                    raise AAuthError(DENIED, 403, "controller token issuer mismatch")
                if claims.get("agent") != proposal.destination:
                    raise AAuthError(DENIED, 403, "controller token agent mismatch")
            elif typ == CONDITIONAL_AUTH_TYP:
                prerequisite = verify_conditional_auth_token(
                    token,
                    key_resolver,
                    issuer=controller,
                    aud=sentinel_issuer,
                    agent=proposal.destination,
                    signing_jwk=agent_jwk,
                    source_agent=proposal.source,
                    scope=proposal.function,
                    edoc_id=proposal.document,
                    controllers=advisory_controllers,
                    function_args_hash=proposal.function_args_hash,
                    now=now,
                )
                if not any(
                    prerequisite.matches(materialized)
                    for materialized in registry.materialized
                ):
                    raise AAuthError(DENIED, 403, "controller prerequisite has not materialized")
            else:
                raise AAuthError(DENIED, 403, f"unsupported controller token type {typ!r}")
        except AAuthError as error:
            _deny(f"controller {controller} did not approve: {error}")

    token = issue_auth_token(
        issuer=sentinel_issuer,
        dwk=DWK_ACCESS,
        aud=resource_issuer,
        agent=proposal.destination,
        cnf_jwk=agent_jwk,
        scope=proposal.function,
        source_agent=proposal.source,
        edoc_id=proposal.document,
        controllers=controllers,
        function_args_hash=proposal.function_args_hash,
        key=sentinel_key,
        lifetime=lifetime,
        now=now,
    )
    registry.materialized.add(proposal)
    return token


def _deny(detail: str) -> None:
    raise AAuthError(DENIED, 403, detail)
