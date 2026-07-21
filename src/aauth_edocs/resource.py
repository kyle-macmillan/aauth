"""Resource-side Flask helpers.

Identity-based access (§4.1.1): `require_aauth_identity` authenticates the
caller by agent token alone. Three-/four-party access (§4.1.3/.4):
`install_resource` adds JWKS + an authorization endpoint that issues resource
tokens (§6.1–6.2), and `require_auth_token` enforces auth tokens, answering
agent-token-signed requests with the §6.6 challenge. Access-control decisions
beyond scope containment belong in the view (see flask.g.aauth).
"""

from __future__ import annotations

import functools
from dataclasses import dataclass

from flask import Flask, g, request

from .errors import AAuthError, DENIED, INVALID_REQUEST, INVALID_TOKEN
from .headers import AGENT_TOKEN, AUTH_TOKEN, REQUIREMENT_HEADER, build_requirement
from .httpsig import HttpRequest, KeyResolver, VerifiedRequest, verify
from .keys import SigningKey, jwk_thumbprint
from .metadata import build_metadata
from .tokens import AGENT_TYP, AUTH_TYP, issue_resource_token, verify_auth_token


@dataclass
class ResourceConfig:
    """Wiring for a resource that issues resource tokens."""

    issuer: str
    key: SigningKey
    key_resolver: KeyResolver
    as_url: str | None = None  # grant audience: AS (four-party) or sentinel (eDocs); unset -> three-party (agent's PS)
    controller_url: str | None = None  # controller AS when as_url is a sentinel
    default_scope: str = "access"


def install_metadata(app: Flask, issuer: str, access_mode: str = "agent-token", **fields) -> None:
    """Serve /.well-known/aauth-resource.json for this resource."""
    document = dict(build_metadata(issuer, access_mode=access_mode, **fields))

    @app.get("/.well-known/aauth-resource.json")
    def resource_metadata():
        return document


def install_resource(app: Flask, config: ResourceConfig) -> None:
    """Metadata + JWKS + authorization endpoint for a token-issuing resource."""
    install_metadata(
        app,
        config.issuer,
        access_mode="auth-token",
        jwks_uri=f"{config.issuer}/jwks.json",
        authorization_endpoint=f"{config.issuer}/authorize",
    )

    @app.get("/jwks.json")
    def resource_jwks():
        return {"keys": [config.key.public_jwk]}

    @app.post("/authorize")
    def authorization_endpoint():
        # §6.1: signed POST {"scope": ...}; agent identity from the signature
        try:
            verified = verify(_incoming_request(), config.key_resolver)
            if verified.header.get("typ") != AGENT_TYP:
                raise AAuthError(INVALID_TOKEN, 401, "authorization endpoint expects an agent token")
            scope = (request.get_json(force=True) or {}).get("scope")
            if not scope:
                raise AAuthError(INVALID_REQUEST, 400, "scope is required")
            return {"resource_token": _mint_resource_token(config, verified, scope)}
        except AAuthError as error:
            return error.body(), error.status


def _mint_resource_token(config: ResourceConfig, verified: VerifiedRequest, scope: str) -> str:
    """Issue a resource token for the verified agent (§6.2.2): aud is the
    resource's AS/sentinel when it has one, else the agent's declared PS.
    When aud is a sentinel, `controller` names the controller AS."""
    aud = config.as_url or verified.claims.get("ps")
    if not aud:
        raise AAuthError(INVALID_REQUEST, 400, "agent has no ps claim and resource has no AS")
    return issue_resource_token(
        issuer=config.issuer,
        aud=aud,
        agent=verified.claims["sub"],
        agent_jkt=jwk_thumbprint(verified.claims["cnf"]["jwk"]),
        scope=scope,
        controller=config.controller_url,
        key=config.key,
    )


def _incoming_request() -> HttpRequest:
    return HttpRequest(request.method, request.url, dict(request.headers.items()))


def require_aauth_identity(key_resolver: KeyResolver, expect_typ: str = AGENT_TYP):
    """Decorator factory: verify the signed request, put the VerifiedRequest
    on g.aauth. Unauthenticated/invalid requests get the error body, with a
    401 carrying AAuth-Requirement: requirement=agent-token (§6.3)."""

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            try:
                verified = verify(_incoming_request(), key_resolver)
                if verified.header.get("typ") != expect_typ:
                    raise AAuthError(INVALID_TOKEN, 401, f"expected a {expect_typ} token")
            except AAuthError as error:
                headers = {}
                if error.status == 401:
                    headers[REQUIREMENT_HEADER] = build_requirement(AGENT_TOKEN)
                return error.body(), error.status, headers
            g.aauth = verified
            return view(*args, **kwargs)

        return wrapper

    return decorator


def require_auth_token(config: ResourceConfig, scope: str | None = None):
    """Decorator factory for auth-token-protected endpoints (§6.6, §9.4.3).

    Auth-token-signed request -> verify (aud = this resource) + optional
    scope containment, then run the view with g.aauth set. Agent-token-signed
    request -> 401 challenge carrying a fresh resource token. Anything else
    -> 401 requirement=agent-token.
    """

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            try:
                verified = verify(_incoming_request(), config.key_resolver)
            except AAuthError as error:
                headers = {REQUIREMENT_HEADER: build_requirement(AGENT_TOKEN)} if error.status == 401 else {}
                return error.body(), error.status, headers

            typ = verified.header.get("typ")
            try:
                if typ == AUTH_TYP:
                    claims = verify_auth_token(verified.token, config.key_resolver, aud=config.issuer)
                    if scope and scope not in (claims.get("scope") or "").split():
                        raise AAuthError(DENIED, 403, f"scope {scope!r} not granted")
                    g.aauth = verified
                    return view(*args, **kwargs)
                if typ == AGENT_TYP:  # §6.6: challenge with a fresh resource token
                    token = _mint_resource_token(config, verified, scope or config.default_scope)
                    return (
                        AAuthError(INVALID_TOKEN, 401, "auth token required").body(),
                        401,
                        {REQUIREMENT_HEADER: build_requirement(AUTH_TOKEN, resource_token=token)},
                    )
                raise AAuthError(INVALID_TOKEN, 401, f"cannot access resource with typ {typ!r}")
            except AAuthError as error:
                headers = {REQUIREMENT_HEADER: build_requirement(AGENT_TOKEN)} if error.status == 401 else {}
                return error.body(), error.status, headers

        return wrapper

    return decorator
