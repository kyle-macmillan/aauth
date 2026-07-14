"""Sentinel: a server for associating AS's with resources based on eDocs.
Our approach to making data rival"""

from __future__ import annotations

from flask import Flask, request

from .metadata import JwksResolver
from .errors import AAuthError, INVALID_REQUEST, INVALID_TOKEN
from .agent import RequestsTransport
from .keys import SigningKey
# from .deferred import PendingStore
from .metadata import build_metadata
from .tokens import issue_auth_token
from .ids import DWK_ACCESS


def create_sentinel(
    issuer: str,
    key: SigningKey,
    transport=None,
    app: Flask | None = None,
    token_path: str = "/token",
    jwks_path: str = "/jwks.json",
) -> Flask:
    app = app or Flask("sentinel")
    key = key or SigningKey.generate(kid="sentinel")
    resolver = JwksResolver(transport or RequestsTransport())
    # store = PendingStore(base_path=f"{issuer}{pending_path}")
    app.extensions["sentinel"] = {"issuer": issuer, "key": key}

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
                name="aauth-edocs sentinel",
            )
        )

    @app.get(jwks_path, endpoint="aauth_as_jwks")
    def sentinel_jwks():
        return {"keys": [key.public_jwk]}


    @app.post(token_path, endpoint="aauth_as_token")
    def sentinel_token():
        return {"token": "sentinel"}


    def _issue(context: dict, granted_scope: str | None, claims: dict | None = None):
        _check_rule(granted_scope, context["rt_claims"].get("scope"))
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


    def _check_rule():
        return True
    return app