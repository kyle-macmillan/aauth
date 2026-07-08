"""Agent Provider: publishes metadata + JWKS and issues agent tokens (§5.2).

Internal-experimentation scope: /issue is an open endpoint — anyone can
enroll. Real enrollment ceremonies (attestation, key refresh) belong to the
bootstrap draft and are out of scope.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import Flask, request

from .errors import AAuthError, INVALID_REQUEST
from .ids import agent_id
from .keys import SigningKey
from .metadata import build_metadata
from .tokens import issue_agent_token


def create_ap(issuer: str, key: SigningKey | None = None, token_lifetime: int = 24 * 3600) -> Flask:
    """Create an AP Flask app for `issuer` (e.g. http://127.0.0.1:5001).

    The signing key and issuer are reachable via app.extensions["aauth_ap"].
    """
    app = Flask("aauth-ap")
    key = key or SigningKey.generate(kid="ap")
    domain = urlsplit(issuer).netloc
    app.extensions["aauth_ap"] = {"issuer": issuer, "key": key}

    @app.errorhandler(AAuthError)
    def aauth_error(error: AAuthError):
        return error.body(), error.status

    @app.get("/.well-known/aauth-agent.json")
    def metadata():
        return dict(
            build_metadata(
                issuer,
                jwks_uri=f"{issuer}/jwks.json",
                issue_endpoint=f"{issuer}/issue",
                name="aauth-edocs demo AP",
            )
        )

    @app.get("/jwks.json")
    def jwks():
        return {"keys": [key.public_jwk]}

    @app.post("/issue")
    def issue():
        body = request.get_json(force=True)
        aid = agent_id(body["local"], domain)
        parent_agent = body.get("parent_agent")
        if parent_agent:
            parent_local = parent_agent.removeprefix("aauth:").split("@", 1)[0]
            if "+" in parent_local:
                raise AAuthError(INVALID_REQUEST, 400, "nested sub-agents are not supported")
            if not body["local"].startswith(f"{parent_local}+"):
                raise AAuthError(INVALID_REQUEST, 400, "sub-agent local must be parent+child")
        token = issue_agent_token(
            issuer=issuer,
            agent=aid,
            agent_jwk=body["jwk"],
            key=key,
            ps=body.get("ps"),
            parent_agent=parent_agent,
            lifetime=token_lifetime,
        )
        return {"agent_token": token, "agent": aid}

    return app
