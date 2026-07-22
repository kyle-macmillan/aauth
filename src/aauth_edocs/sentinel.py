"""Sentinel: a server for associating AS's with resources based on eDocs.
Our approach to making data rival.

To upstream PSes the sentinel looks like an AS (rt.aud = sentinel). Under the
hood it forwards to the controller AS named on the resource token, treats the
AS auth token as a throwaway approval signal, and remints its own auth token.
"""

from __future__ import annotations

from flask import Flask, request

from .agent import RequestsTransport
from .errors import AAuthError, INVALID_REQUEST, INVALID_TOKEN, SERVER_ERROR
from .httpsig import HttpRequest, peek_jwt, sign_server, verify
from .ids import DWK_ACCESS, DWK_SENTINEL
from .keys import SigningKey, jwk_thumbprint
from .metadata import JwksResolver, build_metadata, fetch_metadata
from .tokens import issue_auth_token, verify_agent_token, verify_resource_token


def create_sentinel(
    issuer: str,
    key: SigningKey | None = None,
    transport=None,
    app: Flask | None = None,
    token_path: str = "/token",
    jwks_path: str = "/jwks.json",
) -> Flask:
    app = app or Flask("sentinel")
    key = key or SigningKey.generate(kid="sentinel")
    transport = transport or RequestsTransport()
    resolver = JwksResolver(transport)
    app.extensions["sentinel"] = {"issuer": issuer, "key": key}

    if "aauth_as_error_handler" not in app.extensions:
        app.extensions["aauth_as_error_handler"] = True

        @app.errorhandler(AAuthError)
        def aauth_error(error: AAuthError):
            return error.body(), error.status

    @app.get("/.well-known/aauth-sentinel.json", endpoint="aauth_as_metadata")
    def sentinel_metadata():
        """
        Metadata endpoint to get the metadata for the
        sentinel.

        Response:
        - issuer: str
        - jwks_uri: str
        - token_endpoint: str
        - name: str
        - dwk: str
        """
        return dict(
            build_metadata(
                issuer=issuer,
                jwks_uri=f"{issuer}{jwks_path}",
                token_endpoint=f"{issuer}{token_path}",
                name="aauth-edocs sentinel",
                dwk=DWK_SENTINEL,
            )
        )

    @app.get(jwks_path, endpoint="aauth_as_jwks")
    def sentinel_jwks():
        """
        Sentinel JWKS endpoint to get the JWKS for the
        sentinel.

        Response:
        - keys: list[dict]
        """
        return {"keys": [key.public_jwk]}

    @app.post(token_path, endpoint="aauth_sentinel_token")
    def sentinel_token():
        """
        Endpoint that the PS calls to get an auth token
        for the agent to use for the resource.

        Function Logic:
        1. Verify the incoming request is signed by PS.
        2. Verify both resource and agent tokens are present.
        3. Verify resource and agent tokens are valid.
        4. Check that controller is present.
        5. Check provenance of the proposed dataflow matches internal provenance.
        6. Forward the tokens to the AS.
        7. Check that the AS returned a token.
        8. Issue a new auth token for the agent to use for the resource.

        Request (HTTP-signed by the PS, jwks_uri):
        - resource_token: str
        - agent_token: str

        Response:
        - auth_token: str
        - expires_in: int
        """
        incoming = HttpRequest(request.method, request.url, dict(request.headers.items()))
        verified = verify(incoming, resolver)
        if verified.header.get("scheme") != "jwks_uri":
            raise AAuthError(INVALID_TOKEN, 401, "sentinel token endpoint accepts PS (jwks_uri) calls only")

        body = request.get_json(force=True) or {}
        if "resource_token" not in body or "agent_token" not in body:
            raise AAuthError(INVALID_REQUEST, 400, "resource_token and agent_token are required")

        agent_claims = verify_agent_token(body["agent_token"], resolver)
        rt_claims = verify_resource_token(
            body["resource_token"],
            resolver,
            aud=issuer,
            agent=agent_claims["sub"],
            agent_jkt=jwk_thumbprint(agent_claims["cnf"]["jwk"]),
        )

        controller = rt_claims.get("controller")
        if not controller:
            raise AAuthError(INVALID_REQUEST, 400, "resource token missing controller (AS URL)")

        _check_provenance(rt_claims, controller)


        as_token = _forward_to_as(
            controller,
            resource_token=body["resource_token"],
            agent_token=body["agent_token"],
        )
        _check_as_token(rt_claims, agent_claims, controller, as_token)
        return _issue(agent_claims, rt_claims, as_token)

    def _forward_to_as(as_url: str, *, resource_token: str, agent_token: str) -> str:
        """
        Sends resource and agent tokens to AS to get an auth token.
        """
        as_md = fetch_metadata(as_url, DWK_ACCESS, transport)
        req = HttpRequest("POST", as_md.endpoint("token_endpoint"), {})
        sign_server(req, key, issuer, DWK_SENTINEL)
        response = transport.request(
            "POST",
            req.url,
            headers=req.headers,
            json={"resource_token": resource_token, "agent_token": agent_token},
        )
        # Pending (202) not supported yet — immediate grant/fail only.
        if response.status_code == 202:
            raise AAuthError(
                INVALID_REQUEST,
                400,
                "sentinel does not support AS pending/deferred authorization yet",
            )
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        auth_token = response.json().get("auth_token")
        if not auth_token:
            raise AAuthError(SERVER_ERROR, 502, "AS returned no auth_token")
        return auth_token

    def _check_as_token(rt_claims: dict, agent_claims: dict, as_url: str, auth_token: str) -> None:
        """
        Checks that the AS returned a token that matches the request. Raises error
        if the token does not match the request. Otherwise, returns nothing.
        """
        _, claims = peek_jwt(auth_token)
        if (
            claims.get("iss") != as_url
            or claims.get("aud") != rt_claims["iss"]
            or claims.get("agent") != agent_claims["sub"]
            or jwk_thumbprint(claims["cnf"]["jwk"]) != jwk_thumbprint(agent_claims["cnf"]["jwk"])
        ):
            raise AAuthError(SERVER_ERROR, 502, "AS returned a token that does not match the request")
        if rt_claims.get("dataflow") is not None:
            if claims.get("dataflow") != rt_claims["dataflow"] or "scope" in claims:
                raise AAuthError(SERVER_ERROR, 502, "AS returned a token that does not match the request")
        elif not set((claims.get("scope") or "").split()) <= set((rt_claims.get("scope") or "").split()):
            raise AAuthError(SERVER_ERROR, 502, "AS returned a token that does not match the request")

    def _issue(agent_claims: dict, rt_claims: dict, as_token: str) -> dict:
        _, as_claims = peek_jwt(as_token)
        if rt_claims.get("dataflow") is not None:
            token = issue_auth_token(
                issuer=issuer,
                dwk=DWK_SENTINEL,
                aud=rt_claims["iss"],
                agent=agent_claims["sub"],
                cnf_jwk=agent_claims["cnf"]["jwk"],
                dataflow=as_claims["dataflow"],
                mission=rt_claims.get("mission"),
                key=key,
            )
        else:
            token = issue_auth_token(
                issuer=issuer,
                dwk=DWK_SENTINEL,
                aud=rt_claims["iss"],
                agent=agent_claims["sub"],
                cnf_jwk=agent_claims["cnf"]["jwk"],
                scope=as_claims.get("scope"),
                mission=rt_claims.get("mission"),
                key=key,
            )
        return {"auth_token": token, "expires_in": 3600}

    return app


def _check_provenance(rt_claims: dict, controller: str) -> None:
    """Future: enforce that controllers match the provenance registry."""
    return None
