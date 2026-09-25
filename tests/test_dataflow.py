"""Dataflow grant path integration tests."""

import pytest
from flask import Flask, g

from aauth_edocs import (
    AgentSession,
    HttpRequest,
    JwksResolver,
    ResourceConfig,
    SigningKey,
    create_ap,
    create_as,
    create_ps,
    install_resource,
    peek_jwt,
    require_auth_token,
    sign,
)
from conftest import LoopbackTransport

AP_URL = "http://ap.local"
PS_URL = "http://ps.local"
AS_URL = "http://as.local"
RESOURCE_URL = "http://resource.local"

DATAFLOW = {"data": "patient-42", "function": "avg_bp"}


@pytest.fixture
def three_party_world():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    transport.add(PS_URL, create_ps(PS_URL, transport=transport))

    config = ResourceConfig(issuer=RESOURCE_URL, key=SigningKey.generate(), key_resolver=JwksResolver(transport))
    app = Flask(__name__)
    install_resource(app, config)

    @app.get("/api/data")
    @require_auth_token(config, dataflow=DATAFLOW)
    def data():
        claims = peek_jwt(g.aauth.token)[1]
        return {"dataflow": claims.get("dataflow"), "iss": claims.get("iss")}

    transport.add(RESOURCE_URL, app)
    return transport


@pytest.fixture
def four_party_world():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    transport.add(PS_URL, create_ps(PS_URL, transport=transport))
    transport.add(AS_URL, create_as(AS_URL, transport=transport))

    config = ResourceConfig(
        issuer=RESOURCE_URL,
        key=SigningKey.generate(),
        key_resolver=JwksResolver(transport),
        as_url=AS_URL,
    )
    app = Flask(__name__)
    install_resource(app, config)

    @app.get("/api/data")
    @require_auth_token(config, dataflow=DATAFLOW)
    def data():
        claims = peek_jwt(g.aauth.token)[1]
        return {"dataflow": claims.get("dataflow"), "iss": claims.get("iss")}

    transport.add(RESOURCE_URL, app)
    return transport


def test_three_party_dataflow_end_to_end(three_party_world):
    session = AgentSession.enroll(AP_URL, "assistant", three_party_world, ps=PS_URL)
    session.authorize(RESOURCE_URL, DATAFLOW)
    _, claims = peek_jwt(session._auth_tokens[RESOURCE_URL])
    assert claims["dataflow"] == DATAFLOW

    response = session.get(f"{RESOURCE_URL}/api/data")
    assert response.status_code == 200
    assert response.json()["dataflow"] == DATAFLOW


def test_four_party_dataflow_end_to_end(four_party_world):
    session = AgentSession.enroll(AP_URL, "assistant", four_party_world, ps=PS_URL)
    response = session.get(f"{RESOURCE_URL}/api/data")
    assert response.status_code == 200
    body = response.json()
    assert body["iss"] == AS_URL
    assert body["dataflow"] == DATAFLOW

    _, claims = peek_jwt(session._auth_tokens[RESOURCE_URL])
    assert claims["dataflow"] == DATAFLOW


def test_authorize_rejects_missing_dataflow(three_party_world):
    session = AgentSession.enroll(AP_URL, "assistant", three_party_world, ps=PS_URL)
    authz = HttpRequest("POST", f"{RESOURCE_URL}/authorize", {})
    sign(authz, session.key, session.agent_token)
    response = three_party_world.request("POST", authz.url, headers=authz.headers, json={})
    assert response.status_code == 400


def test_dataflow_mismatch_denied(three_party_world):
    """Auth token for a different dataflow is rejected (before AgentSession retry)."""
    session = AgentSession.enroll(AP_URL, "assistant", three_party_world, ps=PS_URL)
    other = {"data": "other", "function": "sum"}
    session.authorize(RESOURCE_URL, other)
    req = HttpRequest("GET", f"{RESOURCE_URL}/api/data", {})
    sign(req, session.key, session._auth_tokens[RESOURCE_URL])
    response = three_party_world.request("GET", req.url, headers=req.headers)
    assert response.status_code == 403
    assert response.json()["error"] == "denied"
