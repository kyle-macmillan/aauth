"""Phase 2 integration: AP + agent SDK + resource middleware wired through
Flask test clients (no sockets) via a loopback transport."""

import pytest
from flask import Flask, g

from aauth_edocs import (
    HttpRequest,
    JwksResolver,
    issue_agent_token,
    parse_requirement,
    sign,
)
from aauth_edocs.agent import AgentSession
from aauth_edocs.ap import create_ap
from aauth_edocs.resource import install_metadata, require_aauth_identity
from conftest import LoopbackTransport

AP_URL = "http://ap.local"
RESOURCE_URL = "http://resource.local"


@pytest.fixture
def world():
    """AP + resource apps behind one loopback transport."""
    transport = LoopbackTransport()
    ap_app = create_ap(AP_URL)
    transport.add(AP_URL, ap_app)

    resolver = JwksResolver(transport)
    resource_app = Flask(__name__)
    install_metadata(resource_app, RESOURCE_URL)

    @resource_app.get("/api/whoami")
    @require_aauth_identity(resolver)
    def whoami():
        return {"agent": g.aauth.claims["sub"]}

    @resource_app.get("/api/other")
    @require_aauth_identity(resolver)
    def other():
        return {"ok": True}

    transport.add(RESOURCE_URL, resource_app)
    return transport, ap_app


@pytest.fixture
def session(world):
    transport, _ = world
    return AgentSession.enroll(AP_URL, "assistant", transport)


def test_ap_metadata_and_jwks_resolve(world):
    transport, ap_app = world
    md = transport.get(f"{AP_URL}/.well-known/aauth-agent.json").json()
    assert md["issuer"] == AP_URL
    resolver = JwksResolver(transport)
    ap_key = ap_app.extensions["aauth_ap"]["key"]
    assert resolver(AP_URL, "aauth-agent.json", ap_key.kid) == ap_key.public_jwk


def test_resource_metadata(world):
    transport, _ = world
    md = transport.get(f"{RESOURCE_URL}/.well-known/aauth-resource.json").json()
    assert md == {"issuer": RESOURCE_URL, "access_mode": "agent-token"}


def test_signed_request_identifies_agent(session):
    assert session.agent_id == "aauth:assistant@ap.local"
    response = session.get(f"{RESOURCE_URL}/api/whoami")
    assert response.status_code == 200
    assert response.json() == {"agent": "aauth:assistant@ap.local"}


def test_unsigned_request_gets_agent_token_challenge(world):
    transport, _ = world
    response = transport.get(f"{RESOURCE_URL}/api/whoami")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_signature"
    requirement, params = parse_requirement(response.headers["AAuth-Requirement"])
    assert (requirement, params) == ("agent-token", {})


def test_signature_for_other_path_rejected(world, session):
    transport, _ = world
    req = HttpRequest("GET", f"{RESOURCE_URL}/api/whoami", {})
    sign(req, session.key, session.agent_token)
    response = transport.request("GET", f"{RESOURCE_URL}/api/other", headers=req.headers)
    assert response.status_code == 401


def test_expired_agent_token_rejected(world, session):
    transport, ap_app = world
    ap = ap_app.extensions["aauth_ap"]
    stale_token = issue_agent_token(
        issuer=ap["issuer"], agent=session.agent_id, agent_jwk=session.key.public_jwk,
        key=ap["key"], now=lambda: 1000.0,
    )
    stale_session = AgentSession(session.key, stale_token, transport)
    response = stale_session.get(f"{RESOURCE_URL}/api/whoami")
    assert response.status_code == 401
    assert response.json()["error"] == "expired"


def test_unknown_issuer_rejected(world, session):
    transport, _ = world
    from aauth_edocs import SigningKey

    rogue_key = SigningKey.generate(kid="rogue")
    rogue_token = issue_agent_token(
        issuer="http://rogue.local", agent="aauth:evil@rogue.local",
        agent_jwk=session.key.public_jwk, key=rogue_key,
    )
    response = AgentSession(session.key, rogue_token, transport).get(f"{RESOURCE_URL}/api/whoami")
    assert response.status_code in (401, 502)
    assert response.json()["error"] in ("invalid_signature", "server_error")
