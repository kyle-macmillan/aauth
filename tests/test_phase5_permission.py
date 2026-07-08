"""Permission endpoint tests (§7.4-lite, no missions)."""

import pytest

from aauth_edocs import (
    AAuthError,
    AgentSession,
    HttpRequest,
    create_ap,
    create_ps,
    parse_requirement,
    sign,
)
from conftest import LoopbackTransport

AP_URL = "http://ap.local"
PS_URL = "http://ps.local"


@pytest.fixture
def world():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)
    return transport, ps_app


@pytest.fixture
def session(world):
    transport, _ = world
    return AgentSession.enroll(AP_URL, "assistant", transport, ps=PS_URL)


def login_person(transport: LoopbackTransport, ps_url: str = PS_URL):
    return transport.request("POST", f"{ps_url}/login", json={"person": "user-alice"})


def signed_permission(transport: LoopbackTransport, session: AgentSession, ps_url: str = PS_URL, **body):
    req = HttpRequest("POST", f"{ps_url}/permission", {})
    sign(req, session.key, session.agent_token)
    payload = {"action": "send_email"}
    payload.update(body)
    return transport.request("POST", req.url, headers=req.headers, json=payload)


def test_default_signed_permission_grants(world, session):
    transport, _ = world

    response = signed_permission(
        transport,
        session,
        description="Send the final packet",
        parameters={"to": "client@example.com"},
    )

    assert response.status_code == 200
    assert response.json() == {"permission": "granted"}


def test_unsigned_permission_rejected(world):
    transport, _ = world

    response = transport.request("POST", f"{PS_URL}/permission", json={"action": "send_email"})

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_signature"


def test_permission_requires_action(world, session):
    transport, _ = world
    req = HttpRequest("POST", f"{PS_URL}/permission", {})
    sign(req, session.key, session.agent_token)

    response = transport.request("POST", req.url, headers=req.headers, json={})

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_permission_deny_policy():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport, permission_policy=lambda agent, body: "deny")
    transport.add(PS_URL, ps_app)
    denied = AgentSession.enroll(AP_URL, "denied", transport, ps=PS_URL)

    response = signed_permission(transport, denied)

    assert response.status_code == 403
    assert response.json()["error"] == "denied"


def test_pending_permission_grant():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport, permission_policy=lambda agent, body: "pending")
    transport.add(PS_URL, ps_app)
    session = AgentSession.enroll(AP_URL, "pending-grant", transport, ps=PS_URL)

    response = signed_permission(transport, session)
    assert response.status_code == 202
    requirement, _ = parse_requirement(response.headers["AAuth-Requirement"])
    assert requirement == "approval"

    pid = response.headers["Location"].rsplit("/", 1)[-1]
    login_person(transport)
    approve = transport.request("POST", f"{PS_URL}/consent/{pid}", json={"decision": "grant"})
    assert approve.status_code == 200
    final = transport.request("GET", f"{PS_URL}/pending/{pid}")
    assert final.status_code == 200
    assert final.json() == {"permission": "granted"}


def test_pending_permission_deny():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport, permission_policy=lambda agent, body: "pending")
    transport.add(PS_URL, ps_app)
    session = AgentSession.enroll(AP_URL, "pending-deny", transport, ps=PS_URL)

    response = signed_permission(transport, session)
    pid = response.headers["Location"].rsplit("/", 1)[-1]
    login_person(transport)
    deny = transport.request("POST", f"{PS_URL}/consent/{pid}", json={"decision": "deny"})
    assert deny.status_code == 200
    final = transport.request("GET", f"{PS_URL}/pending/{pid}")
    assert final.status_code == 403
    assert final.json()["error"] == "denied"


def test_agent_session_permission_immediate_grant(session):
    assert session.request_permission(
        "send_email",
        description="Send the final packet",
        parameters={"to": "client@example.com"},
    )


def test_agent_session_permission_deferred_grant():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport, permission_policy=lambda agent, body: "pending")
    transport.add(PS_URL, ps_app)
    session = AgentSession.enroll(AP_URL, "agent-pending", transport, ps=PS_URL)

    def approve(location, headers):
        pid = location.rsplit("/", 1)[-1]
        login_person(transport)
        transport.request("POST", f"{PS_URL}/consent/{pid}", json={"decision": "grant"})

    session.on_pending = approve

    assert session.request_permission("send_email")


def test_agent_session_permission_deferred_deny():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport, permission_policy=lambda agent, body: "pending")
    transport.add(PS_URL, ps_app)
    session = AgentSession.enroll(AP_URL, "agent-denied", transport, ps=PS_URL)

    def deny(location, headers):
        pid = location.rsplit("/", 1)[-1]
        login_person(transport)
        transport.request("POST", f"{PS_URL}/consent/{pid}", json={"decision": "deny"})

    session.on_pending = deny

    with pytest.raises(AAuthError) as err:
        session.request_permission("send_email")
    assert err.value.code == "denied"
