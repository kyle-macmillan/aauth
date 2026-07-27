"""Four-party (federated) access integration tests (§4.1.4, §9)."""

import json

import pytest
from flask import Flask, g

from aauth_edocs import (
    AAuthError,
    AgentSession,
    HttpRequest,
    JwksResolver,
    ResourceConfig,
    SigningKey,
    create_ap,
    create_as,
    create_ps,
    install_resource,
    issue_resource_token,
    parse_requirement,
    peek_jwt,
    require_auth_token,
    sign,
    sign_server,
)
from conftest import LoopbackTransport

AP_URL = "http://ap.local"
PS_URL = "http://ps.local"
AS_URL = "http://as.local"
RESOURCE_URL = "http://resource.local"
COLLAPSE_URL = "http://collapsed.local"

DATAFLOW = {"data": "docs", "function": "read"}
DATAFLOW_WRITE = {"data": "docs", "function": "write"}


def consent_grant(df=DATAFLOW):
    return json.dumps(df, sort_keys=True, separators=(",", ":"))


@pytest.fixture
def world():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)

    def grant_read_dataflows(ps_url, agent_claims, rt_claims):
        df = rt_claims.get("dataflow")
        if df and df.get("function") == "read":
            return df
        return None

    as_app = create_as(AS_URL, transport=transport, policy=grant_read_dataflows)
    transport.add(AS_URL, as_app)

    config = ResourceConfig(
        issuer=RESOURCE_URL, key=SigningKey.generate(),
        key_resolver=JwksResolver(transport), as_url=AS_URL,
    )
    app = Flask(__name__)
    install_resource(app, config)

    @app.get("/api/data")
    @require_auth_token(config, dataflow=DATAFLOW)
    def data():
        claims = peek_jwt(g.aauth.token)[1]
        return {"iss": claims["iss"], "dwk": claims["dwk"], "dataflow": claims["dataflow"], "sub": claims.get("sub")}

    transport.add(RESOURCE_URL, app)
    return transport, ps_app, as_app, config


@pytest.fixture
def session(world):
    transport = world[0]
    return AgentSession.enroll(AP_URL, "assistant", transport, ps=PS_URL)


def login_person(transport: LoopbackTransport, ps_url: str):
    return transport.request("POST", f"{ps_url}/login", json={"person": "user-alice"})


def test_four_party_end_to_end(world, session):
    """Agent -> resource challenge -> PS -> AS -> auth token -> 200; the
    agent never talks to the AS and the flow is invisible to it (§13.1.1)."""
    response = session.get(f"{RESOURCE_URL}/api/data")
    assert response.status_code == 200
    body = response.json()
    assert body["iss"] == AS_URL  # AS-issued
    assert body["dwk"] == "aauth-access.json"
    assert body["dataflow"] == DATAFLOW

    cached = session._auth_tokens[RESOURCE_URL]
    _, claims = peek_jwt(cached)
    assert "sub" not in claims


def test_as_policy_denies_write_dataflow(world, session):
    """Write dataflow requested; the AS denies it."""
    with pytest.raises(AAuthError) as err:
        session.authorize(RESOURCE_URL, DATAFLOW_WRITE)
    assert err.value.code == "denied"


def test_as_rejects_agent_callers(world, session):
    """Only PSes (jwks_uri scheme) may call the AS token endpoint (§9.3)."""
    transport = world[0]
    req = HttpRequest("POST", f"{AS_URL}/token", {})
    sign(req, session.key, session.agent_token)  # scheme=jwt — not a PS
    response = transport.request(
        "POST", req.url, headers=req.headers,
        json={"resource_token": "x", "agent_token": session.agent_token},
    )
    assert response.status_code == 401
    assert "PS" in response.json()["detail"]


def test_as_rejects_wrong_aud_resource_token(world, session):
    transport, ps_app, _, config = world
    ps = ps_app.extensions["aauth_ps"]
    rt = issue_resource_token(  # aud is the PS, not the AS
        issuer=RESOURCE_URL, aud=PS_URL, agent=session.agent_id,
        agent_jkt=session.key.thumbprint, dataflow=DATAFLOW, key=config.key,
    )
    req = HttpRequest("POST", f"{AS_URL}/token", {})
    sign_server(req, ps["key"], PS_URL, "aauth-person.json")
    response = transport.request(
        "POST", req.url, headers=req.headers,
        json={"resource_token": rt, "agent_token": session.agent_token},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_token"


def test_claims_required_flow():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)
    as_app = create_as(
        AS_URL,
        transport=transport,
        policy=lambda ps_url, agent_claims, rt_claims: {"requirement": "claims", "required_claims": ["sub"]},
    )
    transport.add(AS_URL, as_app)
    config, app = _four_party_resource(transport)
    transport.add(RESOURCE_URL, app)
    session = AgentSession.enroll(AP_URL, "claims", transport, ps=PS_URL)

    response = session.get(f"{RESOURCE_URL}/api/data")

    assert response.status_code == 200
    body = response.json()
    assert body["iss"] == AS_URL
    assert body["sub"].startswith("u_")


def test_as_interaction_required_flow():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)
    as_app = create_as(
        AS_URL,
        transport=transport,
        policy=lambda ps_url, agent_claims, rt_claims: {"requirement": "interaction"},
    )
    transport.add(AS_URL, as_app)
    config, app = _four_party_resource(transport)
    transport.add(RESOURCE_URL, app)
    session = AgentSession.enroll(AP_URL, "interaction", transport, ps=PS_URL)

    def approve(location, headers):
        requirement, _ = parse_requirement(headers["AAuth-Requirement"])
        assert requirement == "interaction"
        login_person(transport, PS_URL)
        pid = location.rsplit("/", 1)[-1]
        transport.request("POST", f"{PS_URL}/interaction/{pid}", json={"decision": "grant"})

    session.on_pending = approve
    assert session.get(f"{RESOURCE_URL}/api/data").status_code == 200
    ps = ps_app.extensions["aauth_ps"]
    assert ps["agent_bindings"][session.agent_id] == "user-alice"
    assert ("user-alice", session.agent_id, RESOURCE_URL, consent_grant()) in ps["consents"]


def test_as_approval_required_flow():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)
    as_app = create_as(
        AS_URL,
        transport=transport,
        policy=lambda ps_url, agent_claims, rt_claims: {"requirement": "approval"},
    )
    transport.add(AS_URL, as_app)
    config, app = _four_party_resource(transport)
    transport.add(RESOURCE_URL, app)
    session = AgentSession.enroll(AP_URL, "approval", transport, ps=PS_URL)

    def approve(location, headers):
        requirement, _ = parse_requirement(headers["AAuth-Requirement"])
        assert requirement == "approval"
        login_person(transport, PS_URL)
        pid = location.rsplit("/", 1)[-1]
        transport.request("POST", f"{PS_URL}/consent/{pid}", json={"decision": "grant"})

    session.on_pending = approve
    assert session.get(f"{RESOURCE_URL}/api/data").status_code == 200
    ps = ps_app.extensions["aauth_ps"]
    assert ps["agent_bindings"][session.agent_id] == "user-alice"
    assert ("user-alice", session.agent_id, RESOURCE_URL, consent_grant()) in ps["consents"]


def test_as_payment_stub_surfaces_402():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)
    as_app = create_as(
        AS_URL,
        transport=transport,
        policy=lambda ps_url, agent_claims, rt_claims: {"requirement": "payment", "detail": "demo payment"},
    )
    transport.add(AS_URL, as_app)
    config, app = _four_party_resource(transport)
    transport.add(RESOURCE_URL, app)
    session = AgentSession.enroll(AP_URL, "payment", transport, ps=PS_URL)

    with pytest.raises(AAuthError) as err:
        session.authorize(RESOURCE_URL, DATAFLOW)

    assert err.value.status == 402
    assert err.value.code == "payment_required"


def test_ps_as_collapse_end_to_end():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    app = create_ps(COLLAPSE_URL, transport=transport)
    create_as(
        COLLAPSE_URL,
        transport=transport,
        app=app,
        token_path="/as/token",
        jwks_path="/as-jwks.json",
        pending_path="/as/pending",
    )
    transport.add(COLLAPSE_URL, app)

    config = ResourceConfig(
        issuer=RESOURCE_URL, key=SigningKey.generate(),
        key_resolver=JwksResolver(transport), as_url=COLLAPSE_URL,
    )
    resource = Flask(__name__)
    install_resource(resource, config)

    @resource.get("/api/data")
    @require_auth_token(config, dataflow=DATAFLOW)
    def data():
        claims = peek_jwt(g.aauth.token)[1]
        return {"iss": claims["iss"], "dwk": claims["dwk"], "dataflow": claims["dataflow"]}

    transport.add(RESOURCE_URL, resource)
    session = AgentSession.enroll(AP_URL, "collapsed", transport, ps=COLLAPSE_URL)

    response = session.get(f"{RESOURCE_URL}/api/data")

    assert response.status_code == 200
    assert response.json()["iss"] == COLLAPSE_URL
    assert response.json()["dwk"] == "aauth-access.json"


def _four_party_resource(transport: LoopbackTransport):
    config = ResourceConfig(
        issuer=RESOURCE_URL, key=SigningKey.generate(),
        key_resolver=JwksResolver(transport), as_url=AS_URL,
    )
    app = Flask(__name__)
    install_resource(app, config)

    @app.get("/api/data")
    @require_auth_token(config, dataflow=DATAFLOW)
    def data():
        claims = peek_jwt(g.aauth.token)[1]
        return {"iss": claims["iss"], "dwk": claims["dwk"], "dataflow": claims["dataflow"], "sub": claims.get("sub")}

    return config, app
