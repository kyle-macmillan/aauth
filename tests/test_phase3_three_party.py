"""Three-party (PS-asserted) access integration tests (§4.1.3)."""

import pytest
from flask import Flask, g

from aauth_edocs import (
    AAuthError,
    HttpRequest,
    JwksResolver,
    SigningKey,
    issue_auth_token,
    issue_resource_token,
    parse_requirement,
    peek_jwt,
    sign,
)
from aauth_edocs.agent import AgentSession
from aauth_edocs.ap import create_ap
from aauth_edocs.ps import create_ps, directed_sub
from aauth_edocs.resource import ResourceConfig, install_resource, require_auth_token
from conftest import LoopbackTransport

AP_URL = "http://ap.local"
PS_URL = "http://ps.local"
RESOURCE_URL = "http://resource.local"
DOCS_URL = "http://docs.local"
INTERACTION_URL = "http://interaction-resource.local"


def make_resource(url: str, transport: LoopbackTransport, scope: str) -> ResourceConfig:
    config = ResourceConfig(issuer=url, key=SigningKey.generate(), key_resolver=JwksResolver(transport))
    app = Flask(__name__)
    install_resource(app, config)

    @app.get("/api/data")
    @require_auth_token(config, scope=scope)
    def data():
        claims = peek_jwt(g.aauth.token)[1]
        return {"sub": claims.get("sub"), "scope": claims.get("scope"), "iss": claims.get("iss")}

    transport.add(url, app)
    return config


def make_multi_scope_resource(url: str, transport: LoopbackTransport) -> ResourceConfig:
    config = ResourceConfig(issuer=url, key=SigningKey.generate(), key_resolver=JwksResolver(transport))
    app = Flask(__name__)
    install_resource(app, config)

    @app.get("/api/read")
    @require_auth_token(config, scope="docs.read")
    def read():
        claims = peek_jwt(g.aauth.token)[1]
        return {"scope": claims.get("scope")}

    @app.get("/api/write")
    @require_auth_token(config, scope="docs.write")
    def write():
        claims = peek_jwt(g.aauth.token)[1]
        return {"scope": claims.get("scope")}

    transport.add(url, app)
    return config


@pytest.fixture
def world():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)
    make_resource(RESOURCE_URL, transport, scope="docs.read")
    return transport, ps_app


@pytest.fixture
def session(world):
    transport, _ = world
    return AgentSession.enroll(AP_URL, "assistant", transport, ps=PS_URL)


def login_person(transport: LoopbackTransport, ps_url: str, person: str = "user-alice"):
    return transport.request("POST", f"{ps_url}/login", json={"person": person})


def start_pending_consent(transport: LoopbackTransport, session: AgentSession, ps_url: str) -> str:
    authz = HttpRequest("POST", f"{RESOURCE_URL}/authorize", {})
    sign(authz, session.key, session.agent_token)
    authz_response = transport.request(
        "POST", authz.url, headers=authz.headers, json={"scope": "docs.read"}
    )
    resource_token = authz_response.json()["resource_token"]

    token_req = HttpRequest("POST", f"{ps_url}/token", {})
    sign(token_req, session.key, session.agent_token)
    token_response = transport.request(
        "POST", token_req.url, headers=token_req.headers, json={"resource_token": resource_token}
    )
    assert token_response.status_code == 202
    return token_response.headers["Location"].rsplit("/", 1)[-1]


def get_resource_token(transport: LoopbackTransport, session: AgentSession, resource_url: str, scope: str) -> str:
    authz = HttpRequest("POST", f"{resource_url}/authorize", {})
    sign(authz, session.key, session.agent_token)
    response = transport.request("POST", authz.url, headers=authz.headers, json={"scope": scope})
    assert response.status_code == 200
    return response.json()["resource_token"]


def post_ps_token(
    transport: LoopbackTransport,
    session: AgentSession,
    ps_url: str,
    resource_token: str,
    **body,
):
    req = HttpRequest("POST", f"{ps_url}/token", {})
    sign(req, session.key, session.agent_token)
    payload = {"resource_token": resource_token}
    payload.update(body)
    return transport.request("POST", req.url, headers=req.headers, json=payload)


def test_challenge_flow_end_to_end(session):
    """Cold call -> 401 auth-token challenge -> PS exchange -> retry -> 200."""
    response = session.get(f"{RESOURCE_URL}/api/data")
    assert response.status_code == 200
    body = response.json()
    assert body["iss"] == PS_URL  # PS-issued auth token
    assert body["sub"] == directed_sub("user-alice", RESOURCE_URL)
    assert "docs.read" in body["scope"]
    # auth token is cached for subsequent calls
    assert RESOURCE_URL in session._auth_tokens


def test_challenge_header_shape(world, session):
    """The raw 401 carries requirement=auth-token with a resource token (§6.6)."""
    transport, _ = world
    req = HttpRequest("GET", f"{RESOURCE_URL}/api/data", {})
    sign(req, session.key, session.agent_token)
    response = transport.request("GET", req.url, headers=req.headers)
    assert response.status_code == 401
    requirement, params = parse_requirement(response.headers["AAuth-Requirement"])
    assert requirement == "auth-token"
    _, rt_claims = peek_jwt(params["resource-token"])
    assert rt_claims["aud"] == PS_URL  # routed to the agent's PS
    assert rt_claims["agent"] == session.agent_id


def test_proactive_authorize(session):
    session.authorize(RESOURCE_URL, "docs.read")
    response = session.get(f"{RESOURCE_URL}/api/data")
    assert response.status_code == 200


def test_deferred_consent_grant_and_deny(world):
    transport, _ = world
    for decision, expect_ok in (("grant", True), ("deny", False)):
        ps_url = f"http://ps-{decision}.local"
        ps_app = create_ps(ps_url, transport=transport, policy=lambda a, r: "pending")
        transport.add(ps_url, ps_app)

        def consent(location, headers, _decision=decision, _ps=ps_url):
            pid = location.rsplit("/", 1)[-1]
            login_person(transport, _ps)
            transport.request("POST", f"{_ps}/consent/{pid}", json={"decision": _decision})

        session = AgentSession.enroll(AP_URL, f"agent-{decision}", transport, ps=ps_url)
        session.on_pending = consent
        if expect_ok:
            assert session.get(f"{RESOURCE_URL}/api/data").status_code == 200
        else:
            with pytest.raises(AAuthError) as err:
                session.get(f"{RESOURCE_URL}/api/data")
            assert err.value.code == "denied"


def test_grant_binds_agent_to_person(world, session):
    transport, ps_app = world
    assert session.get(f"{RESOURCE_URL}/api/data").status_code == 200
    ps = ps_app.extensions["aauth_ps"]
    assert ps["agent_bindings"][session.agent_id] == "user-alice"


def test_second_person_cannot_claim_bound_agent(world, session):
    transport, ps_app = world
    assert session.get(f"{RESOURCE_URL}/api/data").status_code == 200

    bob_app = create_ps(
        PS_URL,
        transport=transport,
        person="user-bob",
        agent_bindings=ps_app.extensions["aauth_ps"]["agent_bindings"],
    )
    transport.add(PS_URL, bob_app)

    bob_session = AgentSession(session.key, session.agent_token, transport)
    with pytest.raises(AAuthError) as err:
        bob_session.authorize(RESOURCE_URL, "docs.read")
    assert err.value.code == "denied"
    assert bob_app.extensions["aauth_ps"]["agent_bindings"][session.agent_id] == "user-alice"


def test_remembered_consent_bypasses_policy(world):
    transport, _ = world
    calls = {"count": 0}

    def policy(agent_claims, rt_claims):
        calls["count"] += 1
        return "grant"

    ps_url = "http://ps-remember.local"
    ps_app = create_ps(ps_url, transport=transport, policy=policy)
    transport.add(ps_url, ps_app)
    session = AgentSession.enroll(AP_URL, "remember", transport, ps=ps_url)

    session.authorize(RESOURCE_URL, "docs.read")
    session.authorize(RESOURCE_URL, "docs.read")

    assert calls["count"] == 1
    assert ("user-alice", session.agent_id, RESOURCE_URL, "docs.read") in ps_app.extensions["aauth_ps"]["consents"]


def test_remembered_consent_is_per_agent(world):
    transport, _ = world
    calls = {"count": 0}

    def policy(agent_claims, rt_claims):
        calls["count"] += 1
        return "grant"

    ps_url = "http://ps-per-agent.local"
    ps_app = create_ps(ps_url, transport=transport, policy=policy)
    transport.add(ps_url, ps_app)
    first = AgentSession.enroll(AP_URL, "per-agent-one", transport, ps=ps_url)
    second = AgentSession.enroll(AP_URL, "per-agent-two", transport, ps=ps_url)

    first.authorize(RESOURCE_URL, "docs.read")
    second.authorize(RESOURCE_URL, "docs.read")

    assert calls["count"] == 2
    consents = ps_app.extensions["aauth_ps"]["consents"]
    assert ("user-alice", first.agent_id, RESOURCE_URL, "docs.read") in consents
    assert ("user-alice", second.agent_id, RESOURCE_URL, "docs.read") in consents


def test_deferred_grant_records_binding_and_consent(world):
    transport, _ = world
    ps_url = "http://ps-deferred-grant.local"
    ps_app = create_ps(ps_url, transport=transport, policy=lambda a, r: "pending")
    transport.add(ps_url, ps_app)

    def consent(location, headers):
        pid = location.rsplit("/", 1)[-1]
        login_person(transport, ps_url)
        transport.request("POST", f"{ps_url}/consent/{pid}", json={"decision": "grant"})

    session = AgentSession.enroll(AP_URL, "deferred-grant", transport, ps=ps_url)
    session.on_pending = consent
    assert session.get(f"{RESOURCE_URL}/api/data").status_code == 200

    ps = ps_app.extensions["aauth_ps"]
    assert ps["agent_bindings"][session.agent_id] == "user-alice"
    assert ("user-alice", session.agent_id, RESOURCE_URL, "docs.read") in ps["consents"]


def test_deferred_deny_does_not_bind_or_remember(world):
    transport, _ = world
    ps_url = "http://ps-deferred-deny.local"
    ps_app = create_ps(ps_url, transport=transport, policy=lambda a, r: "pending")
    transport.add(ps_url, ps_app)

    def deny(location, headers):
        pid = location.rsplit("/", 1)[-1]
        login_person(transport, ps_url)
        transport.request("POST", f"{ps_url}/consent/{pid}", json={"decision": "deny"})

    session = AgentSession.enroll(AP_URL, "deferred-deny", transport, ps=ps_url)
    session.on_pending = deny
    with pytest.raises(AAuthError) as err:
        session.get(f"{RESOURCE_URL}/api/data")
    assert err.value.code == "denied"

    ps = ps_app.extensions["aauth_ps"]
    assert session.agent_id not in ps["agent_bindings"]
    assert ("user-alice", session.agent_id, RESOURCE_URL, "docs.read") not in ps["consents"]


def test_consent_requires_authenticated_person(world):
    transport, _ = world
    ps_url = "http://ps-auth-required.local"
    ps_app = create_ps(ps_url, transport=transport, policy=lambda a, r: "pending")
    transport.add(ps_url, ps_app)

    session = AgentSession.enroll(AP_URL, "auth-required", transport, ps=ps_url)
    pid = start_pending_consent(transport, session, ps_url)
    response = transport.request("POST", f"{ps_url}/consent/{pid}", json={"decision": "grant"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"
    assert transport.request("GET", f"{ps_url}/pending/{pid}").status_code == 202

    ps = ps_app.extensions["aauth_ps"]
    assert session.agent_id not in ps["agent_bindings"]
    assert ("user-alice", session.agent_id, RESOURCE_URL, "docs.read") not in ps["consents"]


def test_authenticated_person_can_review_verified_pending_request(world):
    transport, _ = world
    ps_url = "http://ps-review.local"
    transport.add(
        ps_url,
        create_ps(ps_url, transport=transport, policy=lambda _agent, _resource: "pending"),
    )
    session = AgentSession.enroll(AP_URL, "review", transport, ps=ps_url)
    pid = start_pending_consent(transport, session, ps_url)

    anonymous = transport.request("GET", f"{ps_url}/consent/{pid}")
    assert anonymous.status_code == 401

    login_person(transport, ps_url)
    first = transport.request("GET", f"{ps_url}/consent/{pid}")
    second = transport.request("GET", f"{ps_url}/consent/{pid}")

    assert first.status_code == 200
    assert first.json()["agent"] == session.agent_id
    assert first.json()["resource"] == RESOURCE_URL
    assert first.json()["audience"] == ps_url
    assert first.json()["scope"] == "docs.read"
    assert first.json()["claims"]["agent"] == session.agent_id
    assert first.json()["claims"]["iss"] == RESOURCE_URL
    assert "resource_token" not in first.json()
    assert "agent_token" not in first.json()
    assert second.json() == first.json()
    assert transport.request("GET", f"{ps_url}/pending/{pid}").status_code == 202

    recorded = transport.request(
        "POST",
        f"{ps_url}/consent/{pid}",
        json={"decision": "deny"},
    )
    completed_review = transport.request("GET", f"{ps_url}/consent/{pid}")

    assert recorded.status_code == 200
    assert completed_review.status_code == 404


def test_consent_rejects_wrong_person_login(world):
    transport, _ = world
    ps_url = "http://ps-wrong-person.local"
    transport.add(ps_url, create_ps(ps_url, transport=transport, policy=lambda a, r: "pending"))

    response = login_person(transport, ps_url, person="user-bob")
    assert response.status_code == 403
    assert response.json()["error"] == "denied"


def test_ps_rejects_foreign_or_misbound_resource_tokens(world, session):
    transport, ps_app = world
    ps = ps_app.extensions["aauth_ps"]
    resource_key = SigningKey.generate()
    # bound to a different key than the requesting agent's
    bad_rt = issue_resource_token(
        issuer=RESOURCE_URL, aud=PS_URL, agent=session.agent_id,
        agent_jkt=SigningKey.generate().thumbprint, scope="docs.read", key=resource_key,
    )
    req = HttpRequest("POST", f"{PS_URL}/token", {})
    sign(req, session.key, session.agent_token)
    response = transport.request("POST", req.url, headers=req.headers, json={"resource_token": bad_rt})
    # resource key isn't discoverable either (docs.local metadata is resource_key-less),
    # so this fails at signature or binding — both are rejections
    assert response.status_code in (400, 401)
    assert response.json()["error"] in ("invalid_token", "invalid_signature")
    assert ps["issuer"] == PS_URL


def test_scope_containment_enforced(world, session):
    """An auth token granting docs.write does not open a docs.read endpoint."""
    transport, _ = world
    session.authorize(RESOURCE_URL, "docs.write")  # mints + exchanges for the wrong scope
    req = HttpRequest("GET", f"{RESOURCE_URL}/api/data", {})
    sign(req, session.key, session._auth_tokens[RESOURCE_URL])
    response = transport.request("GET", req.url, headers=req.headers)
    assert response.status_code == 403
    assert response.json()["error"] == "denied"


def test_ps_rejects_requested_scope_broader_than_resource_token(world, session):
    transport, ps_app = world
    resource_token = get_resource_token(transport, session, RESOURCE_URL, "docs.read")

    response = post_ps_token(transport, session, PS_URL, resource_token, scope="docs.write")

    assert response.status_code == 403
    assert response.json()["error"] == "denied"
    ps = ps_app.extensions["aauth_ps"]
    assert ("user-alice", session.agent_id, RESOURCE_URL, "docs.read") not in ps["consents"]


def test_clarification_flow_resolves_after_agent_response(world):
    transport, _ = world
    ps_url = "http://ps-clarify.local"
    ps_app = create_ps(ps_url, transport=transport, policy=lambda a, r: "clarification")
    transport.add(ps_url, ps_app)
    session = AgentSession.enroll(AP_URL, "clarifier", transport, ps=ps_url)
    resource_token = get_resource_token(transport, session, RESOURCE_URL, "docs.read")

    response = post_ps_token(transport, session, ps_url, resource_token)
    assert response.status_code == 202
    requirement, _ = parse_requirement(response.headers["AAuth-Requirement"])
    assert requirement == "clarification"
    assert response.json()["question"]

    pid = response.headers["Location"].rsplit("/", 1)[-1]
    clarification = transport.request(
        "POST",
        f"{ps_url}/pending/{pid}",
        json={"action": "clarification_response", "response": "Need this to read the document."},
    )
    assert clarification.status_code == 200
    result = transport.request("GET", f"{ps_url}/pending/{pid}")
    assert result.status_code == 200
    _, claims = peek_jwt(result.json()["auth_token"])
    assert claims["scope"] == "docs.read"
    assert ps_app.extensions["aauth_ps"]["agent_bindings"][session.agent_id] == "user-alice"


def test_resource_initiated_interaction_must_be_completed(world):
    transport, _ = world
    config = make_resource(INTERACTION_URL, transport, scope="docs.read")
    session = AgentSession.enroll(AP_URL, "interaction", transport, ps=PS_URL)
    resource_token = issue_resource_token(
        issuer=INTERACTION_URL,
        aud=PS_URL,
        agent=session.agent_id,
        agent_jkt=session.key.thumbprint,
        scope="docs.read",
        interaction={"url": f"{INTERACTION_URL}/confirm", "label": "Confirm document access"},
        key=config.key,
    )

    response = post_ps_token(transport, session, PS_URL, resource_token)
    assert response.status_code == 202
    requirement, params = parse_requirement(response.headers["AAuth-Requirement"])
    assert requirement == "interaction"
    assert params["url"].startswith(f"{PS_URL}/interaction/")

    login_person(transport, PS_URL)
    pid = response.headers["Location"].rsplit("/", 1)[-1]
    completion = transport.request("POST", f"{PS_URL}/interaction/{pid}", json={"decision": "grant"})
    assert completion.status_code == 200
    result = transport.request("GET", f"{PS_URL}/pending/{pid}")
    assert result.status_code == 200
    _, claims = peek_jwt(result.json()["auth_token"])
    assert claims["aud"] == INTERACTION_URL
    assert claims["scope"] == "docs.read"

    second = post_ps_token(transport, session, PS_URL, resource_token)
    assert second.status_code == 202
    requirement, _ = parse_requirement(second.headers["AAuth-Requirement"])
    assert requirement == "interaction"


def test_directed_sub_differs_across_resources(world, session):
    transport, _ = world
    make_resource(DOCS_URL, transport, scope="docs.read")
    sub_a = session.get(f"{RESOURCE_URL}/api/data").json()["sub"]
    sub_b = session.get(f"{DOCS_URL}/api/data").json()["sub"]
    assert sub_a != sub_b  # pairwise pseudonymous (§15.1)
    # ...but stable per resource
    assert session.get(f"{RESOURCE_URL}/api/data").json()["sub"] == sub_a


def test_expired_cached_auth_token_recovers(world, session):
    transport, ps_app = world
    ps = ps_app.extensions["aauth_ps"]
    expired = issue_auth_token(
        issuer=PS_URL, dwk="aauth-person.json", aud=RESOURCE_URL, agent=session.agent_id,
        cnf_jwk=session.key.public_jwk, sub="u_x", scope="docs.read", key=ps["key"],
        now=lambda: 1000.0,
    )
    session._auth_tokens[RESOURCE_URL] = expired
    response = session.get(f"{RESOURCE_URL}/api/data")  # evict -> challenge -> exchange -> 200
    assert response.status_code == 200


def test_narrow_cached_auth_token_recovers_for_new_scope(world, session):
    transport, _ = world
    multi_url = "http://multi-scope.local"
    make_multi_scope_resource(multi_url, transport)

    read = session.get(f"{multi_url}/api/read")
    assert read.status_code == 200
    assert read.json()["scope"] == "docs.read"

    write = session.get(f"{multi_url}/api/write")
    assert write.status_code == 200
    assert write.json()["scope"] == "docs.write"
