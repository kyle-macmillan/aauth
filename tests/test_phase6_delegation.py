"""Phase 6 internal-demo delegation and third-party login tests."""

import pytest

from aauth_edocs import (
    AAuthError,
    AgentSession,
    HttpRequest,
    JwksResolver,
    ResourceConfig,
    SigningKey,
    create_ap,
    create_ps,
    install_resource,
    issue_auth_token,
    issue_resource_token,
    peek_jwt,
    sign,
)
from conftest import LoopbackTransport

AP_URL = "http://ap.local"
PS_URL = "http://ps.local"
RESOURCE_URL = "http://resource.local"
DOWNSTREAM_URL = "http://downstream.local"


@pytest.fixture
def world():
    transport = LoopbackTransport()
    transport.add(AP_URL, create_ap(AP_URL))
    ps_app = create_ps(PS_URL, transport=transport)
    transport.add(PS_URL, ps_app)
    resource_key = SigningKey.generate(kid="res")
    resource = install_test_resource(transport, RESOURCE_URL, resource_key)
    downstream_key = SigningKey.generate(kid="down")
    downstream = install_test_resource(transport, DOWNSTREAM_URL, downstream_key)
    return transport, ps_app, resource, downstream


@pytest.fixture
def parent(world):
    transport, *_ = world
    return AgentSession.enroll(AP_URL, "assistant", transport, ps=PS_URL)


def install_test_resource(transport: LoopbackTransport, url: str, key: SigningKey):
    from flask import Flask

    config = ResourceConfig(issuer=url, key=key, key_resolver=JwksResolver(transport))
    app = Flask(__name__)
    install_resource(app, config)
    transport.add(url, app)
    return config


def resource_token(config: ResourceConfig, agent: str, agent_jkt: str, scope: str = "docs.read") -> str:
    return issue_resource_token(
        issuer=config.issuer,
        aud=PS_URL,
        agent=agent,
        agent_jkt=agent_jkt,
        scope=scope,
        key=config.key,
    )


def signed_ps_token(transport: LoopbackTransport, session: AgentSession, **body):
    req = HttpRequest("POST", f"{PS_URL}/token", {})
    sign(req, session.key, session.agent_token)
    return transport.request("POST", req.url, headers=req.headers, json=body)


def test_subagent_enrollment_adds_parent_claim(world, parent):
    sub = AgentSession.enroll_subagent(AP_URL, parent, "researcher")

    _, claims = peek_jwt(sub.agent_token)
    assert claims["sub"] == "aauth:assistant+researcher@ap.local"
    assert claims["parent_agent"] == parent.agent_id
    assert claims["ps"] == PS_URL


def test_ap_rejects_nested_subagent(world, parent):
    transport = world[0]
    sub = AgentSession.enroll_subagent(AP_URL, parent, "researcher")

    with pytest.raises(AAuthError) as err:
        AgentSession.enroll_subagent(AP_URL, sub, "nested")

    assert err.value.code == "invalid_request"


def test_ps_rejects_subagent_without_parent_token(world, parent):
    transport, _, resource, _ = world
    sub = AgentSession.enroll_subagent(AP_URL, parent, "researcher")
    rt = resource_token(resource, parent.agent_id, sub.key.thumbprint)

    response = signed_ps_token(transport, sub, resource_token=rt)

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_parent_mediated_subagent_authorization(world, parent):
    transport, _, resource, _ = world
    sub = AgentSession.enroll_subagent(AP_URL, parent, "researcher")
    rt = resource_token(resource, parent.agent_id, sub.key.thumbprint)

    token = sub.exchange(rt, subagent_token=parent.agent_token)
    _, claims = peek_jwt(token)

    assert claims["agent"] == sub.agent_id
    assert claims["act"]["agent"] == parent.agent_id
    assert claims["cnf"]["jwk"] == sub.key.public_jwk


def test_call_chaining_sets_act_agent(world, parent):
    transport, ps_app, resource, downstream = world
    upstream = issue_auth_token(
        issuer=PS_URL,
        dwk="aauth-person.json",
        aud=RESOURCE_URL,
        agent=parent.agent_id,
        cnf_jwk=parent.key.public_jwk,
        sub="u_chain",
        scope="docs.read",
        key=ps_app.extensions["aauth_ps"]["key"],
    )
    rt = resource_token(downstream, parent.agent_id, parent.key.thumbprint)

    token = parent.exchange(rt, upstream_token=upstream, upstream_aud=RESOURCE_URL)
    _, claims = peek_jwt(token)

    assert claims["aud"] == DOWNSTREAM_URL
    assert claims["act"]["agent"] == parent.agent_id


def test_bad_upstream_token_audience_rejected(world, parent):
    transport, ps_app, _, downstream = world
    bad_upstream = issue_auth_token(
        issuer=PS_URL,
        dwk="aauth-person.json",
        aud="http://wrong-resource.local",
        agent=parent.agent_id,
        cnf_jwk=parent.key.public_jwk,
        sub="u_chain",
        scope="docs.read",
        key=ps_app.extensions["aauth_ps"]["key"],
    )
    rt = resource_token(downstream, parent.agent_id, parent.key.thumbprint)

    with pytest.raises(AAuthError) as err:
        parent.exchange(rt, upstream_token=bad_upstream, upstream_aud=RESOURCE_URL)

    assert err.value.code == "invalid_token"


def test_ps_metadata_and_third_party_login(world):
    transport = world[0]
    metadata = transport.get(f"{PS_URL}/.well-known/aauth-person.json").json()
    assert metadata["login_endpoint"] == f"{PS_URL}/login/start"

    ok = transport.request("POST", metadata["login_endpoint"], json={"ps": PS_URL, "start_path": "/welcome"})
    assert ok.status_code == 200
    assert ok.json()["start_path"] == "/welcome"


def test_third_party_login_rejects_wrong_ps_and_external_start_path(world):
    transport = world[0]

    wrong_ps = transport.request("POST", f"{PS_URL}/login/start", json={"ps": "http://other.local"})
    assert wrong_ps.status_code == 400

    external = transport.request(
        "POST",
        f"{PS_URL}/login/start",
        json={"ps": PS_URL, "start_path": "https://evil.example/"},
    )
    assert external.status_code == 400

    scheme_relative = transport.request(
        "POST",
        f"{PS_URL}/login/start",
        json={"ps": PS_URL, "start_path": "//evil.example/"},
    )
    assert scheme_relative.status_code == 400
