from flask import Flask

from aauth_edocs import (
    ControllerPolicy,
    Dataflow,
    ExactRule,
    FunctionDescriptor,
    HttpRequest,
    SigningKey,
    build_metadata,
    issue_agent_token,
    issue_resource_token,
    peek_jwt,
    sign,
    sign_server,
)
from aauth_edocs.asrv import create_as
from conftest import LoopbackTransport

AP = "http://ap.local"
RESOURCE = "http://resource.local"
PS = "http://ps.local"
SENTINEL = "http://sentinel.local"
CONTROLLER = "http://controller.local"
AGENT = "aauth:assistant@ap.local"
SOURCE = "aauth:source@ap.local"
CONTROLLERS = (CONTROLLER,)


def _server_app(issuer, dwk, key):
    app = Flask(issuer)

    @app.get(f"/.well-known/{dwk}")
    def metadata():
        return dict(build_metadata(issuer, jwks_uri=f"{issuer}/jwks.json"))

    @app.get("/jwks.json")
    def jwks():
        return {"keys": [key.public_jwk]}

    return app


def _world(conditional=False):
    transport = LoopbackTransport()
    ap_key = SigningKey.generate(kid="ap")
    resource_key = SigningKey.generate(kid="resource")
    ps_key = SigningKey.generate(kid="ps")
    sentinel_key = SigningKey.generate(kid="sentinel")
    controller_key = SigningKey.generate(kid="controller")
    agent_key = SigningKey.generate(kid="agent")
    agent_token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=agent_key.public_jwk,
        ps=PS,
        key=ap_key,
    )
    proposal = Dataflow(SOURCE, "identity@1", "doc-123", AGENT)
    prerequisite = Dataflow(SOURCE, "prepare@1", "doc-input", AGENT)
    rule = ExactRule(proposal, prerequisite if conditional else None)

    transport.add(AP, _server_app(AP, "aauth-agent.json", ap_key))
    transport.add(RESOURCE, _server_app(RESOURCE, "aauth-resource.json", resource_key))
    transport.add(PS, _server_app(PS, "aauth-person.json", ps_key))
    transport.add(SENTINEL, _server_app(SENTINEL, "aauth-person.json", sentinel_key))
    app = create_as(
        CONTROLLER,
        key=controller_key,
        transport=transport,
        sentinel=SENTINEL,
        controller_policy=ControllerPolicy((rule,)),
        functions={
            "identity@1": FunctionDescriptor(
                id="identity@1",
                description="Return the eDoc unchanged",
                implementation_uri="memory://identity",
                digest="sha256:identity",
            )
        },
    )
    transport.add(CONTROLLER, app)
    return {
        "transport": transport,
        "resource_key": resource_key,
        "ps_key": ps_key,
        "sentinel_key": sentinel_key,
        "agent_key": agent_key,
        "agent_token": agent_token,
        "proposal": proposal,
        "prerequisite": prerequisite,
    }


def _resource_token(world, **changes):
    proposal = world["proposal"]
    values = {
        "issuer": RESOURCE,
        "aud": SENTINEL,
        "agent": proposal.destination,
        "agent_jkt": world["agent_key"].thumbprint,
        "scope": proposal.function,
        "source_agent": proposal.source,
        "edoc_id": proposal.document,
        "controllers": CONTROLLERS,
        "key": world["resource_key"],
    }
    values.update(changes)
    return issue_resource_token(**values)


def _post(world, resource_token, *, signer=SENTINEL, scheme="server"):
    request = HttpRequest("POST", f"{CONTROLLER}/token", {})
    if scheme == "agent":
        sign(request, world["agent_key"], world["agent_token"])
    else:
        key = world["sentinel_key"] if signer == SENTINEL else world["ps_key"]
        sign_server(request, key, signer, "aauth-person.json")
    return world["transport"].request(
        "POST",
        request.url,
        headers=request.headers,
        json={"resource_token": resource_token, "agent_token": world["agent_token"]},
    )


def test_sentinel_request_returns_unconditional_controller_token():
    world = _world()

    response = _post(world, _resource_token(world))

    assert response.status_code == 200
    header, claims = peek_jwt(response.json()["auth_token"])
    assert header["typ"] == "aa-auth+jwt"
    assert claims["iss"] == CONTROLLER
    assert claims["aud"] == SENTINEL
    assert claims["agent"] == AGENT


def test_sentinel_request_returns_conditional_controller_token():
    world = _world(conditional=True)

    response = _post(world, _resource_token(world))

    assert response.status_code == 200
    header, claims = peek_jwt(response.json()["auth_token"])
    assert header["typ"] == "aa-conditional-auth+jwt"
    assert claims["aud"] == SENTINEL
    assert claims["prerequisite"] == {
        "source": world["prerequisite"].source,
        "function": world["prerequisite"].function,
        "document": world["prerequisite"].document,
        "destination": world["prerequisite"].destination,
        "function_args_hash": world["prerequisite"].function_args_hash,
    }


def test_edocs_mode_rejects_non_sentinel_server_and_agent_callers():
    world = _world()
    resource_token = _resource_token(world)

    wrong_server = _post(world, resource_token, signer=PS)
    agent = _post(world, resource_token, scheme="agent")

    assert wrong_server.status_code == 400
    assert wrong_server.json()["error"] == "invalid_token"
    assert agent.status_code == 401


def test_edocs_mode_requires_sentinel_audience_and_agent_bindings():
    world = _world()

    wrong_aud = _post(world, _resource_token(world, aud=CONTROLLER))
    wrong_agent = _post(world, _resource_token(world, agent="aauth:other@ap.local"))
    wrong_key = _post(world, _resource_token(world, agent_jkt="wrong-key"))

    assert wrong_aud.status_code == 400
    assert wrong_agent.status_code == 400
    assert wrong_key.status_code == 400


def test_edocs_mode_requires_complete_claims_and_one_scope():
    world = _world()

    no_edocs = _post(
        world,
        issue_resource_token(
            issuer=RESOURCE,
            aud=SENTINEL,
            agent=AGENT,
            agent_jkt=world["agent_key"].thumbprint,
            scope="identity@1",
            key=world["resource_key"],
        ),
    )
    multiple_scopes = _post(world, _resource_token(world, scope="identity@1 prepare@1"))

    assert no_edocs.status_code == 400
    assert "eDocs" in no_edocs.json()["detail"]
    assert multiple_scopes.status_code == 400
    assert "exactly one scope" in multiple_scopes.json()["detail"]


def test_edocs_mode_default_denies_when_policy_does_not_match():
    world = _world()

    response = _post(world, _resource_token(world, edoc_id="doc-456"))

    assert response.status_code == 403
    assert response.json()["error"] == "denied"


def test_edocs_configuration_is_paired():
    policy = ControllerPolicy(())

    for kwargs in ({"sentinel": SENTINEL}, {"controller_policy": policy}):
        try:
            create_as(CONTROLLER, **kwargs)
        except ValueError as error:
            assert "configured together" in str(error)
        else:
            raise AssertionError("incomplete eDocs configuration was accepted")
