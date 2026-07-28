from flask import Flask

from aauth_edocs import (
    ControllerPolicy,
    Dataflow,
    ExactRule,
    FunctionDescriptor,
    HttpRequest,
    JwksResolver,
    ResourceBinding,
    SentinelRegistry,
    SigningKey,
    build_metadata,
    create_sentinel,
    issue_agent_token,
    issue_resource_token,
    peek_jwt,
    sign_server,
    verify_auth_token,
)
from aauth_edocs.asrv import create_as
from conftest import LoopbackTransport

AP = "http://ap.local"
RESOURCE = "http://resource.local"
PS = "http://ps.local"
OTHER_PS = "http://other-ps.local"
SENTINEL = "http://sentinel.local"
AS_A = "http://as-a.local"
AS_B = "http://as-b.local"
AGENT = "aauth:assistant@ap.local"
SOURCE = "aauth:source@ap.local"


def _server_app(issuer, dwk, key):
    app = Flask(issuer)

    @app.get(f"/.well-known/{dwk}")
    def metadata():
        return dict(build_metadata(issuer, jwks_uri=f"{issuer}/jwks.json"))

    @app.get("/jwks.json")
    def jwks():
        return {"keys": [key.public_jwk]}

    return app


def _world(*, conditional=False, controller_b_denies=False):
    transport = LoopbackTransport()
    keys = {
        "ap": SigningKey.generate(kid="ap"),
        "resource": SigningKey.generate(kid="resource"),
        "ps": SigningKey.generate(kid="ps"),
        "other_ps": SigningKey.generate(kid="other-ps"),
        "sentinel": SigningKey.generate(kid="sentinel"),
        "as_a": SigningKey.generate(kid="as-a"),
        "as_b": SigningKey.generate(kid="as-b"),
        "agent": SigningKey.generate(kid="agent"),
    }
    proposal = Dataflow(SOURCE, "identity@1", "doc-123", AGENT)
    prerequisite = Dataflow(SOURCE, "prepare@1", "doc-input", AGENT)
    agent_token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=keys["agent"].public_jwk,
        ps=PS,
        key=keys["ap"],
    )
    descriptor = FunctionDescriptor(
        id="identity@1",
        description="Return the eDoc unchanged",
        implementation_uri="https://functions.example/identity.py",
        digest="sha256:identity",
    )
    registry = SentinelRegistry(
        resource_bindings={
            SOURCE: ResourceBinding(
                source_ps="http://source-ps.local",
                resource_issuer=RESOURCE,
                resource_jkt=keys["resource"].thumbprint,
            )
        },
        resource_owner_ases={RESOURCE: AS_A},
        controllers={(RESOURCE, "doc-123"): (AS_A, AS_B)},
        functions={descriptor.id: descriptor},
    )

    transport.add(AP, _server_app(AP, "aauth-agent.json", keys["ap"]))
    transport.add(RESOURCE, _server_app(RESOURCE, "aauth-resource.json", keys["resource"]))
    transport.add(PS, _server_app(PS, "aauth-person.json", keys["ps"]))
    transport.add(OTHER_PS, _server_app(OTHER_PS, "aauth-person.json", keys["other_ps"]))

    policy_a = ControllerPolicy((ExactRule(proposal),))
    policy_b_target = Dataflow(SOURCE, "identity@1", "other-doc", AGENT) if controller_b_denies else proposal
    policy_b = ControllerPolicy(
        (ExactRule(policy_b_target, prerequisite if conditional and not controller_b_denies else None),)
    )
    transport.add(
        AS_A,
        create_as(
            AS_A,
            key=keys["as_a"],
            transport=transport,
            sentinel=SENTINEL,
            controller_policy=policy_a,
            functions=registry.functions,
        ),
    )
    transport.add(
        AS_B,
        create_as(
            AS_B,
            key=keys["as_b"],
            transport=transport,
            sentinel=SENTINEL,
            controller_policy=policy_b,
            functions=registry.functions,
        ),
    )
    sentinel_app = create_sentinel(
        issuer=SENTINEL,
        registry=registry,
        key=keys["sentinel"],
        transport=transport,
    )
    transport.add(SENTINEL, sentinel_app)
    return {
        "transport": transport,
        "keys": keys,
        "proposal": proposal,
        "prerequisite": prerequisite,
        "agent_token": agent_token,
        "registry": registry,
    }


def _resource_token(world, **changes):
    proposal = world["proposal"]
    values = {
        "issuer": RESOURCE,
        "aud": SENTINEL,
        "agent": proposal.destination,
        "agent_jkt": world["keys"]["agent"].thumbprint,
        "scope": proposal.function,
        "source_agent": proposal.source,
        "edoc_id": proposal.document,
        "controllers": ("https://advisory-a.example",),
        "key": world["keys"]["resource"],
    }
    values.update(changes)
    return issue_resource_token(**values)


def _post(world, resource_token, *, ps=PS, agent_token=None):
    request = HttpRequest("POST", f"{SENTINEL}/token", {})
    key = world["keys"]["ps"] if ps == PS else world["keys"]["other_ps"]
    sign_server(request, key, ps, "aauth-person.json")
    return world["transport"].request(
        "POST",
        request.url,
        headers=request.headers,
        json={
            "resource_token": resource_token,
            "agent_token": agent_token or world["agent_token"],
        },
    )


def test_sentinel_http_flow_mints_one_final_resource_token():
    world = _world()

    response = _post(world, _resource_token(world))

    assert response.status_code == 200
    token = response.json()["auth_token"]
    header, claims = peek_jwt(token)
    assert header["typ"] == "aa-auth+jwt"
    assert claims["iss"] == SENTINEL
    assert claims["aud"] == RESOURCE
    assert claims["controllers"] == [AS_A, AS_B]
    assert world["proposal"] in world["registry"].materialized
    verify_auth_token(
        token,
        JwksResolver(world["transport"]),
        aud=RESOURCE,
        signing_jwk=world["keys"]["agent"].public_jwk,
        source_agent=SOURCE,
        scope="identity@1",
        edoc_id="doc-123",
        controllers=(AS_A, AS_B),
    )


def test_unknown_edoc_discovers_populated_controllers_and_caches_them():
    world = _world()
    world["registry"].controllers.clear()

    response = _post(world, _resource_token(world, controllers=(AS_A, AS_B)))

    assert response.status_code == 200
    assert world["registry"].controllers[(RESOURCE, "doc-123")] == (AS_A, AS_B)
    _, claims = peek_jwt(response.json()["auth_token"])
    assert claims["controllers"] == [AS_A, AS_B]


def test_unknown_edoc_with_empty_controllers_uses_resource_owner_as():
    world = _world()
    world["registry"].controllers.clear()

    response = _post(world, _resource_token(world, controllers=[]))

    assert response.status_code == 200
    assert world["registry"].controllers[(RESOURCE, "doc-123")] == (AS_A,)
    _, claims = peek_jwt(response.json()["auth_token"])
    assert claims["controllers"] == [AS_A]


def test_failed_unknown_edoc_discovery_is_not_cached():
    world = _world(controller_b_denies=True)
    world["registry"].controllers.clear()

    response = _post(world, _resource_token(world, controllers=(AS_A, AS_B)))

    assert response.status_code == 403
    assert (RESOURCE, "doc-123") not in world["registry"].controllers


def test_sentinel_requires_agent_token_ps_to_match_request_signer():
    world = _world()

    response = _post(world, _resource_token(world), ps=OTHER_PS)

    assert response.status_code == 403
    assert "agent token ps" in response.json()["detail"]
    assert world["proposal"] not in world["registry"].materialized


def test_sentinel_requires_resource_audience_and_agent_bindings():
    world = _world()

    wrong_aud = _post(world, _resource_token(world, aud=AS_A))
    wrong_agent = _post(world, _resource_token(world, agent="aauth:other@ap.local"))
    wrong_key = _post(world, _resource_token(world, agent_jkt="wrong-key"))

    assert wrong_aud.status_code == 400
    assert wrong_agent.status_code == 400
    assert wrong_key.status_code == 400
    assert world["proposal"] not in world["registry"].materialized


def test_sentinel_enforces_provisioned_resource_issuer_and_key():
    world = _world()
    binding = world["registry"].resource_bindings[SOURCE]

    world["registry"].resource_bindings[SOURCE] = ResourceBinding(
        binding.source_ps,
        "http://other-resource.local",
        binding.resource_jkt,
    )
    wrong_issuer = _post(world, _resource_token(world))
    world["registry"].resource_bindings[SOURCE] = ResourceBinding(
        binding.source_ps,
        binding.resource_issuer,
        SigningKey.generate().thumbprint,
    )
    wrong_key = _post(world, _resource_token(world))

    assert wrong_issuer.status_code == 403
    assert "issuer" in wrong_issuer.json()["detail"]
    assert wrong_key.status_code == 403
    assert "key" in wrong_key.json()["detail"]
    assert world["proposal"] not in world["registry"].materialized


def test_sentinel_rejects_unknown_source_function_and_edoc():
    world = _world()

    unknown_source = _post(world, _resource_token(world, source_agent="aauth:unknown@ap.local"))
    unknown_function = _post(world, _resource_token(world, scope="unknown@1"))
    unknown_edoc = _post(world, _resource_token(world, edoc_id="doc-456"))

    assert unknown_source.status_code == 403
    assert unknown_function.status_code == 403
    assert unknown_edoc.status_code == 403
    assert world["proposal"] not in world["registry"].materialized


def test_controller_denial_prevents_final_token_and_provenance():
    world = _world(controller_b_denies=True)

    response = _post(world, _resource_token(world))

    assert response.status_code == 403
    assert response.json()["error"] == "denied"
    assert world["proposal"] not in world["registry"].materialized


def test_missing_conditional_prerequisite_prevents_final_token():
    world = _world(conditional=True)

    denied = _post(world, _resource_token(world))
    world["registry"].materialized.add(world["prerequisite"])
    approved = _post(world, _resource_token(world))

    assert denied.status_code == 403
    assert "has not materialized" in denied.json()["detail"]
    assert approved.status_code == 200
    assert world["proposal"] in world["registry"].materialized
