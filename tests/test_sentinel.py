import pytest

from aauth_edocs import (
    AAuthError,
    ControllerPolicy,
    Dataflow,
    ExactRule,
    SentinelRegistry,
    SigningKey,
    aggregate_controller_decisions,
    issue_auth_token,
    issue_controller_decision,
    issue_resource_token,
    peek_jwt,
    static_resolver,
    verify_auth_token,
)

RESOURCE = "https://resource.example"
SENTINEL = "https://sentinel.example"
AS_A = "https://as-a.example"
AS_B = "https://as-b.example"
ADVISORY = ("https://advisory-a.example", "https://advisory-b.example")


@pytest.fixture
def proposal(agent):
    return Dataflow(
        source="aauth:source@ap.example",
        function="identity@1",
        document="doc-123",
        destination=agent,
    )


@pytest.fixture
def controller_keys():
    return {
        AS_A: SigningKey.generate(kid="as-a"),
        AS_B: SigningKey.generate(kid="as-b"),
    }


@pytest.fixture
def sentinel_key():
    return SigningKey.generate(kid="sentinel")


@pytest.fixture
def decision_resolver(controller_keys, sentinel_key):
    return static_resolver(
        {
            **{issuer: key.public_jwk for issuer, key in controller_keys.items()},
            SENTINEL: sentinel_key.public_jwk,
        }
    )


def _decision(issuer, key, policy, proposal, agent_key):
    return issue_controller_decision(
        proposal=proposal,
        policy=policy,
        issuer=issuer,
        sentinel=SENTINEL,
        agent_jwk=agent_key.public_jwk,
        controllers=ADVISORY,
        key=key,
    )


def _normal_response(issuer, key, proposal, agent_key, **changes):
    values = {
        "issuer": issuer,
        "dwk": "aauth-access.json",
        "aud": SENTINEL,
        "agent": proposal.destination,
        "cnf_jwk": agent_key.public_jwk,
        "scope": proposal.function,
        "source_agent": proposal.source,
        "edoc_id": proposal.document,
        "controllers": ADVISORY,
        "key": key,
    }
    values.update(changes)
    return issue_auth_token(**values)


def _aggregate(
    *,
    proposal,
    responses,
    agent_key,
    sentinel_key,
    decision_resolver,
    registry=None,
    advisory_controllers=ADVISORY,
):
    registry = registry or SentinelRegistry(
        controllers={(RESOURCE, proposal.document): (AS_A, AS_B)}
    )
    token = aggregate_controller_decisions(
        proposal=proposal,
        resource_issuer=RESOURCE,
        advisory_controllers=advisory_controllers,
        responses=responses,
        agent_jwk=agent_key.public_jwk,
        registry=registry,
        sentinel_issuer=SENTINEL,
        sentinel_key=sentinel_key,
        key_resolver=decision_resolver,
    )
    return token, registry


def test_two_unconditional_approvals_mint_one_final_token(
    proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    policy = ControllerPolicy((ExactRule(proposal),))
    responses = {
        issuer: _decision(issuer, key, policy, proposal, agent_key)
        for issuer, key in controller_keys.items()
    }

    token, registry = _aggregate(
        proposal=proposal,
        responses=responses,
        agent_key=agent_key,
        sentinel_key=sentinel_key,
        decision_resolver=decision_resolver,
    )

    header, claims = peek_jwt(token)
    assert header["typ"] == "aa-auth+jwt"
    assert claims["iss"] == SENTINEL
    assert claims["aud"] == RESOURCE
    assert claims["agent"] == proposal.destination
    assert claims["controllers"] == [AS_A, AS_B]
    assert proposal not in registry.materialized
    verify_auth_token(
        token,
        decision_resolver,
        aud=RESOURCE,
        signing_jwk=agent_key.public_jwk,
        source_agent=proposal.source,
        scope=proposal.function,
        edoc_id=proposal.document,
        controllers=(AS_A, AS_B),
    )


def test_satisfied_conditional_and_unconditional_approvals_succeed(
    proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    prerequisite = Dataflow(
        source="aauth:upstream@ap.example",
        function="prepare@1",
        document="doc-input",
        destination=proposal.destination,
    )
    responses = {
        AS_A: _decision(
            AS_A,
            controller_keys[AS_A],
            ControllerPolicy((ExactRule(proposal),)),
            proposal,
            agent_key,
        ),
        AS_B: _decision(
            AS_B,
            controller_keys[AS_B],
            ControllerPolicy((ExactRule(proposal, prerequisite),)),
            proposal,
            agent_key,
        ),
    }
    registry = SentinelRegistry(
        controllers={(RESOURCE, proposal.document): (AS_A, AS_B)},
        materialized={prerequisite},
    )

    _, registry = _aggregate(
        proposal=proposal,
        responses=responses,
        agent_key=agent_key,
        sentinel_key=sentinel_key,
        decision_resolver=decision_resolver,
        registry=registry,
    )

    assert proposal not in registry.materialized


def test_missing_prerequisite_denies_without_materializing(
    proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    prerequisite = Dataflow("a", "f", "d", "b")
    responses = {
        AS_A: _decision(
            AS_A,
            controller_keys[AS_A],
            ControllerPolicy((ExactRule(proposal),)),
            proposal,
            agent_key,
        ),
        AS_B: _decision(
            AS_B,
            controller_keys[AS_B],
            ControllerPolicy((ExactRule(proposal, prerequisite),)),
            proposal,
            agent_key,
        ),
    }
    registry = SentinelRegistry(controllers={(RESOURCE, proposal.document): (AS_A, AS_B)})

    with pytest.raises(AAuthError, match="has not materialized") as caught:
        _aggregate(
            proposal=proposal,
            responses=responses,
            agent_key=agent_key,
            sentinel_key=sentinel_key,
            decision_resolver=decision_resolver,
            registry=registry,
        )

    assert caught.value.code == "denied"
    assert proposal not in registry.materialized


@pytest.mark.parametrize(
    "response_keys",
    [
        (AS_A,),
        (AS_A, AS_B, "https://unexpected.example"),
    ],
)
def test_response_set_must_exactly_match_authoritative_controllers(
    response_keys, proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    policy = ControllerPolicy((ExactRule(proposal),))
    responses = {
        issuer: _decision(AS_A, controller_keys[AS_A], policy, proposal, agent_key)
        for issuer in response_keys
    }

    with pytest.raises(AAuthError, match="exactly match"):
        _aggregate(
            proposal=proposal,
            responses=responses,
            agent_key=agent_key,
            sentinel_key=sentinel_key,
            decision_resolver=decision_resolver,
        )


def test_response_must_be_issued_by_controller_it_is_keyed_under(
    proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    policy = ControllerPolicy((ExactRule(proposal),))
    responses = {
        AS_A: _decision(AS_B, controller_keys[AS_B], policy, proposal, agent_key),
        AS_B: _decision(AS_B, controller_keys[AS_B], policy, proposal, agent_key),
    }

    with pytest.raises(AAuthError, match="issuer mismatch"):
        _aggregate(
            proposal=proposal,
            responses=responses,
            agent_key=agent_key,
            sentinel_key=sentinel_key,
            decision_resolver=decision_resolver,
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"aud": "https://other-sentinel.example"}, "aud"),
        ({"agent": "aauth:other@ap.example"}, "agent"),
        ({"source_agent": "aauth:other@ap.example"}, "source_agent"),
        ({"scope": "other@1"}, "scope"),
        ({"edoc_id": "doc-456"}, "edoc_id"),
        ({"controllers": tuple(reversed(ADVISORY))}, "controllers"),
    ],
)
def test_mismatched_controller_binding_denies_without_materializing(
    changes,
    message,
    proposal,
    controller_keys,
    agent_key,
    sentinel_key,
    decision_resolver,
):
    policy = ControllerPolicy((ExactRule(proposal),))
    responses = {
        AS_A: _normal_response(AS_A, controller_keys[AS_A], proposal, agent_key, **changes),
        AS_B: _decision(AS_B, controller_keys[AS_B], policy, proposal, agent_key),
    }
    registry = SentinelRegistry(controllers={(RESOURCE, proposal.document): (AS_A, AS_B)})

    with pytest.raises(AAuthError, match=message):
        _aggregate(
            proposal=proposal,
            responses=responses,
            agent_key=agent_key,
            sentinel_key=sentinel_key,
            decision_resolver=decision_resolver,
            registry=registry,
        )

    assert proposal not in registry.materialized


def test_wrong_agent_confirmation_key_denies_without_materializing(
    proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    other_agent_key = SigningKey.generate(kid="other-agent")
    policy = ControllerPolicy((ExactRule(proposal),))
    responses = {
        AS_A: _normal_response(
            AS_A,
            controller_keys[AS_A],
            proposal,
            agent_key,
            cnf_jwk=other_agent_key.public_jwk,
        ),
        AS_B: _decision(AS_B, controller_keys[AS_B], policy, proposal, agent_key),
    }
    registry = SentinelRegistry(controllers={(RESOURCE, proposal.document): (AS_A, AS_B)})

    with pytest.raises(AAuthError, match="cnf.jwk"):
        _aggregate(
            proposal=proposal,
            responses=responses,
            agent_key=agent_key,
            sentinel_key=sentinel_key,
            decision_resolver=decision_resolver,
            registry=registry,
        )

    assert proposal not in registry.materialized


def test_unsupported_controller_token_type_denies_without_materializing(
    proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    policy = ControllerPolicy((ExactRule(proposal),))
    responses = {
        AS_A: issue_resource_token(
            issuer=AS_A,
            aud=SENTINEL,
            agent=proposal.destination,
            agent_jkt=agent_key.thumbprint,
            scope=proposal.function,
            source_agent=proposal.source,
            edoc_id=proposal.document,
            controllers=ADVISORY,
            key=controller_keys[AS_A],
        ),
        AS_B: _decision(AS_B, controller_keys[AS_B], policy, proposal, agent_key),
    }
    registry = SentinelRegistry(controllers={(RESOURCE, proposal.document): (AS_A, AS_B)})

    with pytest.raises(AAuthError, match="unsupported controller token type"):
        _aggregate(
            proposal=proposal,
            responses=responses,
            agent_key=agent_key,
            sentinel_key=sentinel_key,
            decision_resolver=decision_resolver,
            registry=registry,
        )

    assert proposal not in registry.materialized


def test_advisory_controllers_do_not_determine_required_responses(
    proposal, controller_keys, agent_key, sentinel_key, decision_resolver
):
    policy = ControllerPolicy((ExactRule(proposal),))
    responses = {
        issuer: _decision(issuer, key, policy, proposal, agent_key)
        for issuer, key in controller_keys.items()
    }

    token, _ = _aggregate(
        proposal=proposal,
        responses=responses,
        agent_key=agent_key,
        sentinel_key=sentinel_key,
        decision_resolver=decision_resolver,
    )

    _, claims = peek_jwt(token)
    assert claims["controllers"] == [AS_A, AS_B]
