import pytest

from aauth_edocs import (
    AAuthError,
    ControllerPolicy,
    Dataflow,
    ExactRule,
    issue_controller_decision,
    peek_jwt,
    verify_auth_token,
    verify_conditional_auth_token,
)
from conftest import PS

SENTINEL = "https://sentinel.example"
CONTROLLERS = ("https://as-a.example", "https://as-b.example")


def _flow(**changes) -> Dataflow:
    values = {
        "source": "aauth:source@ap.example",
        "function": "identity@1",
        "document": "doc-123",
        "destination": "aauth:assistant@ap.example",
    }
    values.update(changes)
    return Dataflow(**values)


def _issue(policy, ps_key, agent_key, proposal=None):
    return issue_controller_decision(
        proposal=proposal or _flow(),
        policy=policy,
        issuer=PS,
        sentinel=SENTINEL,
        agent_jwk=agent_key.public_jwk,
        controllers=CONTROLLERS,
        key=ps_key,
    )


def test_controller_policy_matches_only_complete_dataflow():
    proposal = _flow()
    policy = ControllerPolicy((ExactRule(proposal),))

    assert policy.evaluate(proposal) == policy.rules[0]
    assert policy.evaluate(_flow(source="aauth:other@ap.example")) is None
    assert policy.evaluate(_flow(function="other@1")) is None
    assert policy.evaluate(_flow(document="doc-456")) is None
    assert policy.evaluate(_flow(destination="aauth:other@ap.example")) is None


def test_controller_policy_matches_canonical_arguments_exactly():
    proposal = Dataflow.from_arguments(
        "aauth:source@ap.example",
        "search@1",
        "doc-123",
        "aauth:assistant@ap.example",
        {"query": "termination", "limit": 20},
    )
    reordered = Dataflow.from_arguments(
        proposal.source,
        proposal.function,
        proposal.document,
        proposal.destination,
        {"limit": 20, "query": "termination"},
    )
    changed = Dataflow.from_arguments(
        proposal.source,
        proposal.function,
        proposal.document,
        proposal.destination,
        {"query": "termination", "limit": 100},
    )
    policy = ControllerPolicy((ExactRule(proposal),))

    assert policy.evaluate(reordered) == policy.rules[0]
    assert policy.evaluate(changed) is None


def test_controller_policy_rejects_duplicate_targets():
    proposal = _flow()
    with pytest.raises(ValueError, match="duplicate"):
        ControllerPolicy(
            (
                ExactRule(proposal),
                ExactRule(proposal, prerequisite=_flow(document="doc-input")),
            )
        )


@pytest.mark.parametrize(
    "policy",
    [
        ControllerPolicy(()),
        ControllerPolicy((ExactRule(_flow(document="doc-456")),)),
    ],
)
def test_controller_decision_defaults_to_denial(policy, ps_key, agent_key):
    with pytest.raises(AAuthError, match="no controller policy") as caught:
        _issue(policy, ps_key, agent_key)

    assert caught.value.code == "denied"
    assert caught.value.status == 403


def test_unconditional_controller_decision_is_sentinel_auth_token(
    ps_key, agent_key, agent, resolver
):
    proposal = _flow(destination=agent)
    token = _issue(ControllerPolicy((ExactRule(proposal),)), ps_key, agent_key, proposal)

    header, claims = peek_jwt(token)
    assert header["typ"] == "aa-auth+jwt"
    assert claims["iss"] == PS
    assert claims["dwk"] == "aauth-access.json"
    assert claims["aud"] == SENTINEL
    assert claims["agent"] == agent
    assert claims["source_agent"] == proposal.source
    assert claims["scope"] == proposal.function
    assert claims["edoc_id"] == proposal.document
    assert claims["controllers"] == list(CONTROLLERS)
    verify_auth_token(
        token,
        resolver,
        aud=SENTINEL,
        signing_jwk=agent_key.public_jwk,
        source_agent=proposal.source,
        scope=proposal.function,
        edoc_id=proposal.document,
        controllers=CONTROLLERS,
    )


def test_conditional_controller_decision_is_sentinel_conditional_token(
    ps_key, agent_key, agent, resolver
):
    proposal = _flow(destination=agent)
    prerequisite = _flow(
        source="aauth:upstream@ap.example",
        function="prepare@1",
        document="doc-input",
        destination=agent,
    )
    policy = ControllerPolicy((ExactRule(proposal, prerequisite),))

    token = _issue(policy, ps_key, agent_key, proposal)

    header, claims = peek_jwt(token)
    assert header["typ"] == "aa-conditional-auth+jwt"
    assert claims["aud"] == SENTINEL
    assert claims["agent"] == agent
    assert (
        verify_conditional_auth_token(
            token,
            resolver,
            issuer=PS,
            aud=SENTINEL,
            agent=agent,
            signing_jwk=agent_key.public_jwk,
            source_agent=proposal.source,
            scope=proposal.function,
            edoc_id=proposal.document,
            controllers=CONTROLLERS,
        )
        == prerequisite
    )
