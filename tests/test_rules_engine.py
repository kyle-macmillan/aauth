from concurrent.futures import ThreadPoolExecutor

import pytest

from aauth_edocs import (
    Allow,
    Dataflow,
    Deny,
    OutputOf,
    ResourceBinding,
    RuleEngine,
    SentinelRegistry,
    exact_rule,
    parse_stored_rule,
    register_materialization,
    register_origin,
    serialize_rule,
)


def _flow(index: int = 0, **changes) -> Dataflow:
    values = {
        "source": "aauth:source@example",
        "function": "query@1",
        "document": f"doc-{index}",
        "destination": "aauth:destination@example",
        "arguments": {"limit": index},
    }
    values.update(changes)
    return Dataflow.from_arguments(
        values["source"],
        values["function"],
        values["document"],
        values["destination"],
        values["arguments"],
    )


def test_exact_rules_allow_only_their_exact_dataflow():
    target = _flow()
    policy = RuleEngine((exact_rule(target),))

    decision = policy.evaluate(target)
    assert decision == Allow(policy.list_rules()[0].rule_id, exact_rule(target))
    assert decision.reason is None
    assert isinstance(policy.evaluate(_flow(arguments={"limit": 100})), Deny)


def test_create_replace_and_delete_preserve_stable_rule_id():
    policy = RuleEngine()
    original = policy.create_rule(exact_rule(_flow()), rule_id="rule-1")

    assert policy.evaluate(_flow()) == Allow("rule-1", original.rule)
    replacement = policy.replace_rule("rule-1", exact_rule(_flow(1)))

    assert replacement.rule_id == "rule-1"
    assert isinstance(policy.evaluate(_flow()), Deny)
    assert policy.evaluate(_flow(1)) == Allow("rule-1", replacement.rule)
    assert policy.delete_rule("rule-1") == replacement
    assert isinstance(policy.evaluate(_flow(1)), Deny)
    with pytest.raises(KeyError, match="unknown rule ID"):
        policy.delete_rule("rule-1")


def test_duplicate_targets_and_rule_ids_are_rejected():
    policy = RuleEngine()
    policy.create_rule(exact_rule(_flow()), rule_id="first")

    with pytest.raises(ValueError, match="duplicate dataflow"):
        policy.create_rule(exact_rule(_flow()), rule_id="second")
    with pytest.raises(ValueError, match="duplicate rule ID"):
        policy.create_rule(exact_rule(_flow(1)), rule_id="first")


def test_conditional_rule_and_json_round_trip_preserve_semantics():
    target = _flow()
    prerequisite = _flow(
        1,
        function="prepare@1",
        arguments={"format": "parquet"},
    )
    policy = RuleEngine()
    stored = policy.create_rule(
        exact_rule(target, prerequisite),
        rule_id="conditional-1",
    )

    decoded = parse_stored_rule(serialize_rule(stored))

    assert decoded == stored
    assert policy.evaluate(target).rule.prerequisite == prerequisite


def test_future_output_rule_matches_only_after_trusted_materialization():
    producer = _flow()
    registry = SentinelRegistry(
        resource_bindings={
            producer.source: ResourceBinding(
                source_ps="https://source-ps.example",
                resource_issuer="https://resource.example",
                resource_jkt="resource-key-thumbprint",
            )
        }
    )
    register_origin(
        registry,
        resource_issuer="https://resource.example",
        edoc_id=producer.document,
        controllers=["https://alice-as.example"],
    )
    target = Dataflow.from_arguments(
        source=producer.destination,
        function="identity@1",
        document=OutputOf(producer),
        destination="aauth:carol@example",
        arguments={},
    )
    policy = RuleEngine(
        (exact_rule(target),),
        derived_resolver=registry.derived_documents.get,
    )
    unknown = Dataflow.from_arguments(
        target.source,
        target.function,
        "derived-not-registered",
        target.destination,
        {},
    )

    assert isinstance(policy.evaluate(unknown), Deny)
    derived = register_materialization(
        registry,
        dataflow=producer,
        output={"rows": [{"value": 1}]},
    )
    proposal = Dataflow.from_arguments(
        target.source,
        target.function,
        derived.edoc_id,
        target.destination,
        {},
    )
    bob = Dataflow.from_arguments(
        target.source,
        target.function,
        derived.edoc_id,
        "aauth:bob@example",
        {},
    )

    assert policy.evaluate(proposal).rule == policy.list_rules()[0].rule
    assert isinstance(policy.evaluate(bob), Deny)
    assert producer in registry.materialized
    assert registry.derived_documents[derived.edoc_id] == derived
    assert derived.resource_uri == f"edoc://derived/{derived.edoc_id}"
    assert parse_stored_rule(serialize_rule(policy.list_rules()[0])) == (
        policy.list_rules()[0]
    )


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"rule_id": "", "target": {}, "prerequisite": None},
        {"rule_id": "x", "target": {}, "prerequisite": None},
    ],
)
def test_invalid_serialized_rules_are_rejected(value):
    with pytest.raises(ValueError):
        parse_stored_rule(value)


def test_concurrent_reads_and_writes_preserve_all_rules():
    policy = RuleEngine()

    def create(index: int):
        stored = policy.create_rule(exact_rule(_flow(index)), rule_id=f"rule-{index}")
        assert policy.evaluate(_flow(index)) == Allow(stored.rule_id, stored.rule)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(create, range(40)))

    assert len(policy.list_rules()) == 40
    assert {stored.rule_id for stored in policy.list_rules()} == {
        f"rule-{index}" for index in range(40)
    }
