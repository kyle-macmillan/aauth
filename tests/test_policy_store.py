from concurrent.futures import ThreadPoolExecutor

import pytest

from aauth_edocs import (
    ControllerPolicy,
    Dataflow,
    ExactRule,
    MutableControllerPolicy,
    OutputOf,
    SentinelRegistry,
    parse_rule,
    register_materialization,
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


def test_mutable_policy_matches_immutable_exact_decisions():
    target = _flow()
    changed = _flow(arguments={"limit": 100})
    immutable = ControllerPolicy((ExactRule(target),))
    mutable = MutableControllerPolicy((ExactRule(target),))

    assert mutable.evaluate(target) == immutable.evaluate(target)
    assert mutable.evaluate(changed) == immutable.evaluate(changed) is None


def test_create_replace_and_delete_preserve_stable_rule_id():
    policy = MutableControllerPolicy()
    original = policy.create_rule(_flow(), rule_id="rule-1")

    assert policy.evaluate(original.target) == original.rule
    replacement = policy.replace_rule("rule-1", _flow(1))

    assert replacement.rule_id == "rule-1"
    assert policy.evaluate(original.target) is None
    assert policy.evaluate(replacement.target) == replacement.rule
    assert policy.delete_rule("rule-1") == replacement
    assert policy.evaluate(replacement.target) is None
    with pytest.raises(KeyError, match="unknown rule ID"):
        policy.delete_rule("rule-1")


def test_duplicate_targets_and_rule_ids_are_rejected():
    policy = MutableControllerPolicy()
    policy.create_rule(_flow(), rule_id="first")

    with pytest.raises(ValueError, match="duplicate dataflow"):
        policy.create_rule(_flow(), rule_id="second")
    with pytest.raises(ValueError, match="duplicate rule ID"):
        policy.create_rule(_flow(1), rule_id="first")


def test_conditional_rule_and_json_round_trip_preserve_semantics():
    target = _flow()
    prerequisite = _flow(
        1,
        function="prepare@1",
        arguments={"format": "parquet"},
    )
    policy = MutableControllerPolicy()
    stored = policy.create_rule(
        target,
        prerequisite,
        rule_id="conditional-1",
    )

    decoded = parse_rule(serialize_rule(stored))

    assert decoded == stored
    assert policy.evaluate(target).prerequisite == prerequisite


def test_future_output_rule_matches_only_after_trusted_materialization():
    producer = _flow()
    registry = SentinelRegistry()
    target = Dataflow.from_arguments(
        source=producer.destination,
        function="identity@1",
        document=OutputOf(producer),
        destination="aauth:carol@example",
        arguments={},
    )
    policy = MutableControllerPolicy(
        (ExactRule(target),),
        derived_resolver=registry.derived_documents.get,
    )
    unknown = Dataflow.from_arguments(
        target.source,
        target.function,
        "derived-not-registered",
        target.destination,
        {},
    )

    assert policy.evaluate(unknown) is None
    derived = register_materialization(
        registry,
        producer=producer,
        output={"rows": [{"value": 1}]},
        controllers=("https://alice-as.example",),
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

    assert policy.evaluate(proposal) == policy.list_rules()[0].rule
    assert policy.evaluate(bob) is None
    assert producer in registry.materialized
    assert registry.derived_documents[derived.edoc_id] == derived
    assert derived.resource_uri == f"edoc://derived/{derived.edoc_id}"
    assert parse_rule(serialize_rule(policy.list_rules()[0])) == (
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
        parse_rule(value)


def test_concurrent_reads_and_writes_preserve_all_rules():
    policy = MutableControllerPolicy()

    def create(index: int):
        stored = policy.create_rule(_flow(index), rule_id=f"rule-{index}")
        assert policy.evaluate(stored.target) == stored.rule

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(create, range(40)))

    assert len(policy.list_rules()) == 40
    assert {stored.rule_id for stored in policy.list_rules()} == {
        f"rule-{index}" for index in range(40)
    }
