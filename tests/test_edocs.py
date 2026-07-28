from dataclasses import FrozenInstanceError, fields

import pytest

from aauth_edocs import (
    MAX_FUNCTION_ARGS_BYTES,
    Dataflow,
    ExactRule,
    FunctionDescriptor,
    ResourceBinding,
    SentinelRegistry,
    canonicalize_function_args,
    hash_function_args,
    validate_function_args,
)


def _flow(**changes) -> Dataflow:
    values = {
        "source": "aauth:source@ap.example",
        "function": "identity@1",
        "document": "doc-123",
        "destination": "aauth:destination@ap.example",
    }
    values.update(changes)
    return Dataflow(**values)


def test_dataflow_is_an_immutable_exact_tuple():
    flow = _flow()

    assert flow == _flow()
    assert flow != _flow(document="doc-456")
    assert flow in {flow}
    with pytest.raises(FrozenInstanceError):
        flow.document = "doc-456"


def test_function_arguments_are_canonical_and_part_of_exact_dataflow():
    first = Dataflow.from_arguments("a", "f", "d", "b", {"z": 1, "nested": {"b": 2, "a": 1}})
    reordered = Dataflow.from_arguments("a", "f", "d", "b", {"nested": {"a": 1, "b": 2}, "z": 1})
    changed = Dataflow.from_arguments("a", "f", "d", "b", {"nested": {"a": 1, "b": 3}, "z": 1})

    assert first == reordered
    assert first.function_args == {"nested": {"a": 1, "b": 2}, "z": 1}
    assert first.function_args_hash == reordered.function_args_hash
    assert first != changed
    assert first.function_args_hash != changed.function_args_hash


def test_empty_function_arguments_are_supported():
    assert canonicalize_function_args() == b"{}"
    assert hash_function_args() == hash_function_args({})
    assert Dataflow("a", "f", "d", "b") == Dataflow.from_arguments("a", "f", "d", "b", {})


@pytest.mark.parametrize("arguments", [[], {"bad": float("nan")}, {"bad": object()}])
def test_non_json_function_arguments_are_rejected(arguments):
    with pytest.raises(ValueError, match="function arguments"):
        canonicalize_function_args(arguments)


def test_function_arguments_have_a_size_limit():
    with pytest.raises(ValueError, match="exceed"):
        canonicalize_function_args({"value": "x" * MAX_FUNCTION_ARGS_BYTES})


def test_function_descriptor_validates_arbitrary_json_object_schema():
    descriptor = FunctionDescriptor(
        id="search@1",
        description="Search text",
        implementation_uri="https://functions.example/search.py",
        digest="sha256:abc123",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    )

    validate_function_args(descriptor, {"query": "termination", "limit": 20})
    with pytest.raises(ValueError, match="input schema"):
        validate_function_args(descriptor, {"query": "termination", "limit": 0})


def test_exact_rule_matches_only_its_complete_dataflow():
    target = _flow()
    prerequisite = _flow(
        source="aauth:upstream@ap.example",
        function="prepare@1",
        document="doc-input",
    )
    unconditional = ExactRule(target)
    conditional = ExactRule(target, prerequisite)

    assert unconditional.matches(target)
    assert conditional.matches(target)
    assert conditional.prerequisite == prerequisite
    assert not conditional.matches(_flow(source="aauth:other@ap.example"))
    assert not conditional.matches(_flow(function="other@1"))
    assert not conditional.matches(_flow(document="doc-456"))
    assert not conditional.matches(_flow(destination="aauth:other@ap.example"))


def test_function_descriptor_is_immutable():
    descriptor = FunctionDescriptor(
        id="identity@1",
        description="Return the eDoc unchanged",
        implementation_uri="https://functions.example/identity.py",
        digest="sha256:abc123",
    )

    assert descriptor.id == "identity@1"
    with pytest.raises(FrozenInstanceError):
        descriptor.digest = "sha256:tampered"


def test_resource_binding_has_only_the_three_approved_fields():
    assert [item.name for item in fields(ResourceBinding)] == [
        "source_ps",
        "resource_issuer",
        "resource_jkt",
    ]

    binding = ResourceBinding(
        source_ps="https://source-ps.example",
        resource_issuer="https://resource.example",
        resource_jkt="resource-key-thumbprint",
    )
    with pytest.raises(FrozenInstanceError):
        binding.resource_jkt = "tampered"
    with pytest.raises(TypeError):
        ResourceBinding(
            source_agent="aauth:source@ap.example",
            source_ps=binding.source_ps,
            resource_issuer=binding.resource_issuer,
            resource_jkt=binding.resource_jkt,
        )


def test_sentinel_registry_holds_injected_authority_and_provenance_state():
    source = "aauth:source@ap.example"
    binding = ResourceBinding(
        source_ps="https://source-ps.example",
        resource_issuer="https://resource.example",
        resource_jkt="resource-key-thumbprint",
    )
    descriptor = FunctionDescriptor(
        id="identity@1",
        description="Return the eDoc unchanged",
        implementation_uri="https://functions.example/identity.py",
        digest="sha256:abc123",
    )
    flow = _flow()
    registry = SentinelRegistry(
        resource_bindings={source: binding},
        resource_owner_ases={"https://resource.example": "https://owner-as.example"},
        controllers={
            ("https://resource.example", "doc-123"): (
                "https://as-a.example",
                "https://as-b.example",
            )
        },
        functions={descriptor.id: descriptor},
        materialized={flow},
    )

    assert registry.resource_bindings[source] == binding
    assert registry.resource_owner_ases["https://resource.example"] == "https://owner-as.example"
    assert registry.controllers[("https://resource.example", "doc-123")] == (
        "https://as-a.example",
        "https://as-b.example",
    )
    assert registry.functions["identity@1"] == descriptor
    assert flow in registry.materialized


def test_sentinel_registry_defaults_are_not_shared():
    first = SentinelRegistry()
    second = SentinelRegistry()
