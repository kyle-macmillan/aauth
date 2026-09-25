"""JSON representation of controller rules.

A rule target carries exactly one of ``function`` (with ``function_args``)
or ``policy``. Exact targets have the same shape as a serialized dataflow.
"""

from __future__ import annotations

from typing import Any

from ..dataflow_json import parse_dataflow, parse_document, serialize_dataflow, serialize_document
from .model import DataflowRule, ExactFunction, Policy, StoredRule

_EXACT_TARGET_FIELDS = {"source", "function", "document", "destination", "function_args"}
_POLICY_TARGET_FIELDS = {"source", "policy", "document", "destination"}


def serialize_target(rule: DataflowRule) -> dict[str, Any]:
    value: dict[str, Any] = {"source": rule.source}
    if isinstance(rule.function, ExactFunction):
        value["function"] = rule.function.id
    else:
        value["policy"] = rule.function.text
    value["document"] = serialize_document(rule.document)
    value["destination"] = rule.destination
    if isinstance(rule.function, ExactFunction):
        value["function_args"] = rule.function.function_args
    return value


def parse_target(value: object, prerequisite: object = None) -> DataflowRule:
    if not isinstance(value, dict) or set(value) not in (
        _EXACT_TARGET_FIELDS,
        _POLICY_TARGET_FIELDS,
    ):
        raise ValueError(
            "rule target must contain source, document, destination, and "
            "either function with function_args or policy"
        )
    for name in ("source", "destination"):
        if not isinstance(value[name], str) or not value[name]:
            raise ValueError(f"rule target {name} must be a non-empty string")
    if "policy" in value:
        if not isinstance(value["policy"], str):
            raise ValueError("rule target policy must be a string")
        function: ExactFunction | Policy = Policy(value["policy"])
    else:
        if not isinstance(value["function"], str) or not value["function"]:
            raise ValueError("rule target function must be a non-empty string")
        if not isinstance(value["function_args"], dict):
            raise ValueError("rule target function_args must be an object")
        function = ExactFunction.from_arguments(value["function"], value["function_args"])
    return DataflowRule(
        source=value["source"],
        function=function,
        document=parse_document(value["document"]),
        destination=value["destination"],
        prerequisite=parse_dataflow(prerequisite) if prerequisite is not None else None,
    )


def parse_rule(value: object) -> DataflowRule:
    """Parse a create/replace body: ``{"target": ..., "prerequisite": ... | null}``."""
    if not isinstance(value, dict) or "target" not in value or set(value) - {
        "target",
        "prerequisite",
    }:
        raise ValueError("rule requires target and optional prerequisite")
    return parse_target(value["target"], value.get("prerequisite"))


def serialize_rule(stored: StoredRule) -> dict[str, Any]:
    prerequisite = stored.rule.prerequisite
    return {
        "rule_id": stored.rule_id,
        "target": serialize_target(stored.rule),
        "prerequisite": serialize_dataflow(prerequisite) if prerequisite is not None else None,
    }


def parse_stored_rule(value: object) -> StoredRule:
    if not isinstance(value, dict) or set(value) != {
        "rule_id",
        "target",
        "prerequisite",
    }:
        raise ValueError("rule must contain rule_id, target, and prerequisite")
    rule_id = value["rule_id"]
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("rule_id must be a non-empty string")
    return StoredRule(rule_id, parse_target(value["target"], value["prerequisite"]))
