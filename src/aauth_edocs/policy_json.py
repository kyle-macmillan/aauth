"""Framework-neutral JSON representation of mutable eDocs policy rules."""

from __future__ import annotations

from typing import Any

from .edocs import Dataflow, ExactRule, OutputOf
from .policy_store import StoredRule


def serialize_dataflow(dataflow: Dataflow) -> dict[str, Any]:
    return {
        "source": dataflow.source,
        "function": dataflow.function,
        "document": (
            {"output_of": serialize_dataflow(dataflow.document.dataflow)}
            if isinstance(dataflow.document, OutputOf)
            else dataflow.document
        ),
        "destination": dataflow.destination,
        "function_args": dataflow.function_args,
    }


def parse_dataflow(value: object) -> Dataflow:
    if not isinstance(value, dict) or set(value) != {
        "source",
        "function",
        "document",
        "destination",
        "function_args",
    }:
        raise ValueError("dataflow must contain exact eDocs fields")
    for name in ("source", "function", "destination"):
        if not isinstance(value[name], str) or not value[name]:
            raise ValueError(f"dataflow {name} must be a non-empty string")
    document = value["document"]
    if isinstance(document, dict) and set(document) == {"output_of"}:
        document = OutputOf(parse_dataflow(document["output_of"]))
    elif not isinstance(document, str) or not document:
        raise ValueError(
            "dataflow document must be an eDoc ID or output_of selector"
        )
    if not isinstance(value["function_args"], dict):
        raise ValueError("dataflow function_args must be an object")
    return Dataflow.from_arguments(
        source=value["source"],
        function=value["function"],
        document=document,
        destination=value["destination"],
        arguments=value["function_args"],
    )


def serialize_rule(stored: StoredRule) -> dict[str, Any]:
    return {
        "rule_id": stored.rule_id,
        "target": serialize_dataflow(stored.target),
        "prerequisite": (
            serialize_dataflow(stored.prerequisite)
            if stored.prerequisite is not None
            else None
        ),
    }


def parse_rule(value: object) -> StoredRule:
    if not isinstance(value, dict) or set(value) != {
        "rule_id",
        "target",
        "prerequisite",
    }:
        raise ValueError("rule must contain rule_id, target, and prerequisite")
    rule_id = value["rule_id"]
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("rule_id must be a non-empty string")
    prerequisite = value["prerequisite"]
    return StoredRule(
        rule_id=rule_id,
        rule=ExactRule(
            parse_dataflow(value["target"]),
            parse_dataflow(prerequisite) if prerequisite is not None else None,
        ),
    )
