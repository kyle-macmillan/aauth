"""Framework-neutral JSON representation of eDocs dataflows."""

from __future__ import annotations

from typing import Any

from .edocs import Dataflow, OutputOf


def serialize_document(document: str | OutputOf) -> str | dict[str, Any]:
    if isinstance(document, OutputOf):
        return {"output_of": serialize_dataflow(document.dataflow)}
    return document


def parse_document(value: object) -> str | OutputOf:
    if isinstance(value, dict) and set(value) == {"output_of"}:
        return OutputOf(parse_dataflow(value["output_of"]))
    if not isinstance(value, str) or not value:
        raise ValueError(
            "dataflow document must be an eDoc ID or output_of selector"
        )
    return value


def serialize_dataflow(dataflow: Dataflow) -> dict[str, Any]:
    return {
        "source": dataflow.source,
        "function": dataflow.function,
        "document": serialize_document(dataflow.document),
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
    document = parse_document(value["document"])
    if not isinstance(value["function_args"], dict):
        raise ValueError("dataflow function_args must be an object")
    return Dataflow.from_arguments(
        source=value["source"],
        function=value["function"],
        document=document,
        destination=value["destination"],
        arguments=value["function_args"],
    )
