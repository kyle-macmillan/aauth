"""Core domain models for the eDocs authorization extension.

The models in this module are deliberately independent of HTTP and token
handling. Services receive a ``SentinelRegistry`` from their caller, which
keeps the demo's in-memory state explicit and replaceable.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

MAX_FUNCTION_ARGS_BYTES = 16 * 1024
_FUNCTION_ARGS_DOMAIN = b"aauth-edocs-function-args-v1\0"


def canonicalize_function_args(arguments: Mapping[str, Any] | None = None) -> bytes:
    """Return the deterministic JSON representation of one MCP argument object."""
    value = {} if arguments is None else arguments
    if not isinstance(value, Mapping):
        raise ValueError("function arguments must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError("function argument keys must be strings")
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("function arguments must contain only finite JSON values") from error
    if len(encoded) > MAX_FUNCTION_ARGS_BYTES:
        raise ValueError(
            f"canonical function arguments exceed {MAX_FUNCTION_ARGS_BYTES} bytes"
        )
    return encoded


def hash_function_args(arguments: Mapping[str, Any] | None = None) -> str:
    """Return the versioned digest bound into eDocs authorization tokens."""
    digest = hashlib.sha256(
        _FUNCTION_ARGS_DOMAIN + canonicalize_function_args(arguments)
    ).hexdigest()
    return f"sha256:{digest}"


EMPTY_FUNCTION_ARGS_HASH = hash_function_args()


@dataclass(frozen=True)
class Dataflow:
    """An exact eDocs operation, including its canonical argument object."""

    source: str
    function: str
    document: str | OutputOf
    destination: str
    canonical_arguments: str = "{}"

    def __post_init__(self) -> None:
        try:
            decoded = json.loads(self.canonical_arguments)
            canonical = canonicalize_function_args(decoded).decode("utf-8")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            raise ValueError("canonical_arguments must be a canonical JSON object") from error
        if canonical != self.canonical_arguments:
            raise ValueError("canonical_arguments must use canonical JSON encoding")

    @classmethod
    def from_arguments(
        cls,
        source: str,
        function: str,
        document: str | OutputOf,
        destination: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> Dataflow:
        return cls(
            source,
            function,
            document,
            destination,
            canonicalize_function_args(arguments).decode("utf-8"),
        )

    @property
    def function_args(self) -> dict[str, Any]:
        return json.loads(self.canonical_arguments)

    @property
    def function_args_hash(self) -> str:
        return hash_function_args(self.function_args)


@dataclass(frozen=True)
class OutputOf:
    """Select any derived eDoc produced by one exact future dataflow."""

    producer: Dataflow

    def __post_init__(self) -> None:
        if not isinstance(self.producer.document, str):
            raise ValueError("output producer must reference a concrete eDoc")

    @property
    def fingerprint(self) -> str:
        value = {
            "source": self.producer.source,
            "function": self.producer.function,
            "document": self.producer.document,
            "destination": self.producer.destination,
            "function_args_hash": self.producer.function_args_hash,
        }
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True)
class DerivedEdoc:
    """Trusted provenance metadata for one materialized function output."""

    edoc_id: str
    producer: Dataflow
    output_digest: str
    custodian: str
    controllers: tuple[str, ...]

    @property
    def resource_uri(self) -> str:
        return f"edoc://derived/{self.edoc_id}"

    @property
    def producer_fingerprint(self) -> str:
        return OutputOf(self.producer).fingerprint


@dataclass(frozen=True, eq=False)
class DataflowBinding:
    """Token-safe identity of a dataflow whose full arguments are not repeated."""

    source: str
    function: str
    document: str
    destination: str
    function_args_hash: str = EMPTY_FUNCTION_ARGS_HASH

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Dataflow):
            return self.matches(other)
        if isinstance(other, DataflowBinding):
            return (
                self.source,
                self.function,
                self.document,
                self.destination,
                self.function_args_hash,
            ) == (
                other.source,
                other.function,
                other.document,
                other.destination,
                other.function_args_hash,
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash(
            (
                self.source,
                self.function,
                self.document,
                self.destination,
                self.function_args_hash,
            )
        )

    def matches(self, dataflow: Dataflow) -> bool:
        return (
            self.source == dataflow.source
            and self.function == dataflow.function
            and self.document == dataflow.document
            and self.destination == dataflow.destination
            and self.function_args_hash == dataflow.function_args_hash
        )


@dataclass(frozen=True)
class ExactRule:
    """Allow one exact dataflow, optionally after another has materialized."""

    dataflow: Dataflow
    prerequisite: Dataflow | None = None

    def matches(self, proposal: Dataflow) -> bool:
        """Return whether *proposal* is the rule's exact target."""
        return proposal == self.dataflow


@dataclass(frozen=True)
class FunctionDescriptor:
    """Immutable identity and implementation metadata for a function."""

    id: str
    description: str
    implementation_uri: str
    digest: str
    input_schema: dict[str, Any] = field(
        default_factory=lambda: {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
    )

@dataclass(frozen=True)
class ResourceBinding:
    """PS attestation binding a source to a resource key.

    The source agent is the key in ``SentinelRegistry.resource_bindings``.
    Keeping it out of this value avoids two representations of the same
    identity that could disagree.
    """

    source_ps: str
    resource_issuer: str
    resource_jkt: str


@dataclass
class SentinelRegistry:
    """Injected in-memory authority and provenance state for the demo."""

    resource_bindings: dict[str, ResourceBinding] = field(default_factory=dict)
    resource_owner_ases: dict[str, str] = field(default_factory=dict)
    controllers: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    functions: dict[str, FunctionDescriptor] = field(default_factory=dict)
    materialized: set[Dataflow] = field(default_factory=set)
    derived_documents: dict[str, DerivedEdoc] = field(default_factory=dict)


def register_materialization(
    registry: SentinelRegistry,
    *,
    producer: Dataflow,
    output: Any,
    controllers: tuple[str, ...],
) -> DerivedEdoc:
    """Record a successful execution and mint its opaque derived eDoc ID."""
    encoded = json.dumps(
        output,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    derived = DerivedEdoc(
        edoc_id=f"derived_{uuid4().hex}",
        producer=producer,
        output_digest=f"sha256:{hashlib.sha256(encoded).hexdigest()}",
        custodian=producer.destination,
        controllers=controllers,
    )
    registry.materialized.add(producer)
    registry.derived_documents[derived.edoc_id] = derived
    return derived
