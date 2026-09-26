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

    dataflow: Dataflow

    def __post_init__(self) -> None:
        if not isinstance(self.dataflow.document, str):
            raise ValueError("output dataflow must reference a concrete eDoc")

    @property
    def fingerprint(self) -> str:
        value = {
            "source": self.dataflow.source,
            "function": self.dataflow.function,
            "document": self.dataflow.document,
            "destination": self.dataflow.destination,
            "function_args_hash": self.dataflow.function_args_hash,
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
    dataflow: Dataflow
    output_digest: str
    possessor: str
    controllers: tuple[str, ...]

    @property
    def resource_uri(self) -> str:
        return f"edoc://derived/{self.edoc_id}"

    @property
    def dataflow_fingerprint(self) -> str:
        return OutputOf(self.dataflow).fingerprint


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
    controllers: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    functions: dict[str, FunctionDescriptor] = field(default_factory=dict)
    materialized: set[Dataflow] = field(default_factory=set)
    derived_documents: dict[str, DerivedEdoc] = field(default_factory=dict)
    derived_outputs: dict[str, Any] = field(default_factory=dict)
    published_derived: set[str] = field(default_factory=set)


def controller_set(controllers: Any) -> tuple[str, ...]:
    """Validate a controller list: non-empty, distinct, non-empty strings."""
    if (
        isinstance(controllers, str)
        or not isinstance(controllers, (list, tuple))
        or not controllers
        or any(not isinstance(item, str) or not item for item in controllers)
    ):
        raise ValueError("controllers must be a non-empty string list")
    value = tuple(controllers)
    if len(set(value)) != len(value):
        raise ValueError("controllers must not contain duplicates")
    return value


def register_origin(
    registry: SentinelRegistry,
    *,
    resource_issuer: str,
    edoc_id: str,
    controllers: Any,
) -> tuple[str, ...]:
    """Register an eDoc with no provenance and the controllers its registrant names."""
    if not isinstance(resource_issuer, str) or not resource_issuer:
        raise ValueError("resource_issuer must be a non-empty string")
    if not isinstance(edoc_id, str) or not edoc_id:
        raise ValueError("edoc_id must be a non-empty string")
    if edoc_id in registry.derived_documents:
        raise ValueError("derived eDocs inherit their controllers and are not origins")
    value = controller_set(controllers)
    key = (resource_issuer, edoc_id)
    existing = registry.controllers.get(key)
    if existing is not None and existing != value:
        raise ValueError("controllers already registered for this eDoc with a different set")
    registry.controllers[key] = value
    return value


def controllers_for(
    registry: SentinelRegistry,
    resource_issuer: str | None,
    edoc_id: str,
) -> tuple[str, ...] | None:
    """Return an eDoc's authoritative controllers, or None if it is not an eDoc."""
    derived = registry.derived_documents.get(edoc_id)
    if derived is not None:
        return derived.controllers
    if resource_issuer is None:
        return None
    return registry.controllers.get((resource_issuer, edoc_id))


def register_materialization(
    registry: SentinelRegistry,
    *,
    dataflow: Dataflow,
    output: Any,
) -> DerivedEdoc:
    """Record a successful execution and mint its opaque derived eDoc ID.

    The derived eDoc inherits the controllers of the eDoc it was computed from.
    """
    if not isinstance(dataflow.document, str):
        raise ValueError("materialized dataflow must reference a concrete eDoc")
    binding = registry.resource_bindings.get(dataflow.source)
    controllers = controllers_for(
        registry,
        binding.resource_issuer if binding is not None else None,
        dataflow.document,
    )
    if controllers is None:
        raise ValueError(f"input eDoc has no registered controllers: {dataflow.document}")
    encoded = json.dumps(
        output,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    derived = DerivedEdoc(
        edoc_id=f"derived_{uuid4().hex}",
        dataflow=dataflow,
        output_digest=f"sha256:{hashlib.sha256(encoded).hexdigest()}",
        possessor=dataflow.destination,
        controllers=controllers,
    )
    registry.materialized.add(dataflow)
    registry.derived_documents[derived.edoc_id] = derived
    registry.derived_outputs[derived.edoc_id] = output
    return derived
