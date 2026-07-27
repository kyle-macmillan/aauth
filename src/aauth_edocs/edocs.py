"""Core domain models for the eDocs authorization extension.

The models in this module are deliberately independent of HTTP and token
handling. Services receive a ``SentinelRegistry`` from their caller, which
keeps the demo's in-memory state explicit and replaceable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Dataflow:
    """An exact eDocs operation: source, function, document, destination."""

    source: str
    function: str
    document: str
    destination: str


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
