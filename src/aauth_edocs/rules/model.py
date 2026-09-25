"""Controller rules and the decisions a rule engine returns."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..edocs import Dataflow, OutputOf, canonicalize_function_args


@dataclass(frozen=True)
class ExactFunction:
    """Allow one function called with exactly these canonical arguments."""

    id: str
    canonical_arguments: str = "{}"

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("function ID must be a non-empty string")
        try:
            canonical = canonicalize_function_args(
                json.loads(self.canonical_arguments)
            ).decode("utf-8")
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as error:
            raise ValueError("canonical_arguments must be a canonical JSON object") from error
        if canonical != self.canonical_arguments:
            raise ValueError("canonical_arguments must use canonical JSON encoding")

    @classmethod
    def from_arguments(
        cls, id: str, arguments: Mapping[str, Any] | None = None
    ) -> ExactFunction:
        return cls(id, canonicalize_function_args(arguments).decode("utf-8"))

    @property
    def function_args(self) -> dict[str, Any]:
        return json.loads(self.canonical_arguments)

    def matches(self, proposal: Dataflow) -> bool:
        return (
            proposal.function == self.id
            and proposal.canonical_arguments == self.canonical_arguments
        )


@dataclass(frozen=True)
class Policy:
    """Allow any function call that a policy enforcer judges to satisfy ``text``."""

    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("policy text must be a non-empty string")


@dataclass(frozen=True)
class DataflowRule:
    """Allow a dataflow, optionally after an exact prerequisite has materialized."""

    source: str
    function: ExactFunction | Policy
    document: str | OutputOf
    destination: str
    prerequisite: Dataflow | None = None

    def __post_init__(self) -> None:
        for name in ("source", "destination"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"rule {name} must be a non-empty string")
        if not isinstance(self.function, (ExactFunction, Policy)):
            raise TypeError("rule function must be an ExactFunction or Policy")
        if not isinstance(self.document, OutputOf) and (
            not isinstance(self.document, str) or not self.document
        ):
            raise ValueError("rule document must be an eDoc ID or OutputOf selector")
        if self.prerequisite is not None and not isinstance(self.prerequisite, Dataflow):
            raise TypeError("prerequisite must be a Dataflow")

    @property
    def target(self) -> tuple[str, ExactFunction | Policy, str | OutputOf, str]:
        """The rule without its prerequisite; two rules may not share one."""
        return (self.source, self.function, self.document, self.destination)


def exact_rule(target: Dataflow, prerequisite: Dataflow | None = None) -> DataflowRule:
    """Build a rule allowing exactly ``target``."""
    return DataflowRule(
        source=target.source,
        function=ExactFunction(target.function, target.canonical_arguments),
        document=target.document,
        destination=target.destination,
        prerequisite=prerequisite,
    )


def policy_rule(
    *,
    source: str,
    policy: str,
    document: str | OutputOf,
    destination: str,
    prerequisite: Dataflow | None = None,
) -> DataflowRule:
    """Build a rule allowing any function call that satisfies ``policy``."""
    return DataflowRule(source, Policy(policy), document, destination, prerequisite)


@dataclass(frozen=True)
class StoredRule:
    rule_id: str
    rule: DataflowRule

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise ValueError("rule_id must be a non-empty string")
        if not isinstance(self.rule, DataflowRule):
            raise TypeError("rule must be a DataflowRule")


@dataclass(frozen=True)
class Allow:
    rule_id: str
    rule: DataflowRule
    reason: str | None = None


@dataclass(frozen=True)
class Deny:
    reason: str
    rule_ids: tuple[str, ...] = ()


RuleDecision = Allow | Deny
