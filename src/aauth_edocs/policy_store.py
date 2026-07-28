"""Thread-safe mutable exact-rule policy for eDocs controller ASes."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Callable
from uuid import uuid4

from .edocs import Dataflow, DerivedEdoc, ExactRule, OutputOf


@dataclass(frozen=True)
class StoredRule:
    rule_id: str
    rule: ExactRule

    @property
    def target(self) -> Dataflow:
        return self.rule.dataflow

    @property
    def prerequisite(self) -> Dataflow | None:
        return self.rule.prerequisite


class MutableControllerPolicy:
    """Mutable implementation of the controller policy evaluator boundary."""

    def __init__(
        self,
        rules: tuple[ExactRule, ...] = (),
        *,
        derived_resolver: Callable[[str], DerivedEdoc | None] | None = None,
    ) -> None:
        self._lock = RLock()
        self._rules: dict[str, StoredRule] = {}
        self._derived_resolver = derived_resolver or (lambda _edoc_id: None)
        for rule in rules:
            self.create_rule(rule.dataflow, rule.prerequisite)

    def list_rules(self) -> tuple[StoredRule, ...]:
        with self._lock:
            return tuple(self._rules.values())

    def create_rule(
        self,
        target: Dataflow,
        prerequisite: Dataflow | None = None,
        *,
        rule_id: str | None = None,
    ) -> StoredRule:
        self._validate_rule(target, prerequisite)
        stored = StoredRule(
            rule_id=rule_id or uuid4().hex,
            rule=ExactRule(target, prerequisite),
        )
        with self._lock:
            if not stored.rule_id:
                raise ValueError("rule_id must be non-empty")
            if stored.rule_id in self._rules:
                raise ValueError(f"duplicate rule ID: {stored.rule_id}")
            self._check_target_available(target)
            self._rules[stored.rule_id] = stored
        return stored

    def replace_rule(
        self,
        rule_id: str,
        target: Dataflow,
        prerequisite: Dataflow | None = None,
    ) -> StoredRule:
        self._validate_rule(target, prerequisite)
        with self._lock:
            if rule_id not in self._rules:
                raise KeyError(f"unknown rule ID: {rule_id}")
            self._check_target_available(target, excluding=rule_id)
            stored = StoredRule(rule_id, ExactRule(target, prerequisite))
            self._rules[rule_id] = stored
            return stored

    def delete_rule(self, rule_id: str) -> StoredRule:
        with self._lock:
            try:
                return self._rules.pop(rule_id)
            except KeyError as error:
                raise KeyError(f"unknown rule ID: {rule_id}") from error

    def evaluate(self, proposal: Dataflow) -> ExactRule | None:
        with self._lock:
            stored = next(
                (
                    stored
                    for stored in self._rules.values()
                    if self._matches(stored.rule, proposal)
                ),
                None,
            )
            return stored.rule if stored is not None else None

    def _matches(self, rule: ExactRule, proposal: Dataflow) -> bool:
        selector = rule.dataflow.document
        if not isinstance(selector, OutputOf):
            return rule.matches(proposal)
        if not isinstance(proposal.document, str):
            return False
        derived = self._derived_resolver(proposal.document)
        return (
            derived is not None
            and derived.producer == selector.producer
            and rule.dataflow.source == proposal.source
            and rule.dataflow.function == proposal.function
            and rule.dataflow.destination == proposal.destination
            and rule.dataflow.function_args_hash
            == proposal.function_args_hash
        )

    def _check_target_available(
        self,
        target: Dataflow,
        *,
        excluding: str | None = None,
    ) -> None:
        if any(
            stored.rule_id != excluding and stored.target == target
            for stored in self._rules.values()
        ):
            raise ValueError("controller policy cannot contain duplicate dataflow targets")

    @staticmethod
    def _validate_rule(
        target: Dataflow,
        prerequisite: Dataflow | None,
    ) -> None:
        if not isinstance(target, Dataflow):
            raise TypeError("target must be a Dataflow")
        if prerequisite is not None and not isinstance(prerequisite, Dataflow):
            raise TypeError("prerequisite must be a Dataflow")
