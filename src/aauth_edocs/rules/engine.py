"""Thread-safe, default-deny rule engine for eDocs controllers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from threading import RLock
from typing import Any
from uuid import uuid4

from ..edocs import Dataflow, DerivedEdoc, FunctionDescriptor, OutputOf
from . import serialization
from .model import Allow, DataflowRule, Deny, ExactFunction, Policy, RuleDecision, StoredRule
from .policy import (
    CachingEnforcer,
    FailClosedEnforcer,
    FunctionSource,
    PolicyEnforcer,
    PolicyQuestion,
    PolicyVerdict,
    source_digest,
)

NO_MATCH = "no controller rule matches the proposed dataflow"


class RuleEngine:
    """Stores controller rules and evaluates proposals against them.

    Exact-function rules are checked first. Policy rules are then offered to
    the enforcer in creation order, and the first one it allows wins. The
    enforcer only ever sees function source whose digest matches the
    function's trusted registration.
    """

    def __init__(
        self,
        rules: Iterable[DataflowRule] = (),
        *,
        derived_resolver: Callable[[str], DerivedEdoc | None] | None = None,
        function_resolver: Callable[[str], FunctionDescriptor | None] | None = None,
        source_resolver: Callable[[str], FunctionSource | None] | None = None,
        enforcer: PolicyEnforcer | None = None,
    ) -> None:
        self._lock = RLock()
        self._rules: dict[str, StoredRule] = {}
        self._derived_resolver = derived_resolver or (lambda _edoc_id: None)
        self._function_resolver = function_resolver or (lambda _function_id: None)
        self._source_resolver = source_resolver or (lambda _function_id: None)
        self._enforcer = (
            FailClosedEnforcer(CachingEnforcer(enforcer)) if enforcer is not None else None
        )
        for rule in rules:
            self.create_rule(rule)

    # Storage

    def list_rules(self) -> tuple[StoredRule, ...]:
        with self._lock:
            return tuple(self._rules.values())

    def get_rule(self, rule_id: str) -> StoredRule:
        with self._lock:
            try:
                return self._rules[rule_id]
            except KeyError as error:
                raise KeyError(f"unknown rule ID: {rule_id}") from error

    def create_rule(self, rule: DataflowRule, *, rule_id: str | None = None) -> StoredRule:
        self._validate_rule(rule)
        stored = StoredRule(rule_id if rule_id is not None else uuid4().hex, rule)
        with self._lock:
            if stored.rule_id in self._rules:
                raise ValueError(f"duplicate rule ID: {stored.rule_id}")
            self._check_target_available(rule)
            self._rules[stored.rule_id] = stored
        return stored

    def replace_rule(self, rule_id: str, rule: DataflowRule) -> StoredRule:
        self._validate_rule(rule)
        with self._lock:
            if rule_id not in self._rules:
                raise KeyError(f"unknown rule ID: {rule_id}")
            self._check_target_available(rule, excluding=rule_id)
            stored = StoredRule(rule_id, rule)
            self._rules[rule_id] = stored
            return stored

    def delete_rule(self, rule_id: str) -> StoredRule:
        with self._lock:
            try:
                return self._rules.pop(rule_id)
            except KeyError as error:
                raise KeyError(f"unknown rule ID: {rule_id}") from error

    # JSON format

    def parse_rule(self, body: object) -> DataflowRule:
        return serialization.parse_rule(body)

    def serialize_rule(self, stored: StoredRule) -> dict[str, Any]:
        return serialization.serialize_rule(stored)

    def reads(self, stored: StoredRule, edoc_id: str) -> bool:
        """Whether the rule's target reads ``edoc_id``, directly or via ``output_of``."""
        return _reads(stored.rule.document, edoc_id)

    # Evaluation

    def evaluate(self, proposal: Dataflow) -> RuleDecision:
        with self._lock:
            candidates = tuple(self._rules.values())
        candidates = tuple(
            stored for stored in candidates if self._matches_flow(stored.rule, proposal)
        )
        for stored in candidates:
            function = stored.rule.function
            if isinstance(function, ExactFunction) and function.matches(proposal):
                return Allow(stored.rule_id, stored.rule)

        considered: list[str] = []
        for stored in candidates:
            if not isinstance(stored.rule.function, Policy):
                continue
            considered.append(stored.rule_id)
            verdict = self._judge(stored.rule.function, proposal)
            if verdict.allowed:
                return Allow(stored.rule_id, stored.rule, verdict.reason)
        return Deny(NO_MATCH, tuple(considered))

    def _judge(self, policy: Policy, proposal: Dataflow) -> PolicyVerdict:
        if self._enforcer is None:
            return PolicyVerdict(False, "no policy enforcer is configured")
        descriptor = self._function_resolver(proposal.function)
        if descriptor is None:
            return PolicyVerdict(False, "function is not registered")
        function = self._source_resolver(proposal.function)
        if function is None:
            return PolicyVerdict(False, "function source is unavailable")
        if source_digest(function.source) != descriptor.digest:
            return PolicyVerdict(False, "function source does not match its registered digest")
        return self._enforcer.judge(
            PolicyQuestion(policy.text, proposal, proposal.function, function)
        )

    def _matches_flow(self, rule: DataflowRule, proposal: Dataflow) -> bool:
        """Match everything but the function; those fields are never judged by the enforcer."""
        if rule.source != proposal.source or rule.destination != proposal.destination:
            return False
        selector = rule.document
        if not isinstance(selector, OutputOf):
            return selector == proposal.document
        if not isinstance(proposal.document, str):
            return False
        derived = self._derived_resolver(proposal.document)
        return derived is not None and derived.dataflow == selector.dataflow

    def _check_target_available(
        self,
        rule: DataflowRule,
        *,
        excluding: str | None = None,
    ) -> None:
        if any(
            stored.rule_id != excluding and stored.rule.target == rule.target
            for stored in self._rules.values()
        ):
            raise ValueError("controller rules cannot contain duplicate dataflow targets")

    def _validate_rule(self, rule: DataflowRule) -> None:
        if not isinstance(rule, DataflowRule):
            raise TypeError("rule must be a DataflowRule")
        if isinstance(rule.function, Policy) and self._enforcer is None:
            raise ValueError("policy rules require a rule engine with a policy enforcer")


def _reads(document: str | OutputOf, edoc_id: str) -> bool:
    if isinstance(document, OutputOf):
        return _reads(document.dataflow.document, edoc_id)
    return document == edoc_id
