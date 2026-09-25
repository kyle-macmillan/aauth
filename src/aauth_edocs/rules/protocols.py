"""The boundary between a server and whatever rule engine it hosts.

A server needs only ``RuleEvaluator`` to make decisions. It exposes rule
management only when the engine also implements ``RuleAdmin``; deciding who
may manage rules stays with the server.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..edocs import Dataflow
from .model import RuleDecision, StoredRule


class RuleEvaluator(Protocol):
    """Not optional in this context; it's the only way to make decisions."""
    def evaluate(self, proposal: Dataflow) -> RuleDecision: ...


@runtime_checkable
class RuleAdmin(Protocol):
    """Rule storage and modification, including the engine's own JSON format.
    Optional in this context; only used for rule management if a list of rules
    is required."""

    def list_rules(self) -> tuple[StoredRule, ...]: ...

    def get_rule(self, rule_id: str) -> StoredRule: ...

    def create_rule(self, rule: Any, *, rule_id: str | None = None) -> StoredRule: ...

    def replace_rule(self, rule_id: str, rule: Any) -> StoredRule: ...

    def delete_rule(self, rule_id: str) -> StoredRule: ...

    def parse_rule(self, body: object) -> Any: ...

    def serialize_rule(self, stored: StoredRule) -> dict[str, Any]: ...

    def reads(self, stored: StoredRule, edoc_id: str) -> bool: ...
