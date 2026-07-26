"""Controller policy evaluation and intermediate eDocs token issuance."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .edocs import Dataflow, ExactRule
from .errors import AAuthError, DENIED
from .ids import DWK_ACCESS
from .keys import SigningKey
from .tokens import issue_auth_token, issue_conditional_auth_token

Now = Callable[[], float]


@dataclass(frozen=True)
class ControllerPolicy:
    """One controller's exact-match, default-deny policy."""

    rules: tuple[ExactRule, ...]

    def __post_init__(self) -> None:
        targets = [rule.dataflow for rule in self.rules]
        if len(set(targets)) != len(targets):
            raise ValueError("controller policy cannot contain duplicate dataflow targets")

    def evaluate(self, proposal: Dataflow) -> ExactRule | None:
        """Return the exact matching rule, or ``None`` for denial."""
        return next((rule for rule in self.rules if rule.matches(proposal)), None)


def issue_controller_decision(
    *,
    proposal: Dataflow,
    policy: ControllerPolicy,
    issuer: str,
    sentinel: str,
    agent_jwk: dict,
    controllers: list[str] | tuple[str, ...],
    key: SigningKey,
    lifetime: int = 3600,
    now: Now = time.time,
) -> str:
    """Issue one controller's intermediate decision to the Sentinel.

    The caller is responsible for constructing ``proposal`` from verified
    agent and resource tokens. Provenance is deliberately not an input.
    """
    rule = policy.evaluate(proposal)
    if rule is None:
        raise AAuthError(DENIED, 403, "no controller policy matches the proposed dataflow")

    common = {
        "issuer": issuer,
        "aud": sentinel,
        "agent": proposal.destination,
        "cnf_jwk": agent_jwk,
        "scope": proposal.function,
        "source_agent": proposal.source,
        "edoc_id": proposal.document,
        "controllers": controllers,
        "key": key,
        "lifetime": lifetime,
        "now": now,
    }
    if rule.prerequisite is not None:
        return issue_conditional_auth_token(
            **common,
            prerequisite=rule.prerequisite,
        )
    return issue_auth_token(
        **common,
        dwk=DWK_ACCESS,
    )
