"""Intermediate eDocs token issuance for controller decisions."""

from __future__ import annotations

import time
from typing import Callable

from .edocs import Dataflow
from .errors import AAuthError, DENIED
from .ids import DWK_ACCESS
from .keys import SigningKey
from .rules import Allow, RuleEvaluator
from .tokens import issue_auth_token, issue_conditional_auth_token

Now = Callable[[], float]


def issue_controller_decision(
    *,
    proposal: Dataflow,
    rule_engine: RuleEvaluator,
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
    Denial reasons are not returned to the requester.
    """
    decision = rule_engine.evaluate(proposal)
    if not isinstance(decision, Allow):
        raise AAuthError(DENIED, 403, "no controller rule matches the proposed dataflow")

    common = {
        "issuer": issuer,
        "aud": sentinel,
        "agent": proposal.destination,
        "cnf_jwk": agent_jwk,
        "scope": proposal.function,
        "source_agent": proposal.source,
        "edoc_id": proposal.document,
        "controllers": controllers,
        "function_args_hash": proposal.function_args_hash,
        "key": key,
        "lifetime": lifetime,
        "now": now,
    }
    if decision.rule.prerequisite is not None:
        return issue_conditional_auth_token(
            **common,
            prerequisite=decision.rule.prerequisite,
        )
    return issue_auth_token(
        **common,
        dwk=DWK_ACCESS,
    )
