"""In-process Sentinel aggregation for the eDocs demo."""

from __future__ import annotations

import time
from typing import Callable

from .edocs import Dataflow, SentinelRegistry
from .errors import AAuthError, DENIED
from .httpsig import KeyResolver, peek_jwt
from .ids import DWK_ACCESS
from .keys import SigningKey
from .tokens import (
    AUTH_TYP,
    CONDITIONAL_AUTH_TYP,
    issue_auth_token,
    verify_auth_token,
    verify_conditional_auth_token,
)

Now = Callable[[], float]


def aggregate_controller_decisions(
    *,
    proposal: Dataflow,
    resource_issuer: str,
    advisory_controllers: list[str] | tuple[str, ...],
    responses: dict[str, str],
    agent_jwk: dict,
    registry: SentinelRegistry,
    sentinel_issuer: str,
    sentinel_key: SigningKey,
    key_resolver: KeyResolver,
    lifetime: int = 3600,
    now: Now = time.time,
) -> str:
    """Require unanimous controller approval and issue one final auth token.

    ``responses`` is keyed by the authoritative controller URL contacted by
    the caller. HTTP transport and initial agent/resource verification happen
    outside this aggregation boundary.
    """
    controllers = registry.controllers.get(proposal.document)
    if not controllers:
        _deny("no authoritative controllers registered for the eDoc")
    if len(set(controllers)) != len(controllers):
        _deny("authoritative controller registry contains duplicates")
    if set(responses) != set(controllers):
        _deny("controller responses do not exactly match the authoritative controller set")

    for controller in controllers:
        token = responses[controller]
        try:
            header, _ = peek_jwt(token)
            typ = header.get("typ")
            if typ == AUTH_TYP:
                claims = verify_auth_token(
                    token,
                    key_resolver,
                    aud=sentinel_issuer,
                    signing_jwk=agent_jwk,
                    source_agent=proposal.source,
                    scope=proposal.function,
                    edoc_id=proposal.document,
                    controllers=advisory_controllers,
                    now=now,
                )
                if claims.get("iss") != controller:
                    raise AAuthError(DENIED, 403, "controller token issuer mismatch")
                if claims.get("agent") != proposal.destination:
                    raise AAuthError(DENIED, 403, "controller token agent mismatch")
            elif typ == CONDITIONAL_AUTH_TYP:
                prerequisite = verify_conditional_auth_token(
                    token,
                    key_resolver,
                    issuer=controller,
                    aud=sentinel_issuer,
                    agent=proposal.destination,
                    signing_jwk=agent_jwk,
                    source_agent=proposal.source,
                    scope=proposal.function,
                    edoc_id=proposal.document,
                    controllers=advisory_controllers,
                    now=now,
                )
                if prerequisite not in registry.materialized:
                    raise AAuthError(DENIED, 403, "controller prerequisite has not materialized")
            else:
                raise AAuthError(DENIED, 403, f"unsupported controller token type {typ!r}")
        except AAuthError as error:
            _deny(f"controller {controller} did not approve: {error}")

    token = issue_auth_token(
        issuer=sentinel_issuer,
        dwk=DWK_ACCESS,
        aud=resource_issuer,
        agent=proposal.destination,
        cnf_jwk=agent_jwk,
        scope=proposal.function,
        source_agent=proposal.source,
        edoc_id=proposal.document,
        controllers=controllers,
        key=sentinel_key,
        lifetime=lifetime,
        now=now,
    )
    registry.materialized.add(proposal)
    return token


def _deny(detail: str) -> None:
    raise AAuthError(DENIED, 403, detail)
