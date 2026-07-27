"""Trusted host-side consent handling for the eDocs AAuth extension."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from .coordinator import ApprovalRequired
from .errors import AAuthError, INVALID_REQUEST, INVALID_TOKEN


@dataclass(frozen=True)
class EdocsApprovalRequest:
    """PS-verified eDocs facts suitable for a trusted host approval prompt."""

    source_agent: str
    function_id: str
    edoc_id: str
    destination_agent: str
    controllers: tuple[str, ...]
    resource: str
    authorization_audience: str
    approval_url: str


class EdocsConsentClient:
    """Review and decide eDocs approvals through a person-authenticated client.

    The supplied transport represents the human-facing authenticated Person
    Server session. It is intentionally distinct from the agent transport used
    by :class:`AuthorizationCoordinator`.
    """

    def __init__(self, transport) -> None:
        self.transport = transport

    def review(self, approval: ApprovalRequired) -> EdocsApprovalRequest:
        response = self.transport.get(self._approval_url(approval))
        return self._parse_review(response, approval)

    async def review_async(
        self,
        approval: ApprovalRequired,
    ) -> EdocsApprovalRequest:
        response = await self._get_async(self._approval_url(approval))
        return self._parse_review(response, approval)

    def decide(
        self,
        approval: ApprovalRequired,
        decision: Literal["grant", "deny"],
    ) -> None:
        self._validate_decision(decision)
        response = self.transport.request(
            "POST",
            self._approval_url(approval),
            json={"decision": decision},
        )
        self._check_decision_response(response)

    async def decide_async(
        self,
        approval: ApprovalRequired,
        decision: Literal["grant", "deny"],
    ) -> None:
        self._validate_decision(decision)
        response = await self._request_async(
            "POST",
            self._approval_url(approval),
            json={"decision": decision},
        )
        self._check_decision_response(response)

    @staticmethod
    def _approval_url(approval: ApprovalRequired) -> str:
        if not approval.approval_url:
            raise AAuthError(
                INVALID_REQUEST,
                400,
                "approval event has no Person Server approval URL",
            )
        return approval.approval_url

    @staticmethod
    def _validate_decision(decision: str) -> None:
        if decision not in ("grant", "deny"):
            raise AAuthError(
                INVALID_REQUEST,
                400,
                "eDocs consent decision must be grant or deny",
            )

    @staticmethod
    def _check_decision_response(response) -> None:
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        body = response.json()
        if not isinstance(body, dict) or body.get("status") != "recorded":
            raise AAuthError(
                INVALID_TOKEN,
                502,
                "Person Server did not confirm the consent decision",
            )

    @staticmethod
    def _parse_review(
        response,
        approval: ApprovalRequired,
    ) -> EdocsApprovalRequest:
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("claims"), dict):
            raise AAuthError(
                INVALID_TOKEN,
                detail="Person Server returned a malformed consent review",
            )
        claims = body["claims"]
        expected = {
            "agent": claims.get("agent"),
            "resource": claims.get("iss"),
            "audience": claims.get("aud"),
            "scope": claims.get("scope"),
        }
        for name, value in expected.items():
            if body.get(name) != value:
                raise AAuthError(
                    INVALID_TOKEN,
                    detail=f"consent review {name} does not match verified claims",
                )

        fields = {
            "source_agent": claims.get("source_agent"),
            "function_id": claims.get("scope"),
            "edoc_id": claims.get("edoc_id"),
            "destination_agent": claims.get("agent"),
            "resource": claims.get("iss"),
            "authorization_audience": claims.get("aud"),
        }
        if any(not isinstance(value, str) or not value for value in fields.values()):
            raise AAuthError(
                INVALID_TOKEN,
                detail="consent review is missing required eDocs claims",
            )
        controllers = claims.get("controllers")
        if (
            not isinstance(controllers, list)
            or any(not isinstance(value, str) or not value for value in controllers)
            or len(set(controllers)) != len(controllers)
        ):
            raise AAuthError(
                INVALID_TOKEN,
                detail="consent review has invalid eDocs controllers",
            )

        return EdocsApprovalRequest(
            **fields,
            controllers=tuple(controllers),
            approval_url=EdocsConsentClient._approval_url(approval),
        )

    async def _get_async(self, url: str):
        method = getattr(self.transport, "get_async", None)
        if method is None:
            return self.transport.get(url)
        result = method(url)
        return await result if inspect.isawaitable(result) else result

    async def _request_async(self, method: str, url: str, **kwargs):
        request = getattr(self.transport, "request_async", None)
        if request is None:
            return self.transport.request(method, url, **kwargs)
        result = request(method, url, **kwargs)
        return await result if inspect.isawaitable(result) else result


class EdocsApprovalHandler:
    """Connect a pending AAuth event to a trusted eDocs host prompt."""

    def __init__(
        self,
        *,
        consent_client: EdocsConsentClient,
        prompt: Callable[
            [EdocsApprovalRequest],
            Literal["grant", "deny"]
            | Awaitable[Literal["grant", "deny"]],
        ],
    ) -> None:
        self.consent_client = consent_client
        self.prompt = prompt

    async def __call__(self, approval: ApprovalRequired) -> None:
        """Review, prompt, and submit one explicit decision.

        Cancellation and prompt exceptions propagate without submitting
        anything to the Person Server.
        """
        request = await self.consent_client.review_async(approval)
        decision = self.prompt(request)
        if inspect.isawaitable(decision):
            decision = await decision
        if decision not in ("grant", "deny"):
            raise AAuthError(
                INVALID_REQUEST,
                400,
                "trusted eDocs prompt must return grant or deny",
            )
        await self.consent_client.decide_async(approval, decision)
