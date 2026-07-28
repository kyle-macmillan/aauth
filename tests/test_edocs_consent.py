import asyncio

import pytest

from aauth_edocs import (
    AAuthError,
    ApprovalRequired,
    EMPTY_FUNCTION_ARGS_HASH,
    EdocsApprovalHandler,
    EdocsApprovalRequest,
    EdocsConsentClient,
)
from aauth_edocs.agent import TransportResponse

PS = "https://ps.example"
APPROVAL_URL = f"{PS}/consent/abc"


def approval():
    return ApprovalRequired(
        pending_url=f"{PS}/pending/opaque",
        resource_origin="https://resource.example",
        headers={},
        approval_url=APPROVAL_URL,
    )


def review_body():
    claims = {
        "iss": "https://resource.example",
        "aud": "https://sentinel.example",
        "agent": "aauth:destination@ap.example",
        "scope": "identity@1",
        "source_agent": "aauth:source@ap.example",
        "edoc_id": "doc-123",
        "controllers": ["https://as-a.example", "https://as-b.example"],
        "function_args": {},
        "function_args_hash": EMPTY_FUNCTION_ARGS_HASH,
    }
    return {
        "agent": claims["agent"],
        "resource": claims["iss"],
        "audience": claims["aud"],
        "scope": claims["scope"],
        "claims": claims,
    }


class PersonTransport:
    def __init__(self, review=None):
        self.review = review or review_body()
        self.decisions = []

    def get(self, url):
        assert url == APPROVAL_URL
        return TransportResponse(200, {}, self.review)

    def request(self, method, url, headers=None, json=None):
        assert method == "POST"
        assert url == APPROVAL_URL
        self.decisions.append(json)
        return TransportResponse(200, {}, {"status": "recorded"})


def test_returns_typed_ps_verified_edocs_review():
    client = EdocsConsentClient(PersonTransport())
    result = client.review(approval())
    assert result == EdocsApprovalRequest(
        source_agent="aauth:source@ap.example",
        function_id="identity@1",
        edoc_id="doc-123",
        destination_agent="aauth:destination@ap.example",
        controllers=("https://as-a.example", "https://as-b.example"),
        resource="https://resource.example",
        authorization_audience="https://sentinel.example",
        approval_url=APPROVAL_URL,
        function_args={},
        function_args_hash=EMPTY_FUNCTION_ARGS_HASH,
    )


def test_submits_only_explicit_grant_or_deny():
    transport = PersonTransport()
    client = EdocsConsentClient(transport)
    client.decide(approval(), "grant")
    client.decide(approval(), "deny")
    assert transport.decisions == [
        {"decision": "grant"},
        {"decision": "deny"},
    ]

    with pytest.raises(AAuthError, match="must be grant or deny"):
        client.decide(approval(), "maybe")


def test_rejects_review_that_disagrees_with_verified_claims():
    body = review_body()
    body["scope"] = "safe-looking-function@1"
    client = EdocsConsentClient(PersonTransport(body))
    with pytest.raises(AAuthError, match="scope does not match"):
        client.review(approval())


def test_requires_advertised_approval_url():
    event = ApprovalRequired(
        pending_url=f"{PS}/pending/opaque",
        resource_origin="https://resource.example",
        headers={},
    )
    with pytest.raises(AAuthError, match="has no Person Server approval URL"):
        EdocsConsentClient(PersonTransport()).review(event)


def test_async_review_and_decision():
    transport = PersonTransport()
    client = EdocsConsentClient(transport)

    async def scenario():
        result = await client.review_async(approval())
        await client.decide_async(approval(), "grant")
        return result

    result = asyncio.run(scenario())
    assert result.function_id == "identity@1"
    assert transport.decisions == [{"decision": "grant"}]


def test_approval_handler_passes_typed_review_and_submits_grant():
    transport = PersonTransport()
    consent = EdocsConsentClient(transport)
    prompted = []

    async def prompt(request):
        prompted.append(request)
        await asyncio.sleep(0)
        return "grant"

    asyncio.run(
        EdocsApprovalHandler(
            consent_client=consent,
            prompt=prompt,
        )(approval())
    )
    assert len(prompted) == 1
    assert isinstance(prompted[0], EdocsApprovalRequest)
    assert prompted[0].edoc_id == "doc-123"
    assert transport.decisions == [{"decision": "grant"}]


def test_approval_handler_accepts_sync_deny_prompt():
    transport = PersonTransport()
    handler = EdocsApprovalHandler(
        consent_client=EdocsConsentClient(transport),
        prompt=lambda _request: "deny",
    )
    asyncio.run(handler(approval()))
    assert transport.decisions == [{"decision": "deny"}]


def test_approval_handler_rejects_invalid_prompt_result():
    transport = PersonTransport()
    handler = EdocsApprovalHandler(
        consent_client=EdocsConsentClient(transport),
        prompt=lambda _request: "later",
    )
    with pytest.raises(AAuthError, match="must return grant or deny"):
        asyncio.run(handler(approval()))
    assert transport.decisions == []


def test_approval_handler_cancellation_submits_no_decision():
    transport = PersonTransport()

    async def cancelled(_request):
        raise asyncio.CancelledError

    handler = EdocsApprovalHandler(
        consent_client=EdocsConsentClient(transport),
        prompt=cancelled,
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(handler(approval()))
    assert transport.decisions == []


def test_decided_approval_cannot_be_replayed():
    class OneShotPersonTransport(PersonTransport):
        def __init__(self):
            super().__init__()
            self.decided = False

        def get(self, url):
            if self.decided:
                return TransportResponse(
                    404,
                    {},
                    {"error": "invalid_request", "detail": "no such pending consent"},
                )
            return super().get(url)

        def request(self, method, url, headers=None, json=None):
            if self.decided:
                return TransportResponse(
                    404,
                    {},
                    {"error": "invalid_request", "detail": "no such pending consent"},
                )
            response = super().request(method, url, headers=headers, json=json)
            self.decided = True
            return response

    transport = OneShotPersonTransport()
    client = EdocsConsentClient(transport)
    client.decide(approval(), "grant")

    with pytest.raises(AAuthError, match="no such pending consent"):
        client.review(approval())
    with pytest.raises(AAuthError, match="no such pending consent"):
        client.decide(approval(), "grant")
