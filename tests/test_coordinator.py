import asyncio
from collections import deque

import pytest

from aauth_edocs import (
    AAuthError,
    ApprovalRequired,
    AuthorizationCoordinator,
    DWK_ACCESS,
    SigningKey,
    build_metadata,
    build_requirement,
    issue_agent_token,
    issue_auth_token,
    issue_resource_token,
)
from aauth_edocs.agent import TransportResponse

AP = "https://ap.example"
PS = "https://ps.example"
RESOURCE = "https://resource.example"
OTHER_RESOURCE = "https://other.example"
AGENT = "aauth:assistant@ap.example"


class ScriptedTransport:
    def __init__(self, responses):
        self.responses = deque(responses)
        self.requests = []

    def request(self, method, url, headers=None, json=None):
        self.requests.append((method, url, headers or {}, json))
        return self.responses.popleft()

    def get(self, url):
        return self.request("GET", url)


def setup_tokens(*, final_audience=RESOURCE, final_agent=AGENT, final_key=None):
    ap_key = SigningKey.generate(kid="ap")
    resource_key = SigningKey.generate(kid="resource")
    ps_key = SigningKey.generate(kid="ps")
    agent_key = SigningKey.generate(kid="agent")
    bound_key = final_key or agent_key
    agent_token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=agent_key.public_jwk,
        ps=PS,
        key=ap_key,
    )
    resource_token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=AGENT,
        agent_jkt=agent_key.thumbprint,
        scope="read",
        key=resource_key,
    )
    auth_token = issue_auth_token(
        issuer=PS,
        dwk=DWK_ACCESS,
        aud=final_audience,
        agent=final_agent,
        cnf_jwk=bound_key.public_jwk,
        scope="read",
        key=ps_key,
    )
    return agent_key, agent_token, resource_token, auth_token


def metadata_response():
    return TransportResponse(
        200,
        {},
        build_metadata(PS, token_endpoint=f"{PS}/token"),
    )


def test_immediate_exchange_caches_by_resource_origin():
    key, agent_token, resource_token, auth_token = setup_tokens()
    transport = ScriptedTransport(
        [metadata_response(), TransportResponse(200, {}, {"auth_token": auth_token})]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    assert coordinator.begin(
        resource_token,
        resource_url=f"{RESOURCE}/mcp",
    ) == auth_token
    assert coordinator.token_for(f"{RESOURCE}/another-path") == auth_token
    assert coordinator.token_for(OTHER_RESOURCE) is None
    coordinator.invalidate(f"{RESOURCE}/mcp")
    assert coordinator.token_for(RESOURCE) is None


def test_deferred_exchange_returns_event_then_polls():
    key, agent_token, resource_token, auth_token = setup_tokens()
    pending_url = f"{PS}/opaque/abc"
    transport = ScriptedTransport(
        [
            metadata_response(),
            TransportResponse(
                202,
                {
                    "Location": pending_url,
                    "Retry-After": "0",
                    "AAuth-Requirement": build_requirement(
                        "approval",
                        url=f"{PS}/consent/abc",
                    ),
                },
                {"status": "pending"},
            ),
            TransportResponse(202, {"Retry-After": "0"}, {"status": "pending"}),
            TransportResponse(200, {}, {"auth_token": auth_token}),
        ]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    event = coordinator.begin(resource_token, resource_url=RESOURCE)
    assert isinstance(event, ApprovalRequired)
    assert event.pending_url == pending_url
    assert event.resource_origin == RESOURCE
    assert event.approval_url == f"{PS}/consent/abc"
    assert coordinator.token_for(RESOURCE) is None

    assert coordinator.complete(event, sleep=lambda _: None) == auth_token
    assert coordinator.token_for(RESOURCE) == auth_token


def test_rejects_approval_url_outside_person_server():
    key, agent_token, resource_token, _ = setup_tokens()
    transport = ScriptedTransport(
        [
            metadata_response(),
            TransportResponse(
                202,
                {
                    "Location": f"{PS}/opaque/abc",
                    "AAuth-Requirement": build_requirement(
                        "approval",
                        url="https://evil.example/consent/abc",
                    ),
                },
                {"status": "pending"},
            ),
        ]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    with pytest.raises(AAuthError, match="not on the agent's Person Server"):
        coordinator.begin(resource_token, resource_url=RESOURCE)


def test_async_deferred_exchange_does_not_block_event_loop():
    key, agent_token, resource_token, auth_token = setup_tokens()
    transport = ScriptedTransport(
        [
            metadata_response(),
            TransportResponse(
                202,
                {"Location": f"{PS}/opaque/async", "Retry-After": "0"},
                {"status": "pending"},
            ),
            TransportResponse(202, {"Retry-After": "0"}, {"status": "pending"}),
            TransportResponse(200, {}, {"auth_token": auth_token}),
        ]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    async def scenario():
        event = await coordinator.begin_async(
            resource_token,
            resource_url=RESOURCE,
        )
        yielded = {"value": False}

        async def nonblocking_sleep(_):
            await asyncio.sleep(0)
            yielded["value"] = True

        token = await coordinator.complete_async(
            event,
            sleep=nonblocking_sleep,
        )
        return token, yielded["value"]

    token, yielded = asyncio.run(scenario())
    assert token == auth_token
    assert yielded is True


def test_async_deferred_poll_can_be_cancelled():
    key, agent_token, resource_token, _ = setup_tokens()

    class AlwaysPendingTransport(ScriptedTransport):
        def get(self, url):
            if "/.well-known/" in url:
                return super().get(url)
            return TransportResponse(
                202,
                {"Retry-After": "60"},
                {"status": "pending"},
            )

    transport = AlwaysPendingTransport(
        [
            metadata_response(),
            TransportResponse(
                202,
                {"Location": f"{PS}/opaque/cancel", "Retry-After": "60"},
                {"status": "pending"},
            ),
        ]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    async def scenario():
        event = await coordinator.begin_async(
            resource_token,
            resource_url=RESOURCE,
        )
        task = asyncio.create_task(coordinator.complete_async(event))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


def test_deferred_denial_preserves_status_and_detail():
    key, agent_token, resource_token, _ = setup_tokens()
    transport = ScriptedTransport(
        [
            metadata_response(),
            TransportResponse(
                202,
                {"Location": f"{PS}/opaque/denied"},
                {"status": "pending"},
            ),
            TransportResponse(
                403,
                {},
                {"error": "denied", "detail": "controller rejected request"},
            ),
        ]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )
    event = coordinator.begin(resource_token, resource_url=RESOURCE)

    with pytest.raises(AAuthError) as caught:
        coordinator.complete(event, sleep=lambda _: None)
    assert caught.value.status == 403
    assert caught.value.code == "denied"
    assert caught.value.detail == "controller rejected request"


def test_async_deferred_denial_preserves_status_and_detail():
    key, agent_token, resource_token, _ = setup_tokens()
    transport = ScriptedTransport(
        [
            metadata_response(),
            TransportResponse(
                202,
                {"Location": f"{PS}/opaque/async-denied"},
                {"status": "pending"},
            ),
            TransportResponse(
                403,
                {},
                {"error": "denied", "detail": "person denied request"},
            ),
        ]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    async def scenario():
        event = await coordinator.begin_async(
            resource_token,
            resource_url=RESOURCE,
        )
        with pytest.raises(AAuthError) as caught:
            await coordinator.complete_async(event)
        return caught.value

    error = asyncio.run(scenario())
    assert error.status == 403
    assert error.code == "denied"
    assert error.detail == "person denied request"


def test_async_deferred_poll_times_out():
    key, agent_token, resource_token, _ = setup_tokens()

    class PendingAfterExchangeTransport(ScriptedTransport):
        def get(self, url):
            if "/.well-known/" in url:
                return super().get(url)
            return TransportResponse(
                202,
                {"Retry-After": "0"},
                {"status": "pending"},
            )

    transport = PendingAfterExchangeTransport(
        [
            metadata_response(),
            TransportResponse(
                202,
                {"Location": f"{PS}/opaque/timeout"},
                {"status": "pending"},
            ),
        ]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    async def no_sleep(_):
        return None

    async def scenario():
        event = await coordinator.begin_async(
            resource_token,
            resource_url=RESOURCE,
        )
        clock = iter((0.0, 6.0))
        with pytest.raises(AAuthError) as caught:
            await coordinator.complete_async(
                event,
                timeout=5.0,
                sleep=no_sleep,
                now=lambda: next(clock),
            )
        return caught.value

    error = asyncio.run(scenario())
    assert error.status == 408
    assert error.code == "server_error"


@pytest.mark.parametrize("change", ["agent", "key", "audience"])
def test_rejects_final_token_with_wrong_binding(change):
    wrong_key = SigningKey.generate(kid="wrong")
    options = {}
    if change == "agent":
        options["final_agent"] = "aauth:other@ap.example"
    elif change == "key":
        options["final_key"] = wrong_key
    else:
        options["final_audience"] = OTHER_RESOURCE
    key, agent_token, resource_token, auth_token = setup_tokens(**options)
    transport = ScriptedTransport(
        [metadata_response(), TransportResponse(200, {}, {"auth_token": auth_token})]
    )
    coordinator = AuthorizationCoordinator(
        key=key,
        agent_token=agent_token,
        transport=transport,
    )

    with pytest.raises(AAuthError) as caught:
        coordinator.begin(resource_token, resource_url=RESOURCE)
    assert caught.value.code == "invalid_token"
    assert coordinator.token_for(RESOURCE) is None
