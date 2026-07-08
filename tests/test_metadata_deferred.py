import pytest

from aauth_edocs import (
    AAuthError,
    JwksResolver,
    PendingStore,
    SigningKey,
    build_metadata,
    fetch_metadata,
    poll,
)


class FakeResponse:
    def __init__(self, status_code=200, body=None, headers=None):
        self.status_code = status_code
        self._body = body or {}
        self.headers = headers or {}

    def json(self):
        return self._body


class FakeTransport:
    """Maps URL -> FakeResponse (or a list consumed per call)."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        response = self.routes.get(url)
        if isinstance(response, list):
            response = response.pop(0)
        return response or FakeResponse(404)


def test_metadata_roundtrip_and_issuer_check():
    md = build_metadata("https://ps.example", jwks_uri="https://ps.example/jwks", token_endpoint="https://ps.example/token")
    transport = FakeTransport({"https://ps.example/.well-known/aauth-person.json": FakeResponse(body=dict(md))})
    fetched = fetch_metadata("https://ps.example", "aauth-person.json", transport)
    assert fetched.endpoint("token_endpoint") == "https://ps.example/token"

    evil = FakeTransport({"https://evil.example/.well-known/aauth-person.json": FakeResponse(body=dict(md))})
    with pytest.raises(AAuthError, match="issuer"):
        fetch_metadata("https://evil.example", "aauth-person.json", evil)


def test_jwks_resolver_caches_and_finds_kid():
    key = SigningKey.generate(kid="k1")
    routes = {
        "https://ps.example/.well-known/aauth-person.json": FakeResponse(
            body={"issuer": "https://ps.example", "jwks_uri": "https://ps.example/jwks"}
        ),
        "https://ps.example/jwks": FakeResponse(body={"keys": [key.public_jwk]}),
    }
    transport = FakeTransport(routes)
    resolver = JwksResolver(transport)
    assert resolver("https://ps.example", "aauth-person.json", "k1") == key.public_jwk
    calls_before = len(transport.calls)
    resolver("https://ps.example", "aauth-person.json", "k1")
    # second resolve hits the key cache — no second JWKS fetch
    assert "https://ps.example/jwks" not in transport.calls[calls_before:]
    with pytest.raises(AAuthError, match="kid"):
        resolver("https://ps.example", "aauth-person.json", "missing")


def test_pending_lifecycle():
    store = PendingStore()
    pid = store.create(requirement='requirement=interaction;url="https://x";code="C"')
    status, headers, body = store.response(pid)
    assert status == 202
    assert body == {"status": "pending"}
    assert headers["Location"] == store.location(pid)
    assert "AAuth-Requirement" in headers and headers["Cache-Control"] == "no-store"

    store.resolve(pid, {"auth_token": "eyJ..."})
    status, _, body = store.response(pid)
    assert (status, body) == (200, {"auth_token": "eyJ..."})
    # terminal responses are delivered once; afterwards 410 (§14.3)
    assert store.response(pid)[0] == 410
    assert store.response("nonexistent")[0] == 410


def test_pending_denial():
    store = PendingStore()
    pid = store.create()
    store.deny(pid, detail="user said no")
    status, _, body = store.response(pid)
    assert status == 403
    assert body["error"] == "denied"


def test_codes_single_use():
    store = PendingStore()
    code = store.new_code()
    assert store.consume_code(code)
    assert not store.consume_code(code)
    assert not store.consume_code("NEVER-ISSUED")


def test_poll_success_after_pending():
    responses = [
        FakeResponse(202, {"status": "pending"}, {"Retry-After": "0"}),
        FakeResponse(202, {"status": "pending"}, {"Retry-After": "0"}),
        FakeResponse(200, {"auth_token": "tok"}),
    ]
    transport = FakeTransport({"https://ps.example/pending/1": responses})
    slept = []
    body = poll("https://ps.example/pending/1", transport, sleep=slept.append, default_interval=2)
    assert body == {"auth_token": "tok"}
    assert len(slept) == 2


def test_poll_terminal_error():
    transport = FakeTransport({"u": [FakeResponse(403, {"error": "denied", "detail": "no"})]})
    with pytest.raises(AAuthError) as err:
        poll("u", transport, sleep=lambda s: None)
    assert err.value.code == "denied"
    assert err.value.status == 403


def test_poll_timeout():
    transport = FakeTransport({"u": FakeResponse(202, {"status": "pending"}, {"Retry-After": "0"})})
    clock = iter(range(100))
    with pytest.raises(AAuthError, match="gave up"):
        poll("u", transport, sleep=lambda s: None, timeout=5, now=lambda: float(next(clock)))
