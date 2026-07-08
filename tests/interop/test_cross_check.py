"""Best-effort cross-checks against the exploratory PyPI `aauth` library
(christian-posta/aauth-python-library). Auto-skipped unless installed
(`uv sync --group interop`). Not an M1 gate — that library tracks an older
draft in places, and its API may drift."""

import pytest

theirs = pytest.importorskip("aauth")

from aauth_edocs import HttpRequest, SigningKey, sign  # noqa: E402


@pytest.fixture
def their_keypair():
    return theirs.generate_ed25519_keypair()


def test_their_signature_verifies_with_our_verifier_primitives(their_keypair):
    """Their JWK thumbprint and ours agree — key-binding claims interoperate."""
    private_key, public_key = their_keypair
    their_jwk = theirs.public_key_to_jwk(public_key, kid="k1")
    from aauth_edocs import jwk_thumbprint

    assert jwk_thumbprint(their_jwk) == theirs.calculate_jwk_thumbprint(their_jwk)


def test_our_signed_request_verifies_with_their_verifier():
    """Our signature base (component canonicalization + @signature-params)
    verifies with their verifier.

    Known drift: their Signature header parser only accepts unpadded
    base64url, while RFC 8941 byte sequences (and our output) use standard
    base64. We transcode the header for this test; the meaningful interop
    check — that both sides build the identical RFC 9421 signature base —
    is what the verification below exercises.
    """
    import base64
    import re

    ap_key, agent_key = SigningKey.generate(kid="ap"), SigningKey.generate(kid="agent")
    from aauth_edocs import agent_id, issue_agent_token

    token = issue_agent_token(
        issuer="https://ap.example",
        agent=agent_id("assistant", "ap.example"),
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
    )
    request = sign(HttpRequest("GET", "https://resource.example/api/data", {}), agent_key, token)

    sig_b64 = re.fullmatch(r"sig=:(.+):", request.headers["Signature"]).group(1)
    sig_urlsafe = base64.urlsafe_b64encode(base64.b64decode(sig_b64)).decode().rstrip("=")
    request.headers["Signature"] = f"sig=:{sig_urlsafe}:"

    is_valid = theirs.verify_signature(
        method=request.method,
        target_uri=request.url,
        headers=request.headers,
        body=None,
        signature_input_header=request.headers["Signature-Input"],
        signature_header=request.headers["Signature"],
        signature_key_header=request.headers["Signature-Key"],
        # their verifier discovers the JWT-issuer key via this fetcher
        jwks_fetcher=lambda *a, **kw: {"keys": [ap_key.public_jwk]},
    )
    assert is_valid
