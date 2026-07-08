"""Ed25519 signing keys and JWK helpers.

AAuth binds tokens and requests to keys via JWK ``cnf`` claims and RFC 7638
thumbprints (the ``agent_jkt`` claim). Internal-experimentation scope:
Ed25519 only (the spec's MUST algorithm, §12.7.1).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an OKP public JWK (base64url SHA-256)."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode()).digest())


class SigningKey:
    """An Ed25519 keypair with JWK import/export and raw sign/verify."""

    def __init__(self, private_key: Ed25519PrivateKey, kid: str | None = None):
        self._private = private_key
        self._public = private_key.public_key()
        self.kid = kid or secrets.token_urlsafe(8)

    @classmethod
    def generate(cls, kid: str | None = None) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate(), kid=kid)

    @classmethod
    def from_private_jwk(cls, jwk: dict) -> "SigningKey":
        private = Ed25519PrivateKey.from_private_bytes(b64url_decode(jwk["d"]))
        return cls(private, kid=jwk.get("kid"))

    @property
    def public_jwk(self) -> dict:
        raw = self._public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw), "kid": self.kid}

    def private_jwk(self) -> dict:
        raw = self._private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return {**self.public_jwk, "d": b64url(raw)}

    @property
    def thumbprint(self) -> str:
        """The key's ``jkt`` — used as ``agent_jkt`` in resource tokens."""
        return jwk_thumbprint(self.public_jwk)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)


def verify_raw(public_jwk: dict, data: bytes, signature: bytes) -> bool:
    """Verify raw bytes against an Ed25519 public JWK."""
    try:
        key = Ed25519PublicKey.from_public_bytes(b64url_decode(public_jwk["x"]))
        key.verify(signature, data)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False
