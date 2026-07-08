"""HTTP Message Signatures — the AAuth profile (§12.7) plus the
Signature-Key ``jwt`` scheme (SigKey §3.6), in one module.

The RFC 9421 subset AAuth needs: one signature label, derived components
@method/@authority/@path/@query plus header fields, a single ``created``
parameter, Ed25519. ``verify()`` is the server-side entry point for every
role in later phases: it authenticates the request and returns the verified
claims of whatever JWT (agent token or auth token) was presented.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from http_sfv import Dictionary
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import OKPKey

from .errors import AAuthError, EXPIRED, INVALID_SIGNATURE
from .keys import SigningKey, b64url_decode, verify_raw

# §12.7.3.1 — every AAuth request signature covers at least these.
MANDATED_COMPONENTS = ("@method", "@authority", "@path", "signature-key")

# KeyResolver: (iss, dwk, kid) -> public JWK dict for verifying a JWT.
KeyResolver = Callable[[str, str, str], dict]


@dataclass
class HttpRequest:
    """Framework-agnostic request view shared by client and servers."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None

    def get_header(self, name: str) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


@dataclass
class VerifiedRequest:
    """Result of a successful ``verify()``."""

    claims: dict  # payload of the presented JWT (agent/auth token), or {"iss": ...} for jwks_uri signers
    header: dict  # its JOSE header (typ tells you which kind), or {"scheme": "jwks_uri"}
    token: str | None  # the presented compact JWT (None for jwks_uri signers)
    covered: list[str]


def _component_value(request: HttpRequest, name: str) -> str:
    parts = urlsplit(request.url)
    if name == "@method":
        return request.method.upper()
    if name == "@authority":
        return parts.netloc.lower()
    if name == "@path":
        return parts.path or "/"
    if name == "@query":
        return "?" + parts.query
    value = request.get_header(name)
    if value is None:
        raise AAuthError(INVALID_SIGNATURE, 401, f"covered header missing: {name}")
    return value.strip()


def _signature_base(request: HttpRequest, components: list[str], params: str) -> bytes:
    lines = [f'"{c}": {_component_value(request, c)}' for c in components]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode()


def sign(request: HttpRequest, key: SigningKey, token: str, *, now: Callable[[], float] = time.time) -> HttpRequest:
    """Sign a request, presenting `token` (agent or auth token) via Signature-Key.

    Mutates and returns `request`, adding Signature-Key, Signature-Input,
    and Signature headers.
    """
    request.headers["Signature-Key"] = f'sig=jwt;jwt="{token}"'
    return _sign_prepared(request, key, now)


def sign_server(
    request: HttpRequest, key: SigningKey, issuer: str, dwk: str, *, now: Callable[[], float] = time.time
) -> HttpRequest:
    """Sign a server-to-server request using the jwks_uri Signature-Key
    scheme (SigKey §3.5) — how a PS authenticates to an AS (§9.1.1)."""
    request.headers["Signature-Key"] = f'sig=jwks_uri;id="{issuer}";dwk="{dwk}";kid="{key.kid}"'
    return _sign_prepared(request, key, now)


def _sign_prepared(request: HttpRequest, key: SigningKey, now: Callable[[], float]) -> HttpRequest:
    components = ["@method", "@authority", "@path"]
    if urlsplit(request.url).query:
        components.append("@query")  # interop: the JS/Python libs cover @query
    for header in ("authorization", "aauth-mission"):  # §6.4, §6.1
        if request.get_header(header) is not None:
            components.append(header)
    components.append("signature-key")

    quoted = " ".join(f'"{c}"' for c in components)
    params = f"({quoted});created={int(now())}"
    signature = key.sign(_signature_base(request, components, params))

    request.headers["Signature-Input"] = f"sig={params}"
    request.headers["Signature"] = f"sig=:{base64.b64encode(signature).decode()}:"
    return request


def peek_jwt(token: str) -> tuple[dict, dict]:
    """Decode a compact JWT's header and claims WITHOUT verification."""
    try:
        head, payload, _ = token.split(".")
        return (
            json.loads(b64url_decode(head)),
            json.loads(b64url_decode(payload)),
        )
    except (ValueError, json.JSONDecodeError):
        raise AAuthError(INVALID_SIGNATURE, 401, "malformed JWT in Signature-Key")


def verify_jwt(token: str, key_resolver: KeyResolver, *, now: Callable[[], float] = time.time) -> tuple[dict, dict]:
    """Verify a JWT's signature (issuer key via resolver) and exp.

    Returns (header, claims).
    """
    header, claims = peek_jwt(token)
    jwk = key_resolver(claims.get("iss", ""), claims.get("dwk", ""), header.get("kid", ""))
    try:
        joserfc_jwt.decode(token, OKPKey.import_key(jwk), algorithms=["EdDSA"])
    except Exception as e:
        raise AAuthError(INVALID_SIGNATURE, 401, f"JWT verification failed: {e}")
    if "exp" in claims and claims["exp"] <= now():
        raise AAuthError(EXPIRED, 401, "presented token has expired")
    return header, claims


def verify(
    request: HttpRequest,
    key_resolver: KeyResolver,
    *,
    now: Callable[[], float] = time.time,
    window: int = 300,
) -> VerifiedRequest:
    """Verify a signed request per the AAuth profile (§12.7.4, simplified).

    Checks: headers present, mandated components covered (extras accepted),
    `created` within the window, the presented JWT verifies against its
    issuer's published key, and the HTTP signature verifies against the
    JWT's cnf.jwk (proof-of-possession).
    """
    sig_input = request.get_header("Signature-Input")
    sig_header = request.get_header("Signature")
    sig_key = request.get_header("Signature-Key")
    if not (sig_input and sig_header and sig_key):
        raise AAuthError(INVALID_SIGNATURE, 401, "missing signature headers")

    input_dict, key_dict, sig_dict = Dictionary(), Dictionary(), Dictionary()
    try:
        input_dict.parse(sig_input.encode())
        key_dict.parse(sig_key.encode())
        sig_dict.parse(sig_header.encode())
        label = next(iter(input_dict))
        inner = input_dict[label]
        components = [str(item.value) for item in inner]
        created = int(inner.params["created"])
        key_member = key_dict[label]
        signature = bytes(sig_dict[label].value)
    except (KeyError, ValueError, StopIteration) as e:
        raise AAuthError(INVALID_SIGNATURE, 401, f"malformed signature headers: {e}")

    missing = set(MANDATED_COMPONENTS) - set(components)
    if missing:
        raise AAuthError(INVALID_SIGNATURE, 401, f"signature must cover {sorted(missing)}")
    if abs(now() - created) > window:
        raise AAuthError(INVALID_SIGNATURE, 401, "signature created outside validity window")

    scheme = str(key_member.value)
    if scheme == "jwt":  # agents (§12.7.2): key comes from the token's cnf
        token = str(key_member.params["jwt"])
        header, claims = verify_jwt(token, key_resolver, now=now)
        cnf_jwk = (claims.get("cnf") or {}).get("jwk")
        if not cnf_jwk:
            raise AAuthError(INVALID_SIGNATURE, 401, "presented token has no cnf.jwk")
    elif scheme == "jwks_uri":  # servers, e.g. PS -> AS (SigKey §3.5)
        try:
            signer = str(key_member.params["id"])
            cnf_jwk = key_resolver(signer, str(key_member.params["dwk"]), str(key_member.params["kid"]))
        except KeyError as e:
            raise AAuthError(INVALID_SIGNATURE, 401, f"jwks_uri scheme missing param: {e}")
        token, header, claims = None, {"scheme": "jwks_uri"}, {"iss": signer}
    else:
        raise AAuthError(INVALID_SIGNATURE, 401, f"unsupported Signature-Key scheme {scheme!r}")

    # Rebuild @signature-params byte-exactly from the received header value.
    params = sig_input[len(str(label)) + 1 :]
    base = _signature_base(request, components, params)
    if not verify_raw(cnf_jwk, base, signature):
        raise AAuthError(INVALID_SIGNATURE, 401, "HTTP signature verification failed")

    return VerifiedRequest(claims=claims, header=header, token=token, covered=components)
