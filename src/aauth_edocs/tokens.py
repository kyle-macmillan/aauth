"""The three AAuth token types: agent (?5.2), resource (?6.7), auth (?9.4).

Builders set typ/dwk/jti/iat/exp; verifiers check what the flows depend on ?
signature via the issuer's published key, typ, exp, and the binding claims
(aud = me, agent = expected, cnf.jwk / agent_jkt = the request's signing key).
Internal-experimentation scope: no lifetime-cap enforcement, no act-chain or
sub-agent verification (those claims pass through untouched).
"""

from __future__ import annotations

import secrets
import time
from typing import Callable

from joserfc import jwt as joserfc_jwt
from joserfc.jwk import OKPKey

from .errors import AAuthError, INVALID_TOKEN
from .httpsig import KeyResolver, verify_jwt
from .ids import DWK_ACCESS, DWK_AGENT, DWK_PERSON, DWK_RESOURCE, DWK_SENTINEL
from .keys import SigningKey, jwk_thumbprint

AGENT_TYP = "aa-agent+jwt"
RESOURCE_TYP = "aa-resource+jwt"
AUTH_TYP = "aa-auth+jwt"

Now = Callable[[], float]


def _issue(typ: str, key: SigningKey, claims: dict, lifetime: int, now: Now) -> str:
    t = int(now())
    payload = {"jti": secrets.token_urlsafe(12), "iat": t, "exp": t + lifetime}
    payload.update({k: v for k, v in claims.items() if v is not None})
    header = {"alg": "EdDSA", "typ": typ, "kid": key.kid}
    return joserfc_jwt.encode(header, payload, OKPKey.import_key(key.private_jwk()), algorithms=["EdDSA"])


def issue_agent_token(
    *,
    issuer: str,
    agent: str,
    agent_jwk: dict,
    key: SigningKey,
    ps: str | None = None,
    parent_agent: str | None = None,
    lifetime: int = 24 * 3600,
    now: Now = time.time,
) -> str:
    """Agent-provider side: bind `agent_jwk` to the agent identifier (?5.2.2)."""
    return _issue(
        AGENT_TYP,
        key,
        {
            "iss": issuer,
            "dwk": DWK_AGENT,
            "sub": agent,
            "cnf": {"jwk": agent_jwk},
            "ps": ps,
            "parent_agent": parent_agent,
        },
        lifetime,
        now,
    )


def validate_dataflow(dataflow: dict) -> dict:
    """Require ``{"data": <any JSON>, "function": <str>}``."""
    if not isinstance(dataflow, dict) or "data" not in dataflow or "function" not in dataflow:
        raise ValueError("dataflow must be a dict with data and function")
    if not isinstance(dataflow["function"], str):
        raise ValueError("dataflow.function must be a string")
    return dataflow


def _require_scope_xor_dataflow(*, scope: str | None, dataflow: dict | None) -> tuple[str | None, dict | None]:
    has_scope = scope is not None
    has_dataflow = dataflow is not None
    if has_scope == has_dataflow:
        raise ValueError("exactly one of scope or dataflow is required")
    if has_dataflow:
        dataflow = validate_dataflow(dataflow)
    return scope, dataflow


def issue_resource_token(
    *,
    issuer: str,
    aud: str,
    agent: str,
    agent_jkt: str,
    key: SigningKey,
    scope: str | None = None,
    dataflow: dict | None = None,
    mission: dict | None = None,
    interaction: dict | None = None,
    controller: str | None = None,
    lifetime: int = 300,
    now: Now = time.time,
) -> str:
    """Resource side: describe the access the agent needs (?6.7.1).

    `aud` is the PS URL (three-party), AS URL (four-party), or sentinel URL
    (eDocs). When `aud` is a sentinel, `controller` is the controller AS URL.
    `mission` is a mission-reference claim dict when the agent sent
    AAuth-Mission (?8.7).

    Exactly one of `scope` or `dataflow` is required (mutually exclusive).
    """
    scope, dataflow = _require_scope_xor_dataflow(scope=scope, dataflow=dataflow)
    return _issue(
        RESOURCE_TYP,
        key,
        {
            "iss": issuer,
            "dwk": DWK_RESOURCE,
            "aud": aud,
            "agent": agent,
            "agent_jkt": agent_jkt,
            "scope": scope,
            "dataflow": dataflow,
            "mission": mission,
            "interaction": interaction,
            "controller": controller,
        },
        lifetime,
        now,
    )


def issue_auth_token(
    *,
    issuer: str,
    dwk: str,
    aud: str,
    agent: str,
    cnf_jwk: dict,
    sub: str | None = None,
    scope: str | None = None,
    dataflow: dict | None = None,
    mission: dict | None = None,
    act: dict | None = None,
    key: SigningKey,
    lifetime: int = 3600,
    now: Now = time.time,
) -> str:
    """PS/AS side: grant the agent access to `aud` (?9.4.1).

    `dwk` is aauth-person.json (PS-issued) or aauth-access.json (AS-issued).
    Exactly one of scope/dataflow is required; `sub` is optional alongside either.
    """
    if dwk not in (DWK_PERSON, DWK_ACCESS, DWK_SENTINEL):
        raise ValueError("auth token dwk must be aauth-person.json or aauth-access.json")
    scope, dataflow = _require_scope_xor_dataflow(scope=scope, dataflow=dataflow)
    return _issue(
        AUTH_TYP,
        key,
        {
            "iss": issuer,
            "dwk": dwk,
            "aud": aud,
            "agent": agent,
            "cnf": {"jwk": cnf_jwk},
            "sub": sub,
            "scope": scope,
            "dataflow": dataflow,
            "mission": mission,
            "act": act,
        },
        lifetime,
        now,
    )


def _decode(token: str, key_resolver: KeyResolver, expect_typ: str, now: Now) -> dict:
    header, claims = verify_jwt(token, key_resolver, now=now)
    if header.get("typ") != expect_typ:
        raise AAuthError(INVALID_TOKEN, detail=f"expected typ {expect_typ}, got {header.get('typ')}")
    return claims


def verify_agent_token(
    token: str,
    key_resolver: KeyResolver,
    *,
    signing_jwk: dict | None = None,
    now: Now = time.time,
) -> dict:
    """Verify an agent token (?5.2.4); optionally bind it to the request's
    signing key (cnf.jwk must match `signing_jwk`). Returns the claims."""
    claims = _decode(token, key_resolver, AGENT_TYP, now)
    if signing_jwk is not None:
        _check_cnf(claims, signing_jwk)
    return claims


def verify_resource_token(
    token: str,
    key_resolver: KeyResolver,
    *,
    aud: str,
    agent: str | None = None,
    agent_jkt: str | None = None,
    now: Now = time.time,
) -> dict:
    """PS/AS-side resource token verification (?6.7.2). `aud` is the
    recipient's own identifier (or matches RT `controller` on the sentinel
    path). agent/agent_jkt are checked when given."""
    claims = _decode(token, key_resolver, RESOURCE_TYP, now)
    # Classic: aud == recipient. Sentinel path: aud is the sentinel and
    # controller == this AS (dual-authority eDocs profile).
    if claims.get("aud") != aud and claims.get("controller") != aud:
        raise AAuthError(
            INVALID_TOKEN,
            detail=f"resource token aud/controller is {claims.get('aud')!r}/{claims.get('controller')!r}, not us",
        )
    if agent is not None and claims.get("agent") != agent:
        raise AAuthError(INVALID_TOKEN, detail="resource token agent mismatch")
    if agent_jkt is not None and claims.get("agent_jkt") != agent_jkt:
        raise AAuthError(INVALID_TOKEN, detail="resource token agent_jkt mismatch")
    return claims


def check_resource_challenge(
    token: str,
    *,
    resource: str,
    agent: str,
    agent_jkt: str,
    key_resolver: KeyResolver | None = None,
    now: Now = time.time,
) -> dict:
    """Agent-side check of a resource token from a 401 challenge (?6.7.3):
    it names the resource we called, us, and our key. Signature verification
    is optional here (pass a resolver to enable it)."""
    if key_resolver is not None:
        claims = _decode(token, key_resolver, RESOURCE_TYP, now)
    else:
        from .httpsig import peek_jwt

        header, claims = peek_jwt(token)
        if header.get("typ") != RESOURCE_TYP:
            raise AAuthError(INVALID_TOKEN, detail="challenge token is not aa-resource+jwt")
        if claims.get("exp", 0) <= now():
            raise AAuthError(INVALID_TOKEN, detail="challenge resource token expired")
    if claims.get("iss") != resource:
        raise AAuthError(INVALID_TOKEN, detail="resource token iss is not the resource we called")
    if claims.get("agent") != agent:
        raise AAuthError(INVALID_TOKEN, detail="resource token was issued to a different agent")
    if claims.get("agent_jkt") != agent_jkt:
        raise AAuthError(INVALID_TOKEN, detail="resource token bound to a different key")
    return claims


def verify_auth_token(
    token: str,
    key_resolver: KeyResolver,
    *,
    aud: str,
    signing_jwk: dict | None = None,
    now: Now = time.time,
) -> dict:
    """Resource-side auth token verification (?9.4.3, simplified): typ, an
    issuer dwk of person/access, aud = me, cnf.jwk = the request's signing
    key, and exactly one of scope/dataflow (sub optional)."""
    claims = _decode(token, key_resolver, AUTH_TYP, now)
    if claims.get("dwk") not in (DWK_PERSON, DWK_ACCESS, DWK_SENTINEL):
        raise AAuthError(INVALID_TOKEN, detail=f"auth token dwk {claims.get('dwk')!r} not recognized")
    if claims.get("aud") != aud:
        raise AAuthError(INVALID_TOKEN, detail=f"auth token aud is {claims.get('aud')}, not us")
    has_scope = "scope" in claims
    has_dataflow = "dataflow" in claims
    if has_scope == has_dataflow:
        raise AAuthError(INVALID_TOKEN, detail="auth token needs exactly one of scope or dataflow")
    if has_dataflow:
        try:
            validate_dataflow(claims["dataflow"])
        except ValueError as error:
            raise AAuthError(INVALID_TOKEN, detail=str(error)) from error
    if signing_jwk is not None:
        _check_cnf(claims, signing_jwk)
    return claims


def _check_cnf(claims: dict, signing_jwk: dict) -> None:
    cnf_jwk = (claims.get("cnf") or {}).get("jwk")
    if not cnf_jwk or jwk_thumbprint(cnf_jwk) != jwk_thumbprint(signing_jwk):
        raise AAuthError(INVALID_TOKEN, detail="token cnf.jwk does not match the signing key")
