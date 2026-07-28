"""The three AAuth token types: agent (§5.2), resource (§6.7), auth (§9.4).

Builders set typ/dwk/jti/iat/exp; verifiers check what the flows depend on —
signature via the issuer's published key, typ, exp, and the binding claims
(aud = me, agent = expected, cnf.jwk / agent_jkt = the request's signing key).
Internal-experimentation scope: no lifetime-cap enforcement, no act-chain or
sub-agent verification (those claims pass through untouched).
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Mapping
from typing import Callable

from joserfc import jwt as joserfc_jwt
from joserfc.jwk import OKPKey

from .edocs import (
    EMPTY_FUNCTION_ARGS_HASH,
    Dataflow,
    DataflowBinding,
    canonicalize_function_args,
    hash_function_args,
)
from .errors import AAuthError, INVALID_TOKEN
from .httpsig import KeyResolver, verify_jwt
from .ids import DWK_ACCESS, DWK_AGENT, DWK_PERSON, DWK_RESOURCE
from .keys import SigningKey, jwk_thumbprint

AGENT_TYP = "aa-agent+jwt"
RESOURCE_TYP = "aa-resource+jwt"
AUTH_TYP = "aa-auth+jwt"
CONDITIONAL_AUTH_TYP = "aa-conditional-auth+jwt"

Now = Callable[[], float]
_EDOC_CLAIMS = ("source_agent", "edoc_id", "controllers", "function_args_hash")


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
    """Agent-provider side: bind `agent_jwk` to the agent identifier (§5.2.2)."""
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


def issue_resource_token(
    *,
    issuer: str,
    aud: str,
    agent: str,
    agent_jkt: str,
    scope: str,
    key: SigningKey,
    mission: dict | None = None,
    interaction: dict | None = None,
    source_agent: str | None = None,
    edoc_id: str | None = None,
    controllers: list[str] | tuple[str, ...] | None = None,
    function_args: Mapping | None = None,
    lifetime: int = 300,
    now: Now = time.time,
) -> str:
    """Resource side: describe the access the agent needs (§6.7.1).

    `aud` is the PS URL (three-party) or AS URL (four-party). `mission` is a
    mission-reference claim dict when the agent sent AAuth-Mission (§8.7).
    """
    edocs = _edocs_claims(source_agent, edoc_id, controllers)
    if edocs:
        arguments = {} if function_args is None else dict(function_args)
        canonicalize_function_args(arguments)
        edocs.update(
            {
                "function_args": arguments,
                "function_args_hash": hash_function_args(arguments),
            }
        )
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
            "mission": mission,
            "interaction": interaction,
            **edocs,
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
    mission: dict | None = None,
    act: dict | None = None,
    source_agent: str | None = None,
    edoc_id: str | None = None,
    controllers: list[str] | tuple[str, ...] | None = None,
    function_args_hash: str | None = None,
    key: SigningKey,
    lifetime: int = 3600,
    now: Now = time.time,
) -> str:
    """PS/AS side: grant the agent access to `aud` (§9.4.1).

    `dwk` is aauth-person.json (PS-issued) or aauth-access.json (AS-issued).
    At least one of sub/scope is required.
    """
    if dwk not in (DWK_PERSON, DWK_ACCESS):
        raise ValueError("auth token dwk must be aauth-person.json or aauth-access.json")
    if sub is None and scope is None:
        raise ValueError("auth token needs at least one of sub or scope")
    edocs = _edocs_claims(source_agent, edoc_id, controllers)
    if edocs:
        edocs["function_args_hash"] = _validate_function_args_hash(
            function_args_hash or EMPTY_FUNCTION_ARGS_HASH
        )
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
            "mission": mission,
            "act": act,
            **edocs,
        },
        lifetime,
        now,
    )


def issue_conditional_auth_token(
    *,
    issuer: str,
    aud: str,
    agent: str,
    cnf_jwk: dict,
    scope: str,
    source_agent: str,
    edoc_id: str,
    controllers: list[str] | tuple[str, ...],
    function_args_hash: str = EMPTY_FUNCTION_ARGS_HASH,
    prerequisite: Dataflow,
    key: SigningKey,
    lifetime: int = 3600,
    now: Now = time.time,
) -> str:
    """AS side: approve an eDocs proposal subject to one prerequisite.

    This intermediate token is addressed to the Sentinel and cannot be used
    as a normal resource authorization.
    """
    if not isinstance(prerequisite, Dataflow):
        raise ValueError("prerequisite must be a Dataflow")
    edocs = _edocs_claims(source_agent, edoc_id, controllers)
    edocs["function_args_hash"] = _validate_function_args_hash(function_args_hash)
    return _issue(
        CONDITIONAL_AUTH_TYP,
        key,
        {
            "iss": issuer,
            "dwk": DWK_ACCESS,
            "aud": aud,
            "agent": agent,
            "cnf": {"jwk": cnf_jwk},
            "scope": scope,
            **edocs,
            "prerequisite": _encode_dataflow(prerequisite),
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
    """Verify an agent token (§5.2.4); optionally bind it to the request's
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
    source_agent: str | None = None,
    scope: str | None = None,
    edoc_id: str | None = None,
    controllers: list[str] | tuple[str, ...] | None = None,
    function_args_hash: str | None = None,
    now: Now = time.time,
) -> dict:
    """PS/AS-side resource token verification (§6.7.2). `aud` is the
    recipient's own identifier; other expected bindings are checked when given."""
    claims = _decode(token, key_resolver, RESOURCE_TYP, now)
    _validate_edocs_claims(claims, require_full_args=True)
    if claims.get("aud") != aud:
        raise AAuthError(INVALID_TOKEN, detail=f"resource token aud is {claims.get('aud')}, not us")
    if agent is not None and claims.get("agent") != agent:
        raise AAuthError(INVALID_TOKEN, detail="resource token agent mismatch")
    if agent_jkt is not None and claims.get("agent_jkt") != agent_jkt:
        raise AAuthError(INVALID_TOKEN, detail="resource token agent_jkt mismatch")
    _check_edocs_bindings(
        claims, source_agent, scope, edoc_id, controllers, function_args_hash
    )
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
    """Agent-side check of a resource token from a 401 challenge (§6.7.3):
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
    source_agent: str | None = None,
    scope: str | None = None,
    edoc_id: str | None = None,
    controllers: list[str] | tuple[str, ...] | None = None,
    function_args_hash: str | None = None,
    now: Now = time.time,
) -> dict:
    """Resource-side auth token verification (§9.4.3, simplified): typ, an
    issuer dwk of person/access, aud = me, cnf.jwk = the request's signing
    key, and at least one of sub/scope."""
    claims = _decode(token, key_resolver, AUTH_TYP, now)
    _validate_edocs_claims(claims)
    if claims.get("dwk") not in (DWK_PERSON, DWK_ACCESS):
        raise AAuthError(INVALID_TOKEN, detail=f"auth token dwk {claims.get('dwk')!r} not recognized")
    if claims.get("aud") != aud:
        raise AAuthError(INVALID_TOKEN, detail=f"auth token aud is {claims.get('aud')}, not us")
    if "sub" not in claims and "scope" not in claims:
        raise AAuthError(INVALID_TOKEN, detail="auth token has neither sub nor scope")
    if signing_jwk is not None:
        _check_cnf(claims, signing_jwk)
    _check_edocs_bindings(
        claims, source_agent, scope, edoc_id, controllers, function_args_hash
    )
    return claims


def verify_conditional_auth_token(
    token: str,
    key_resolver: KeyResolver,
    *,
    issuer: str,
    aud: str,
    agent: str,
    signing_jwk: dict,
    source_agent: str,
    scope: str,
    edoc_id: str,
    controllers: list[str] | tuple[str, ...],
    function_args_hash: str = EMPTY_FUNCTION_ARGS_HASH,
    now: Now = time.time,
) -> DataflowBinding:
    """Sentinel-side verification of one controller AS's conditional approval."""
    claims = _decode(token, key_resolver, CONDITIONAL_AUTH_TYP, now)
    _validate_edocs_claims(claims)
    if claims.get("iss") != issuer:
        raise AAuthError(INVALID_TOKEN, detail="conditional token issuer mismatch")
    if claims.get("dwk") != DWK_ACCESS:
        raise AAuthError(INVALID_TOKEN, detail="conditional token dwk must be aauth-access.json")
    if claims.get("aud") != aud:
        raise AAuthError(INVALID_TOKEN, detail=f"conditional token aud is {claims.get('aud')}, not us")
    if claims.get("agent") != agent:
        raise AAuthError(INVALID_TOKEN, detail="conditional token agent mismatch")
    _check_cnf(claims, signing_jwk)
    _check_edocs_bindings(
        claims,
        source_agent,
        scope,
        edoc_id,
        controllers,
        function_args_hash,
    )
    return _decode_dataflow(claims.get("prerequisite"))


def _check_cnf(claims: dict, signing_jwk: dict) -> None:
    cnf_jwk = (claims.get("cnf") or {}).get("jwk")
    if not cnf_jwk or jwk_thumbprint(cnf_jwk) != jwk_thumbprint(signing_jwk):
        raise AAuthError(INVALID_TOKEN, detail="token cnf.jwk does not match the signing key")


def _encode_dataflow(dataflow: Dataflow) -> dict:
    value = {
        "source": dataflow.source,
        "function": dataflow.function,
        "document": dataflow.document,
        "destination": dataflow.destination,
        "function_args_hash": dataflow.function_args_hash,
    }
    if any(not isinstance(item, str) or not item for item in value.values()):
        raise ValueError("prerequisite Dataflow fields must be non-empty strings")
    return value


def _decode_dataflow(value: object) -> DataflowBinding:
    fields = {
        "source",
        "function",
        "document",
        "destination",
        "function_args_hash",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AAuthError(
            INVALID_TOKEN,
            detail="conditional token prerequisite has the wrong fields",
        )
    if any(not isinstance(value[name], str) or not value[name] for name in fields):
        raise AAuthError(INVALID_TOKEN, detail="conditional token prerequisite fields must be non-empty strings")
    _validate_function_args_hash(value["function_args_hash"])
    return DataflowBinding(
        source=value["source"],
        function=value["function"],
        document=value["document"],
        destination=value["destination"],
        function_args_hash=value["function_args_hash"],
    )


def _edocs_claims(
    source_agent: str | None,
    edoc_id: str | None,
    controllers: list[str] | tuple[str, ...] | None,
) -> dict:
    values = (source_agent, edoc_id, controllers)
    if all(value is None for value in values):
        return {}
    if any(value is None for value in values):
        raise ValueError("eDocs claims require source_agent, edoc_id, and controllers together")
    if not isinstance(source_agent, str) or not source_agent:
        raise ValueError("source_agent must be a non-empty string")
    if not isinstance(edoc_id, str) or not edoc_id:
        raise ValueError("edoc_id must be a non-empty string")
    if not isinstance(controllers, (list, tuple)):
        raise ValueError("controllers must be a list or tuple")
    if any(not isinstance(controller, str) or not controller for controller in controllers):
        raise ValueError("controllers must contain non-empty strings")
    if len(set(controllers)) != len(controllers):
        raise ValueError("controllers must not contain duplicates")
    return {
        "source_agent": source_agent,
        "edoc_id": edoc_id,
        "controllers": list(controllers),
    }


def _validate_edocs_claims(claims: dict, *, require_full_args: bool = False) -> None:
    if not any(name in claims for name in _EDOC_CLAIMS):
        return
    if not all(name in claims for name in _EDOC_CLAIMS):
        raise AAuthError(INVALID_TOKEN, detail="token has an incomplete eDocs claim group")
    if not isinstance(claims["controllers"], list):
        raise AAuthError(INVALID_TOKEN, detail="token controllers claim must be a JSON list")
    try:
        _edocs_claims(claims["source_agent"], claims["edoc_id"], claims["controllers"])
        _validate_function_args_hash(claims["function_args_hash"])
    except ValueError as error:
        raise AAuthError(INVALID_TOKEN, detail=f"invalid eDocs claims: {error}") from error
    if require_full_args:
        arguments = claims.get("function_args")
        if not isinstance(arguments, dict):
            raise AAuthError(
                INVALID_TOKEN,
                detail="eDocs resource token function_args must be a JSON object",
            )
        try:
            actual = hash_function_args(arguments)
        except ValueError as error:
            raise AAuthError(
                INVALID_TOKEN, detail=f"invalid function_args: {error}"
            ) from error
        if actual != claims["function_args_hash"]:
            raise AAuthError(
                INVALID_TOKEN,
                detail="resource token function_args_hash does not match function_args",
            )


def _check_edocs_bindings(
    claims: dict,
    source_agent: str | None,
    scope: str | None,
    edoc_id: str | None,
    controllers: list[str] | tuple[str, ...] | None,
    function_args_hash: str | None,
) -> None:
    expected = {
        "source_agent": source_agent,
        "scope": scope,
        "edoc_id": edoc_id,
        "controllers": list(controllers) if controllers is not None else None,
        "function_args_hash": function_args_hash,
    }
    for name, value in expected.items():
        if value is not None and claims.get(name) != value:
            raise AAuthError(INVALID_TOKEN, detail=f"token {name} mismatch")


def _validate_function_args_hash(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
    ):
        raise ValueError("function_args_hash must be a sha256 digest")
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError as error:
        raise ValueError("function_args_hash must be a sha256 digest") from error
    return value
