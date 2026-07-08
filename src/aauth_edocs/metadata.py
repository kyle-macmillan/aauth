"""Well-known metadata documents and key discovery (§12.10, §12.8-lite).

A metadata document is just a dict published at {issuer}/.well-known/{dwk}.
`JwksResolver` implements the KeyResolver seam used by httpsig/tokens:
metadata -> jwks_uri -> key by kid, with a simple dict cache (the spec's
full caching policy is intentionally skipped for internal experimentation).
"""

from __future__ import annotations

from .errors import AAuthError, INVALID_TOKEN, SERVER_ERROR
from .ids import well_known_url


class Metadata(dict):
    """A well-known metadata document. A dict with convenience accessors."""

    @property
    def issuer(self) -> str:
        return self["issuer"]

    @property
    def jwks_uri(self) -> str | None:
        return self.get("jwks_uri")

    def endpoint(self, name: str) -> str | None:
        return self.get(name)


def build_metadata(issuer: str, jwks_uri: str | None = None, **fields) -> Metadata:
    md = Metadata(issuer=issuer)
    if jwks_uri:
        md["jwks_uri"] = jwks_uri
    md.update({k: v for k, v in fields.items() if v is not None})
    return md


def fetch_metadata(issuer: str, dwk: str, transport) -> Metadata:
    """GET {issuer}/.well-known/{dwk}. Keeps the one cheap high-value check:
    the document's issuer must match where we fetched it from (§12.10)."""
    url = well_known_url(issuer, dwk)
    response = transport.get(url)
    if response.status_code != 200:
        raise AAuthError(SERVER_ERROR, 502, f"metadata fetch failed: {url} -> {response.status_code}")
    md = Metadata(response.json())
    if md.get("issuer") != issuer:
        raise AAuthError(INVALID_TOKEN, detail=f"metadata issuer {md.get('issuer')!r} != {issuer!r}")
    return md


class JwksResolver:
    """KeyResolver backed by well-known metadata + JWKS over HTTP.

    `transport` is anything requests.Session-compatible (.get -> response
    with .status_code / .json()).
    """

    def __init__(self, transport):
        self._transport = transport
        self._keys: dict[tuple[str, str], dict] = {}  # (jwks_uri, kid) -> jwk

    def __call__(self, iss: str, dwk: str, kid: str) -> dict:
        md = fetch_metadata(iss, dwk, self._transport)
        if not md.jwks_uri:
            raise AAuthError(INVALID_TOKEN, detail=f"{iss} metadata has no jwks_uri")
        cached = self._keys.get((md.jwks_uri, kid))
        if cached is not None:
            return cached
        response = self._transport.get(md.jwks_uri)
        if response.status_code != 200:
            raise AAuthError(SERVER_ERROR, 502, f"JWKS fetch failed: {md.jwks_uri}")
        for jwk in response.json().get("keys", []):
            self._keys[(md.jwks_uri, jwk.get("kid"))] = jwk
        key = self._keys.get((md.jwks_uri, kid))
        if key is None:
            raise AAuthError(INVALID_TOKEN, detail=f"kid {kid!r} not in {md.jwks_uri}")
        return key


def static_resolver(keys: dict[str, dict]):
    """KeyResolver from a plain {issuer: public_jwk} dict — for tests and
    in-process wiring where nothing is served over HTTP."""

    def resolve(iss: str, dwk: str, kid: str) -> dict:
        try:
            return keys[iss]
        except KeyError:
            raise AAuthError(INVALID_TOKEN, detail=f"unknown issuer {iss!r}")

    return resolve
