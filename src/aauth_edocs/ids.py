"""Agent identifiers and well-known document names.

Agent identifiers are ``aauth:local@domain`` URIs (§5.1). Internal-
experimentation scope: split and non-empty checks only — no charset/IDN/
https pedantry, exact string comparison throughout.
"""

from __future__ import annotations

# Well-known metadata document names (§12.10) — also used as `dwk` claims.
DWK_AGENT = "aauth-agent.json"
DWK_PERSON = "aauth-person.json"
DWK_ACCESS = "aauth-access.json"
DWK_RESOURCE = "aauth-resource.json"


def agent_id(local: str, domain: str) -> str:
    return f"aauth:{local}@{domain}"


def parse_agent_id(identifier: str) -> tuple[str, str]:
    """Return (local, domain); raise ValueError if not aauth:local@domain."""
    if not identifier.startswith("aauth:"):
        raise ValueError(f"not an aauth: identifier: {identifier!r}")
    local, sep, domain = identifier[len("aauth:"):].partition("@")
    if not sep or not local or not domain:
        raise ValueError(f"malformed agent identifier: {identifier!r}")
    return local, domain


def well_known_url(issuer: str, dwk: str) -> str:
    return f"{issuer.rstrip('/')}/.well-known/{dwk}"
