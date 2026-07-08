"""AAuth HTTP headers (§12.1, §12.3.1, §6.4, §8.7).

Builders format the (simple) structured-field shapes directly; parsers use
http-sfv so we accept anything another implementation emits.
"""

from __future__ import annotations

from dataclasses import dataclass

from http_sfv import Dictionary, List

from .errors import AAuthError, INVALID_REQUEST

REQUIREMENT_HEADER = "AAuth-Requirement"
MISSION_HEADER = "AAuth-Mission"
CAPABILITIES_HEADER = "AAuth-Capabilities"
ACCESS_HEADER = "AAuth-Access"

# Requirement values (§12.3.2 Table 8)
AGENT_TOKEN = "agent-token"
AUTH_TOKEN = "auth-token"
INTERACTION = "interaction"
APPROVAL = "approval"
CLARIFICATION = "clarification"
CLAIMS = "claims"


def build_requirement(requirement: str, **params: str) -> str:
    """e.g. requirement=auth-token; resource-token="eyJ..." """
    parts = [f"requirement={requirement}"]
    for name, value in params.items():
        parts.append(f'{name.replace("_", "-")}="{value}"')
    return ";".join(parts)


def parse_requirement(value: str) -> tuple[str, dict]:
    """Return (requirement, params). Unknown params pass through (§12.3.1)."""
    d = Dictionary()
    try:
        d.parse(value.encode())
        member = d["requirement"]
        requirement = str(member.value)
        params = {str(k): _plain(v) for k, v in member.params.items()}
    except (KeyError, ValueError) as e:
        raise AAuthError(INVALID_REQUEST, detail=f"bad AAuth-Requirement: {e}")
    return requirement, params


@dataclass(frozen=True)
class MissionRef:
    """The {approver, s256} mission reference (§8.7) — never the blob."""

    approver: str
    s256: str

    def to_header(self) -> str:
        return f'approver="{self.approver}";s256="{self.s256}"'

    def to_claim(self) -> dict:
        return {"approver": self.approver, "s256": self.s256}

    @classmethod
    def from_header(cls, value: str) -> "MissionRef":
        # The spec's example wire form (§8.7) separates with ';', which SF
        # parses as a parameter on the approver member; a ','-separated form
        # parses as two members. Accept both.
        d = Dictionary()
        try:
            d.parse(value.encode())
            member = d["approver"]
            if "s256" in d:
                s256 = str(d["s256"].value)
            else:
                s256 = str(member.params["s256"])
            return cls(approver=str(member.value), s256=s256)
        except (KeyError, ValueError) as e:
            raise AAuthError(INVALID_REQUEST, detail=f"bad AAuth-Mission: {e}")

    @classmethod
    def from_claim(cls, claim: dict) -> "MissionRef":
        return cls(approver=claim["approver"], s256=claim["s256"])


def build_capabilities(values: list[str]) -> str:
    return ", ".join(values)


def parse_capabilities(value: str) -> list[str]:
    lst = List()
    lst.parse(value.encode())
    return [str(item.value) for item in lst]


def build_authorization(access_token: str) -> str:
    """Authorization header value for an AAuth-Access opaque token (§6.4)."""
    return f"AAuth {access_token}"


def parse_authorization(value: str) -> str:
    scheme, _, token = value.partition(" ")
    if scheme != "AAuth" or not token.strip():
        raise AAuthError(INVALID_REQUEST, detail="not an AAuth authorization")
    return token.strip()


def _plain(value):
    """Unwrap http-sfv value types to plain str/int/bytes."""
    return str(value) if type(value).__name__ == "Token" else value
