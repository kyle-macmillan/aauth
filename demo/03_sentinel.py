"""Four-party (federated) access demo (§4.1.4, §9) over real localhost HTTP.

Runs AP (:5001), Resource (:5002), PS (:5003), sentinel (:5005) and AS (:5004), then:
  1. calls the protected endpoint unsigned  -> 401 + requirement=agent-token
  2. enrolls an agent bound to the PS
  3. authorize: resource token -> PS federates to sentinel -> AS -> auth token
  4. presents the auth token to the resource -> 200

The agent never talks to the AS or sentinel; federation is invisible to it (§13.1.1).

Run: uv run python demo/03_sentinel.py
"""

import logging
import threading
import time
import warnings

warnings.filterwarnings("ignore", message="EdDSA is deprecated")  # we match other AAuth impls

import requests
from flask import Flask, g, request

from aauth_edocs import (
    AgentSession,
    JwksResolver,
    ResourceConfig,
    RequestsTransport,
    SigningKey,
    create_ap,
    create_as,
    create_ps,
    create_sentinel,
    install_resource,
    peek_jwt,
    require_auth_token,
)

AP_URL = "http://127.0.0.1:5001"
RESOURCE_URL = "http://127.0.0.1:5002"
PS_URL = "http://127.0.0.1:5003"
AS_URL = "http://127.0.0.1:5004"
SENTINEL_URL = "http://127.0.0.1:5005"

PARTY_NAMES = {
    AP_URL: "AP",
    RESOURCE_URL: "Resource",
    PS_URL: "PS",
    AS_URL: "AS",
    SENTINEL_URL: "Sentinel",
}


def fmt_url(url: str | None) -> str:
    if not url:
        return "None"
    name = PARTY_NAMES.get(url)
    return f"{url} ({name})" if name else url

logging.getLogger("werkzeug").setLevel(logging.ERROR)


def make_resource() -> Flask:
    transport = RequestsTransport()
    config = ResourceConfig(
        issuer=RESOURCE_URL,
        key=SigningKey.generate(kid="res"),
        key_resolver=JwksResolver(transport),
        as_url=SENTINEL_URL,  # grant audience: resource token aud is the sentinel
        controller_url=AS_URL,  # controller AS the sentinel forwards to
        default_scope="docs.read",
    )
    app = Flask(__name__)
    install_resource(app, config)

    @app.get("/api/data")
    @require_auth_token(config, scope="docs.read")
    def data():
        claims = peek_jwt(g.aauth.token)[1]
        return {
            "iss": claims["iss"],
            "dwk": claims["dwk"],
            "scope": claims["scope"],
            "sub": claims.get("sub"),
        }

    return app


def as_policy(ps_url, agent_claims, rt_claims):
    """Grant only *.read scopes from whatever the resource token requested."""
    readable = [s for s in rt_claims.get("scope", "").split() if s.endswith(".read")]
    return " ".join(readable) or None


def checkpoint(app: Flask, label: str) -> Flask:
    """Print enter/exit on POST /token so the PS -> sentinel -> AS hop is visible."""

    @app.before_request
    def _enter():
        if request.method != "POST" or request.path != "/token":
            return
        body = request.get_json(silent=True) or {}
        parts = [f"  [{label}] POST /token"]
        if rt := body.get("resource_token"):
            _, rt_claims = peek_jwt(rt)
            parts.append(
                f"    resource_token:\n      iss={fmt_url(rt_claims.get('iss'))}"
                f"\n      aud={fmt_url(rt_claims.get('aud'))}"
                f"\n      controller={fmt_url(rt_claims.get('controller'))}"
                f"\n      scope={rt_claims.get('scope')}"
            )
        if at := body.get("agent_token"):
            _, agent_claims = peek_jwt(at)
            parts.append(
                f"    agent_token:\n      iss={fmt_url(agent_claims.get('iss'))}"
                f"\n      sub={agent_claims.get('sub')}"
            )
        print("\n".join(parts), flush=True)

    @app.after_request
    def _leave(response):
        if request.method == "POST" and request.path == "/token":
            detail = ""
            if response.status_code == 200 and response.is_json:
                body = response.get_json(silent=True) or {}
                if "auth_token" in body:
                    _, claims = peek_jwt(body["auth_token"])
                    detail = (
                        f" auth_token:\n      iss={fmt_url(claims.get('iss'))}"
                        f"\n      aud={fmt_url(claims.get('aud'))}"
                        f"\n      scope={claims.get('scope')}"
                    )
            print(f"  [{label}] -> {response.status_code}{detail}", flush=True)
        return response

    return app


def serve(app: Flask, port: int) -> None:
    threading.Thread(
        target=lambda: app.run(port=port, use_reloader=False), daemon=True
    ).start()


def wait_for(url: str) -> None:
    for _ in range(50):
        try:
            requests.get(url, timeout=0.2)
            return
        except requests.ConnectionError:
            time.sleep(0.1)
    raise RuntimeError(f"server at {url} did not come up")


def main() -> None:
    serve(create_ap(AP_URL), 5001)
    serve(make_resource(), 5002)
    serve(checkpoint(create_ps(PS_URL), "PS"), 5003)
    serve(checkpoint(create_as(AS_URL, policy=as_policy), "AS"), 5004)
    serve(checkpoint(create_sentinel(SENTINEL_URL), "sentinel"), 5005)

    wait_for(f"{AP_URL}/.well-known/aauth-agent.json")
    wait_for(f"{RESOURCE_URL}/.well-known/aauth-resource.json")
    wait_for(f"{PS_URL}/.well-known/aauth-person.json")
    wait_for(f"{AS_URL}/.well-known/aauth-access.json")
    wait_for(f"{SENTINEL_URL}/.well-known/aauth-sentinel.json")
    print(f"AP {AP_URL}")
    print(f"Resource {RESOURCE_URL}")
    print(f"PS {PS_URL}")
    print(f"AS {AS_URL}")
    print(f"Sentinel {SENTINEL_URL}\n")

    print("1) unsigned request:")
    r = requests.get(f"{RESOURCE_URL}/api/data")
    print(f"   -> {r.status_code} {r.json()}")
    print(f"   -> AAuth-Requirement: {r.headers.get('AAuth-Requirement')}\n")

    print("2) enroll agent (ps=PS):")
    agent = AgentSession.enroll(AP_URL, "assistant", ps=PS_URL)
    print(f"   enrolled as {agent.agent_id}\n")

    print("3) create auth token (resource /authorize -> PS -> sentinel -> AS):")
    auth_token = agent.authorize(RESOURCE_URL, "docs.read")
    _, claims = peek_jwt(auth_token)
    print(f"   (agent) got auth token iss={claims['iss']} aud={claims['aud']} scope={claims['scope']}")
    print(f"   (agent) sub present? {'sub' in claims}\n")
    assert claims["iss"] == SENTINEL_URL
    assert claims["aud"] == RESOURCE_URL
    assert claims["scope"] == "docs.read"
    assert "sub" not in claims  # scope-only auth token (§9.4.1)

    print("4) present auth token to resource:")
    r = agent.get(f"{RESOURCE_URL}/api/data")
    print(f"   -> {r.status_code} {r.json()}\n")
    assert r.status_code == 200
    body = r.json()
    assert body["iss"] == SENTINEL_URL
    assert body["dwk"] == "aauth-sentinel.json"
    assert body["scope"] == "docs.read"
    assert body["sub"] is None

    print("demo complete: four-party federation via PS -> sentinel -> AS over real HTTP")


if __name__ == "__main__":
    main()
