"""Identity-based access demo (§4.1.1) over real localhost HTTP.

Runs an Agent Provider (:5001) and a Resource (:5002), then:
  1. calls the protected endpoint unsigned  -> 401 + requirement=agent-token
  2. enrolls agent A and calls signed       -> 200, identity recognized
  3. enrolls agent B (not on the allowlist) -> 403 from the resource's ACL

Run: uv run python demo/01_identity_based.py
"""

import logging
import threading
import time
import warnings

warnings.filterwarnings("ignore", message="EdDSA is deprecated")  # we match other AAuth impls

import requests
from flask import Flask, g

from aauth_edocs import (
    AgentSession,
    JwksResolver,
    RequestsTransport,
    create_ap,
    install_metadata,
    require_aauth_identity,
)

AP_URL = "http://127.0.0.1:5001"
RESOURCE_URL = "http://127.0.0.1:5002"
ALLOWED_AGENT = "aauth:assistant@127.0.0.1:5001"

logging.getLogger("werkzeug").setLevel(logging.ERROR)


def make_resource() -> Flask:
    app = Flask(__name__)
    install_metadata(app, RESOURCE_URL)
    resolver = JwksResolver(RequestsTransport())

    @app.get("/api/whoami")
    @require_aauth_identity(resolver)
    def whoami():
        agent = g.aauth.claims["sub"]
        if agent != ALLOWED_AGENT:  # access control by agent identity
            return {"error": "denied", "detail": f"{agent} is not allowed"}, 403
        return {"agent": agent, "message": "hello, recognized agent"}

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
    wait_for(f"{AP_URL}/.well-known/aauth-agent.json")
    wait_for(f"{RESOURCE_URL}/.well-known/aauth-resource.json")
    print(f"AP up at {AP_URL}, resource up at {RESOURCE_URL}\n")

    print("1) unsigned request:")
    r = requests.get(f"{RESOURCE_URL}/api/whoami")
    print(f"   -> {r.status_code} {r.json()}")
    print(f"   -> AAuth-Requirement: {r.headers.get('AAuth-Requirement')}\n")

    print("2) enroll agent A and call signed:")
    agent_a = AgentSession.enroll(AP_URL, "assistant")
    print(f"   enrolled as {agent_a.agent_id}")
    r = agent_a.get(f"{RESOURCE_URL}/api/whoami")
    print(f"   -> {r.status_code} {r.json()}\n")

    print("3) enroll agent B (not allowlisted) and call signed:")
    agent_b = AgentSession.enroll(AP_URL, "intruder")
    r = agent_b.get(f"{RESOURCE_URL}/api/whoami")
    print(f"   -> {r.status_code} {r.json()}\n")

    assert r.status_code == 403
    print("demo complete: identity verified cryptographically, access decided by agent id")


if __name__ == "__main__":
    main()
