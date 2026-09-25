import pytest

from aauth_edocs import Allow, Deny, PolicyVerdict, RuleEngine, parse_dataflow
from aauth_edocs.asrv import create_as

AS = "http://controller.local"
SENTINEL = "http://sentinel.local"


def _flow(document="doc-1", **changes):
    value = {
        "source": "aauth:source@ap.local",
        "function": "identity@1",
        "document": document,
        "destination": "aauth:assistant@ap.local",
        "function_args": {},
    }
    value.update(changes)
    return value


class _DenyingEnforcer:
    def judge(self, question):
        return PolicyVerdict(False, "not satisfied")


class _EvaluateOnly:
    def evaluate(self, proposal):
        return Deny("evaluate-only engine")


def _policy_target(document="doc-1", policy="Only aggregates are allowed"):
    return {
        "source": "aauth:source@ap.local",
        "policy": policy,
        "document": document,
        "destination": "aauth:assistant@ap.local",
    }


@pytest.fixture
def engine():
    return RuleEngine(enforcer=_DenyingEnforcer())


@pytest.fixture
def client(engine):
    return create_as(AS, sentinel=SENTINEL, rule_engine=engine).test_client()


def _create(client, target, prerequisite=None):
    response = client.post("/rules", json={"target": target, "prerequisite": prerequisite})
    assert response.status_code == 201
    return response.get_json()["rule"]


def test_create_assigns_id_and_registers_with_engine(client, engine):
    rule = _create(client, _flow())

    assert rule["rule_id"]
    assert rule["target"] == _flow()
    assert rule["prerequisite"] is None
    assert isinstance(engine.evaluate(parse_dataflow(_flow())), Allow)


def test_create_policy_rule_round_trips(client, engine):
    rule = _create(client, _policy_target())

    assert rule["target"] == _policy_target()
    assert engine.get_rule(rule["rule_id"]).rule.function.text == "Only aggregates are allowed"


@pytest.mark.parametrize(
    "target",
    [
        {**_policy_target(), "function": "identity@1"},
        {**_policy_target(), "function_args": {}},
        _policy_target(policy="  "),
    ],
)
def test_create_rejects_malformed_policy_targets(client, target):
    response = client.post("/rules", json={"target": target})
    assert response.status_code == 400


def test_policy_rules_require_an_enforcer():
    client = create_as(AS, sentinel=SENTINEL, rule_engine=RuleEngine()).test_client()

    response = client.post("/rules", json={"target": _policy_target()})
    assert response.status_code == 409
    assert "policy enforcer" in response.get_json()["detail"]


def test_create_accepts_prerequisite_and_omitted_prerequisite(client):
    with_prerequisite = _create(client, _flow(), _flow("doc-0"))
    omitted = client.post("/rules", json={"target": _flow("doc-2")})

    assert with_prerequisite["prerequisite"] == _flow("doc-0")
    assert omitted.status_code == 201
    assert omitted.get_json()["rule"]["prerequisite"] is None


@pytest.mark.parametrize(
    "body",
    [None, [], {}, {"target": _flow(), "extra": 1}, {"target": {"source": "x"}}],
)
def test_create_rejects_malformed_bodies(client, body):
    response = client.post("/rules", json=body)
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_request"


def test_create_rejects_duplicate_target(client):
    _create(client, _flow())
    assert client.post("/rules", json={"target": _flow()}).status_code == 409


def test_list_and_filter_by_edoc(client):
    direct = _create(client, _flow("doc-1"))
    other = _create(client, _flow("doc-2"))
    derived = _create(client, _flow({"output_of": _flow("doc-1")}))

    listed = client.get("/rules").get_json()["rules"]
    assert {rule["rule_id"] for rule in listed} == {direct["rule_id"], other["rule_id"], derived["rule_id"]}

    filtered = client.get("/rules?edoc_id=doc-1").get_json()["rules"]
    assert {rule["rule_id"] for rule in filtered} == {direct["rule_id"], derived["rule_id"]}
    assert client.get("/rules?edoc_id=missing").get_json()["rules"] == []


def test_get_replace_delete(client, engine):
    rule_id = _create(client, _flow())["rule_id"]

    assert client.get(f"/rules/{rule_id}").get_json()["rule"]["rule_id"] == rule_id

    replacement = _flow(function_args={"x": 1})
    replaced = client.put(f"/rules/{rule_id}", json={"target": replacement})
    assert replaced.status_code == 200
    assert replaced.get_json()["rule"] == {"rule_id": rule_id, "target": replacement, "prerequisite": None}
    assert isinstance(engine.evaluate(parse_dataflow(_flow())), Deny)

    assert client.delete(f"/rules/{rule_id}").status_code == 204
    assert engine.list_rules() == ()
    assert client.get(f"/rules/{rule_id}").status_code == 404


def test_unknown_rule_id_returns_404(client):
    assert client.get("/rules/nope").status_code == 404
    assert client.put("/rules/nope", json={"target": _flow()}).status_code == 404
    assert client.delete("/rules/nope").status_code == 404


def test_replace_rejects_target_owned_by_another_rule(client):
    _create(client, _flow("doc-1"))
    second = _create(client, _flow("doc-2"))

    response = client.put(f"/rules/{second['rule_id']}", json={"target": _flow("doc-1")})
    assert response.status_code == 409


@pytest.mark.parametrize("kwargs", [{}, {"sentinel": SENTINEL, "rule_engine": _EvaluateOnly()}])
def test_rules_unavailable_without_mutable_engine(kwargs):
    client = create_as(AS, **kwargs).test_client()

    assert client.get("/rules").status_code == 404
    assert client.post("/rules", json={"target": _flow()}).status_code == 404
