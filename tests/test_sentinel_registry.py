"""Registry HTTP API on create_sentinel."""

from aauth_edocs import (
    Dataflow,
    FunctionDescriptor,
    ResourceBinding,
    SentinelRegistry,
    SigningKey,
    create_sentinel,
    serialize_dataflow,
)


SENTINEL = "http://sentinel.local"
SOURCE = "aauth:source@ap.local"
DESTINATION = "aauth:producer@demo.local"
AS = "http://as.local"
RESOURCE = "http://resource.local"
PS = "http://ps.local"


def _seeded_registry():
    """A registry where SOURCE serves origin eDoc doc_1, controlled by AS."""
    return SentinelRegistry(
        resource_bindings={
            SOURCE: ResourceBinding(
                source_ps=PS,
                resource_issuer=RESOURCE,
                resource_jkt="jkt-1",
            )
        },
        controllers={(RESOURCE, "doc_1"): (AS,)},
    )


def _client(registry=None, on_function_register=None):
    registry = registry or _seeded_registry()
    app = create_sentinel(
        issuer=SENTINEL,
        registry=registry,
        key=SigningKey.generate("sentinel"),
        on_function_register=on_function_register,
    )
    app.config["TESTING"] = True
    return app.test_client(), registry


def test_materialize_get_derived_and_publish_controllers():
    client, registry = _client()
    producer = Dataflow.from_arguments(
        SOURCE,
        "query_table@1",
        "doc_1",
        DESTINATION,
        {"statement": "SELECT 1", "parameters": []},
    )
    output = {"rows": [{"name": "Ada"}]}
    created = client.post(
        "/registry/materializations",
        json={
            "dataflow": serialize_dataflow(producer),
            "output": output,
        },
    )
    assert created.status_code == 201
    body = created.get_json()
    edoc_id = body["derived_edoc_id"]
    assert body["possessor"] == DESTINATION
    assert edoc_id in registry.derived_documents
    assert registry.derived_outputs[edoc_id] == output
    assert edoc_id not in registry.published_derived

    missing = client.get("/registry/derived/unknown")
    assert missing.status_code == 404

    derived = client.get(f"/registry/derived/{edoc_id}")
    assert derived.status_code == 200
    derived_body = derived.get_json()
    assert derived_body["possessor"] == DESTINATION
    assert derived_body["controllers"] == [AS]
    assert derived_body["output"] == output
    assert derived_body["published"] is False

    published = client.post(
        "/registry/controllers",
        json={
            "resource_issuer": RESOURCE,
            "edoc_id": edoc_id,
            "controllers": [AS],
        },
    )
    assert published.status_code == 201
    assert edoc_id in registry.published_derived
    assert registry.controllers[(RESOURCE, edoc_id)] == (AS,)

    again = client.get(f"/registry/derived/{edoc_id}")
    assert again.get_json()["published"] is True


def test_origin_registration_is_idempotent_and_rejects_conflicts():
    client, registry = _client(SentinelRegistry())
    payload = {"resource_issuer": RESOURCE, "edoc_id": "doc_2", "controllers": [AS]}

    first = client.post("/registry/origins", json=payload)
    again = client.post("/registry/origins", json=payload)
    conflict = client.post(
        "/registry/origins",
        json={**payload, "controllers": ["http://other-as.local"]},
    )
    empty = client.post("/registry/origins", json={**payload, "edoc_id": "doc_3", "controllers": []})

    assert first.status_code == 201
    assert first.get_json()["origin"]["controllers"] == [AS]
    assert again.status_code == 201
    assert conflict.status_code == 400
    assert empty.status_code == 400
    assert registry.controllers == {(RESOURCE, "doc_2"): (AS,)}


def test_derived_edocs_cannot_be_registered_as_origins():
    client, registry = _client()
    created = client.post(
        "/registry/materializations",
        json={
            "dataflow": serialize_dataflow(
                Dataflow.from_arguments(SOURCE, "identity@1", "doc_1", DESTINATION, {})
            ),
            "output": {"ok": True},
        },
    )
    edoc_id = created.get_json()["derived_edoc_id"]

    response = client.post(
        "/registry/origins",
        json={"resource_issuer": RESOURCE, "edoc_id": edoc_id, "controllers": ["http://other-as.local"]},
    )

    assert response.status_code == 400
    assert "derived" in response.get_json()["detail"]
    assert (RESOURCE, edoc_id) not in registry.controllers


def test_publish_accepts_only_derived_edocs_with_inherited_controllers():
    client, registry = _client()
    created = client.post(
        "/registry/materializations",
        json={
            "dataflow": serialize_dataflow(
                Dataflow.from_arguments(SOURCE, "identity@1", "doc_1", DESTINATION, {})
            ),
            "output": {"ok": True},
        },
    )
    edoc_id = created.get_json()["derived_edoc_id"]

    origin = client.post(
        "/registry/controllers",
        json={"resource_issuer": RESOURCE, "edoc_id": "doc_9", "controllers": [AS]},
    )
    wrong = client.post(
        "/registry/controllers",
        json={"resource_issuer": RESOURCE, "edoc_id": edoc_id, "controllers": ["http://other-as.local"]},
    )

    assert origin.status_code == 400
    assert "/registry/origins" in origin.get_json()["detail"]
    assert wrong.status_code == 400
    assert (RESOURCE, "doc_9") not in registry.controllers
    assert edoc_id not in registry.published_derived


def test_materialization_requires_controlled_input_and_ignores_caller_controllers():
    client, registry = _client()
    unknown = client.post(
        "/registry/materializations",
        json={
            "dataflow": serialize_dataflow(
                Dataflow.from_arguments(SOURCE, "identity@1", "doc_unregistered", DESTINATION, {})
            ),
            "output": {"ok": True},
        },
    )
    with_controllers = client.post(
        "/registry/materializations",
        json={
            "dataflow": serialize_dataflow(
                Dataflow.from_arguments(SOURCE, "identity@1", "doc_1", DESTINATION, {})
            ),
            "output": {"ok": True},
            "controllers": ["http://other-as.local"],
        },
    )

    assert unknown.status_code == 400
    assert "no registered controllers" in unknown.get_json()["detail"]
    assert with_controllers.status_code == 400
    assert registry.derived_documents == {}


def test_registry_state_reports_manual_registration():
    client, _ = _client()

    assert client.get("/registry").get_json()["manual_registration"] is True


def test_binding_idempotent_and_rejects_conflict():
    client, registry = _client()
    payload = {
        "source_agent": SOURCE,
        "source_ps": PS,
        "resource_issuer": RESOURCE,
        "resource_jkt": "jkt-1",
    }
    first = client.post("/registry/bindings", json=payload)
    assert first.status_code == 201
    second = client.post("/registry/bindings", json=payload)
    assert second.status_code == 201
    assert SOURCE in registry.resource_bindings

    conflict = client.post(
        "/registry/bindings",
        json={**payload, "resource_jkt": "jkt-2"},
    )
    assert conflict.status_code == 400


def test_function_list_and_register_callback():
    def on_register(body):
        return FunctionDescriptor(
            id=body["function_id"],
            description=body["description"],
            implementation_uri="local://demo",
            digest="sha256:abc",
            input_schema=body["input_schema"],
        )

    client, registry = _client(on_function_register=on_register)
    empty = client.get("/registry/functions")
    assert empty.status_code == 200
    assert empty.get_json()["functions"] == []

    created = client.post(
        "/registry/functions",
        json={
            "function_id": "demo_fn@1",
            "description": "demo",
            "input_schema": {"type": "object"},
            "implementation": {"runtime": "sql", "source": "SELECT 1"},
        },
    )
    assert created.status_code == 201
    assert "demo_fn@1" in registry.functions

    listed = client.get("/registry/functions")
    assert listed.get_json()["functions"] == [
        {
            "function_id": "demo_fn@1",
            "description": "demo",
            "input_schema": {"type": "object"},
            "digest": "sha256:abc",
        }
    ]


def test_registry_state_dump_includes_published_flag():
    client, registry = _client()
    producer = Dataflow.from_arguments(
        SOURCE,
        "identity@1",
        "doc_1",
        DESTINATION,
        {},
    )
    created = client.post(
        "/registry/materializations",
        json={
            "dataflow": serialize_dataflow(producer),
            "output": {"ok": True},
        },
    )
    edoc_id = created.get_json()["derived_edoc_id"]
    state = client.get("/registry")
    assert state.status_code == 200
    derived = state.get_json()["derived_documents"]
    assert len(derived) == 1
    assert derived[0]["edoc_id"] == edoc_id
    assert derived[0]["published"] is False
    assert edoc_id in registry.derived_outputs


def test_transform_records_source_equals_destination():
    def execute(function_id, output, function_args):
        assert function_id == "count_names@1"
        assert function_args == {}
        return {
            "columns": ["employee_count"],
            "rows": [{"employee_count": len(output["rows"])}],
            "truncated": False,
        }

    registry = _seeded_registry()
    registry.functions["count_names@1"] = FunctionDescriptor(
        id="count_names@1",
        description="count",
        implementation_uri="demo://count",
        digest="sha256:abc",
    )
    app = create_sentinel(
        issuer=SENTINEL,
        registry=registry,
        key=SigningKey.generate("sentinel"),
        execute_function=execute,
    )
    app.config["TESTING"] = True
    client = app.test_client()

    created = client.post(
        "/registry/materializations",
        json={
            "dataflow": serialize_dataflow(
                Dataflow.from_arguments(
                    SOURCE,
                    "query_table@1",
                    "doc_1",
                    DESTINATION,
                    {"statement": "SELECT 1", "parameters": []},
                )
            ),
            "output": {
                "columns": ["name"],
                "rows": [{"name": "Ada"}, {"name": "Bob"}],
                "truncated": False,
            },
        },
    )
    assert created.status_code == 201
    input_id = created.get_json()["derived_edoc_id"]

    denied = client.post(
        f"/registry/derived/{input_id}/transform",
        json={
            "possessor": "aauth:other@demo.local",
            "function_id": "count_names@1",
            "function_args": {},
        },
    )
    assert denied.status_code == 403

    unknown_fn = client.post(
        f"/registry/derived/{input_id}/transform",
        json={
            "possessor": DESTINATION,
            "function_id": "missing@1",
            "function_args": {},
        },
    )
    assert unknown_fn.status_code == 404

    transformed = client.post(
        f"/registry/derived/{input_id}/transform",
        json={
            "possessor": DESTINATION,
            "function_id": "count_names@1",
            "function_args": {},
        },
    )
    assert transformed.status_code == 201
    body = transformed.get_json()
    new_id = body["derived_edoc_id"]
    assert new_id != input_id
    assert body["possessor"] == DESTINATION
    assert body["controllers"] == [AS]
    assert body["output"]["rows"] == [{"employee_count": 2}]

    derived = registry.derived_documents[new_id]
    assert derived.dataflow.source == DESTINATION
    assert derived.dataflow.destination == DESTINATION
    assert derived.dataflow.function == "count_names@1"
    assert derived.dataflow.document == input_id
    assert derived.possessor == DESTINATION
    assert new_id in registry.derived_outputs
    assert input_id not in registry.published_derived
    assert new_id not in registry.published_derived
