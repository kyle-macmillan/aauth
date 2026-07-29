"""In-process Sentinel aggregation for the eDocs demo."""

from __future__ import annotations

import time
from typing import Any, Callable

from flask import Flask, jsonify, request

from .agent import RequestsTransport
from .edocs import (
    Dataflow,
    FunctionDescriptor,
    ResourceBinding,
    SentinelRegistry,
    register_materialization,
)
from .errors import AAuthError, DENIED, INVALID_REQUEST, INVALID_TOKEN, SERVER_ERROR
from .httpsig import HttpRequest, KeyResolver, peek_jwt, sign_server, verify
from .ids import DWK_ACCESS, DWK_PERSON
from .keys import SigningKey, jwk_thumbprint
from .metadata import JwksResolver, build_metadata, fetch_metadata
from .policy_json import parse_dataflow, serialize_dataflow
from .tokens import (
    AUTH_TYP,
    CONDITIONAL_AUTH_TYP,
    issue_auth_token,
    verify_agent_token,
    verify_auth_token,
    verify_conditional_auth_token,
    verify_resource_token,
)

Now = Callable[[], float]
FunctionRegister = Callable[[dict[str, Any]], Any]
ExecuteFunction = Callable[[str, dict[str, Any], dict[str, Any]], dict[str, Any]]


def create_sentinel(
    *,
    issuer: str,
    registry: SentinelRegistry,
    key: SigningKey | None = None,
    transport=None,
    app: Flask | None = None,
    token_path: str = "/token",
    jwks_path: str = "/jwks.json",
    on_function_register: FunctionRegister | None = None,
    execute_function: ExecuteFunction | None = None,
) -> Flask:
    """Create the Sentinel's AS-facing, PS-facing, and registry HTTP adapter."""
    app = app or Flask("aauth-sentinel")
    key = key or SigningKey.generate(kid="sentinel")
    transport = transport or RequestsTransport()
    resolver = JwksResolver(transport)
    app.extensions["aauth_sentinel"] = {
        "issuer": issuer,
        "key": key,
        "registry": registry,
    }

    @app.errorhandler(AAuthError)
    def aauth_error(error: AAuthError):
        return error.body(), error.status

    @app.errorhandler(LookupError)
    def not_found(error):
        return jsonify(error="not_found", detail=str(error)), 404

    @app.errorhandler(PermissionError)
    def forbidden(error):
        return jsonify(error="forbidden", detail=str(error)), 403

    @app.errorhandler(ValueError)
    @app.errorhandler(TypeError)
    def invalid_request(error):
        return jsonify(error="invalid_request", detail=str(error)), 400

    @app.get("/.well-known/aauth-access.json")
    def access_metadata():
        return dict(
            build_metadata(
                issuer,
                jwks_uri=f"{issuer}{jwks_path}",
                token_endpoint=f"{issuer}{token_path}",
                name="aauth-edocs demo Sentinel",
            )
        )

    @app.get("/.well-known/aauth-person.json")
    def person_metadata():
        return dict(
            build_metadata(
                issuer,
                jwks_uri=f"{issuer}{jwks_path}",
                token_endpoint=f"{issuer}{token_path}",
                name="aauth-edocs demo Sentinel",
            )
        )

    @app.get(jwks_path)
    def jwks():
        return {"keys": [key.public_jwk]}

    @app.post(token_path)
    def token_endpoint():
        incoming = HttpRequest(request.method, request.url, dict(request.headers.items()))
        verified = verify(incoming, resolver)
        if verified.header.get("scheme") != "jwks_uri":
            raise AAuthError(INVALID_TOKEN, 401, "Sentinel token endpoint accepts PS calls only")
        ps_issuer = verified.claims["iss"]

        body = request.get_json(force=True) or {}
        if "resource_token" not in body or "agent_token" not in body:
            raise AAuthError(INVALID_REQUEST, 400, "resource_token and agent_token are required")

        agent_claims = verify_agent_token(body["agent_token"], resolver)
        if agent_claims.get("ps") != ps_issuer:
            raise AAuthError(INVALID_TOKEN, 403, "requesting PS does not match agent token ps")

        rt_header, rt_peeked = peek_jwt(body["resource_token"])
        resource_jwk = resolver(
            rt_peeked.get("iss", ""),
            rt_peeked.get("dwk", ""),
            rt_header.get("kid", ""),
        )
        rt_claims = verify_resource_token(
            body["resource_token"],
            resolver,
            aud=issuer,
            agent=agent_claims["sub"],
            agent_jkt=jwk_thumbprint(agent_claims["cnf"]["jwk"]),
        )

        scope = rt_claims.get("scope")
        if not isinstance(scope, str) or len(scope.split()) != 1:
            raise AAuthError(INVALID_TOKEN, 400, "eDocs resource token must contain exactly one scope")
        if not all(
            isinstance(rt_claims.get(name), str) and rt_claims[name]
            for name in ("source_agent", "edoc_id")
        ) or not isinstance(rt_claims.get("controllers"), list):
            raise AAuthError(INVALID_TOKEN, 400, "eDocs resource token claims are required")

        descriptor = registry.functions.get(scope)
        if descriptor is None:
            raise AAuthError(DENIED, 403, "requested function is not registered")
        proposal = Dataflow.from_arguments(
            source=rt_claims["source_agent"],
            function=scope,
            document=rt_claims["edoc_id"],
            destination=agent_claims["sub"],
            arguments=rt_claims["function_args"],
        )
        binding = registry.resource_bindings.get(proposal.source)
        if binding is None:
            raise AAuthError(DENIED, 403, "source agent has no provisioned resource binding")
        if rt_claims.get("iss") != binding.resource_issuer:
            raise AAuthError(DENIED, 403, "resource token issuer does not match its provisioned binding")
        if jwk_thumbprint(resource_jwk) != binding.resource_jkt:
            raise AAuthError(DENIED, 403, "resource token key does not match its provisioned binding")
        controller_key = (rt_claims["iss"], proposal.document)
        authoritative = registry.controllers.get(controller_key)
        discovered = authoritative is None
        if discovered:
            if rt_claims["controllers"]:
                authoritative = tuple(rt_claims["controllers"])
            else:
                owner_as = registry.resource_owner_ases.get(rt_claims["iss"])
                if owner_as is None:
                    raise AAuthError(DENIED, 403, "resource owner has no provisioned controller AS")
                authoritative = (owner_as,)

        responses = {}
        for controller in authoritative:
            try:
                metadata = fetch_metadata(controller, DWK_ACCESS, transport)
                endpoint = metadata.endpoint("token_endpoint")
                if not endpoint:
                    raise AAuthError(SERVER_ERROR, 502, "controller has no token endpoint")
                outgoing = HttpRequest("POST", endpoint, {})
                sign_server(outgoing, key, issuer, DWK_PERSON)
                response = transport.request(
                    "POST",
                    outgoing.url,
                    headers=outgoing.headers,
                    json={
                        "resource_token": body["resource_token"],
                        "agent_token": body["agent_token"],
                    },
                )
                response_body = response.json()
                if response.status_code != 200:
                    detail = response_body.get("detail") if isinstance(response_body, dict) else None
                    raise AAuthError(DENIED, 403, detail or "controller denied the request")
                if not isinstance(response_body, dict) or not isinstance(response_body.get("auth_token"), str):
                    raise AAuthError(DENIED, 403, "controller returned no auth token")
                responses[controller] = response_body["auth_token"]
            except AAuthError as error:
                raise AAuthError(DENIED, 403, f"controller {controller} did not approve: {error}") from error

        token = aggregate_controller_decisions(
            proposal=proposal,
            resource_issuer=rt_claims["iss"],
            advisory_controllers=rt_claims["controllers"],
            responses=responses,
            agent_jwk=agent_claims["cnf"]["jwk"],
            registry=registry,
            sentinel_issuer=issuer,
            sentinel_key=key,
            key_resolver=resolver,
            authoritative_controllers=authoritative,
        )
        if discovered:
            registry.controllers[controller_key] = authoritative
        return {"auth_token": token, "expires_in": 3600}

    def _public_function(descriptor: FunctionDescriptor) -> dict[str, Any]:
        return {
            "function_id": descriptor.id,
            "description": descriptor.description,
            "input_schema": descriptor.input_schema,
            "digest": descriptor.digest,
        }

    @app.get("/registry")
    def registry_state():
        return jsonify(
            {
                "resource_bindings": [
                    {
                        "source_agent": source,
                        "source_ps": binding.source_ps,
                        "resource_issuer": binding.resource_issuer,
                        "resource_jkt": binding.resource_jkt,
                    }
                    for source, binding in registry.resource_bindings.items()
                ],
                "controllers": [
                    {
                        "resource_issuer": resource_issuer,
                        "edoc_id": edoc_id,
                        "controllers": list(controllers),
                    }
                    for (
                        resource_issuer,
                        edoc_id,
                    ), controllers in registry.controllers.items()
                ],
                "functions": [
                    {
                        **_public_function(descriptor),
                        "implementation_uri": descriptor.implementation_uri,
                    }
                    for descriptor in sorted(
                        registry.functions.values(),
                        key=lambda item: item.id,
                    )
                ],
                "materialized": [
                    serialize_dataflow(flow)
                    for flow in sorted(
                        registry.materialized,
                        key=lambda flow: (
                            flow.source,
                            flow.document,
                            flow.function_args_hash,
                        ),
                    )
                ],
                "derived_documents": [
                    {
                        "edoc_id": derived.edoc_id,
                        "resource_uri": derived.resource_uri,
                        "dataflow": serialize_dataflow(derived.dataflow),
                        "dataflow_fingerprint": derived.dataflow_fingerprint,
                        "output_digest": derived.output_digest,
                        "possessor": derived.possessor,
                        "controllers": list(derived.controllers),
                        "published": derived.edoc_id in registry.published_derived,
                    }
                    for derived in registry.derived_documents.values()
                ],
            }
        )

    @app.post("/registry/bindings")
    def register_binding():
        body = _json_object()
        required = {
            "source_agent",
            "source_ps",
            "resource_issuer",
            "resource_jkt",
        }
        if set(body) != required:
            raise ValueError(
                "binding requires source_agent, source_ps, "
                "resource_issuer, and resource_jkt"
            )
        for field in required:
            if not isinstance(body[field], str) or not body[field]:
                raise ValueError(f"{field} must be a non-empty string")
        source_agent = body["source_agent"]
        existing = registry.resource_bindings.get(source_agent)
        binding = ResourceBinding(
            source_ps=body["source_ps"],
            resource_issuer=body["resource_issuer"],
            resource_jkt=body["resource_jkt"],
        )
        if existing is not None and existing != binding:
            raise ValueError(
                f"source_agent already bound to a different resource: {source_agent}"
            )
        registry.resource_bindings[source_agent] = binding
        return jsonify(
            {
                "binding": {
                    "source_agent": source_agent,
                    "source_ps": binding.source_ps,
                    "resource_issuer": binding.resource_issuer,
                    "resource_jkt": binding.resource_jkt,
                }
            }
        ), 201

    @app.post("/registry/controllers")
    def register_controllers():
        body = _json_object()
        if set(body) != {"resource_issuer", "edoc_id", "controllers"}:
            raise ValueError(
                "controller registration requires resource_issuer, "
                "edoc_id, and controllers"
            )
        resource_issuer = body["resource_issuer"]
        edoc_id = body["edoc_id"]
        controllers = body["controllers"]
        if not isinstance(resource_issuer, str) or not resource_issuer:
            raise ValueError("resource_issuer must be a non-empty string")
        if not isinstance(edoc_id, str) or not edoc_id:
            raise ValueError("edoc_id must be a non-empty string")
        if (
            not isinstance(controllers, list)
            or not controllers
            or any(not isinstance(item, str) or not item for item in controllers)
        ):
            raise ValueError("controllers must be a non-empty string list")
        controller_key = (resource_issuer, edoc_id)
        controller_tuple = tuple(controllers)
        existing = registry.controllers.get(controller_key)
        if existing is not None and existing != controller_tuple:
            raise ValueError(
                "controllers already registered for this eDoc with a different set"
            )
        derived = registry.derived_documents.get(edoc_id)
        if derived is not None and tuple(derived.controllers) != controller_tuple:
            raise ValueError(
                "controllers must match the inherited derived eDoc controllers"
            )
        registry.controllers[controller_key] = controller_tuple
        if edoc_id in registry.derived_documents:
            registry.published_derived.add(edoc_id)
        return jsonify(
            {
                "controller": {
                    "resource_issuer": resource_issuer,
                    "edoc_id": edoc_id,
                    "controllers": list(controller_tuple),
                }
            }
        ), 201

    @app.get("/registry/derived/<edoc_id>")
    def get_derived(edoc_id: str):
        derived = registry.derived_documents.get(edoc_id)
        if derived is None:
            raise LookupError(f"unknown derived eDoc: {edoc_id}")
        output = registry.derived_outputs.get(edoc_id)
        if output is None:
            raise LookupError(f"derived eDoc output unavailable: {edoc_id}")
        return jsonify(
            {
                "edoc_id": derived.edoc_id,
                "possessor": derived.possessor,
                "controllers": list(derived.controllers),
                "output_digest": derived.output_digest,
                "dataflow": serialize_dataflow(derived.dataflow),
                "dataflow_fingerprint": derived.dataflow_fingerprint,
                "output": output,
                "published": edoc_id in registry.published_derived,
            }
        )

    @app.post("/registry/derived/<edoc_id>/transform")
    def transform_derived(edoc_id: str):
        """Apply one registry function locally and record source=destination provenance."""
        if execute_function is None:
            raise ValueError("local transform is not configured")
        body = _json_object()
        if set(body) != {"possessor", "function_id", "function_args"}:
            raise ValueError(
                "transform requires possessor, function_id, and function_args"
            )
        possessor = body["possessor"]
        function_id = body["function_id"]
        function_args = body["function_args"]
        if not isinstance(possessor, str) or not possessor:
            raise ValueError("possessor must be a non-empty string")
        if not isinstance(function_id, str) or not function_id:
            raise ValueError("function_id must be a non-empty string")
        if not isinstance(function_args, dict):
            raise ValueError("function_args must be a JSON object")
        derived = registry.derived_documents.get(edoc_id)
        if derived is None:
            raise LookupError(f"unknown derived eDoc: {edoc_id}")
        if derived.possessor != possessor:
            raise PermissionError(
                "only the possessor agent may transform this derived eDoc"
            )
        if edoc_id in registry.published_derived:
            raise ValueError("derived eDoc is already published")
        if function_id not in registry.functions:
            raise LookupError(f"unknown function: {function_id}")
        output = registry.derived_outputs.get(edoc_id)
        if output is None:
            raise LookupError(f"derived eDoc output unavailable: {edoc_id}")
        if not isinstance(output, dict):
            raise RuntimeError(f"derived eDoc payload is invalid: {edoc_id}")
        transformed = execute_function(function_id, output, function_args)
        if not isinstance(transformed, dict):
            raise ValueError("transform function must return a JSON object")
        dataflow = Dataflow.from_arguments(
            possessor,
            function_id,
            edoc_id,
            possessor,
            function_args,
        )
        created = register_materialization(
            registry,
            dataflow=dataflow,
            output=transformed,
            controllers=derived.controllers,
        )
        return jsonify(
            {
                "derived_edoc_id": created.edoc_id,
                "possessor": created.possessor,
                "controllers": list(created.controllers),
                "output": transformed,
            }
        ), 201

    @app.post("/registry/materializations")
    def record_materialization():
        body = _json_object()
        if set(body) != {"dataflow", "output", "controllers"}:
            raise ValueError(
                "materialization requires dataflow, output, and controllers"
            )
        if not isinstance(body["output"], dict):
            raise ValueError("output must be a JSON object")
        controllers = body["controllers"]
        if (
            not isinstance(controllers, list)
            or not controllers
            or any(not isinstance(item, str) or not item for item in controllers)
        ):
            raise ValueError("controllers must be a non-empty string list")
        dataflow = parse_dataflow(body["dataflow"])
        derived = register_materialization(
            registry,
            dataflow=dataflow,
            output=body["output"],
            controllers=tuple(controllers),
        )
        return jsonify(
            {
                "derived_edoc_id": derived.edoc_id,
                "possessor": derived.possessor,
                "controllers": list(derived.controllers),
            }
        ), 201

    @app.get("/registry/functions")
    def list_functions():
        return jsonify(
            {
                "functions": [
                    _public_function(descriptor)
                    for descriptor in sorted(
                        registry.functions.values(),
                        key=lambda item: item.id,
                    )
                ]
            }
        )

    @app.post("/registry/functions")
    def register_function():
        if on_function_register is None:
            raise ValueError("function registration is not configured")
        body = _json_object()
        result = on_function_register(body)
        descriptor = getattr(result, "descriptor", result)
        if not isinstance(descriptor, FunctionDescriptor):
            raise ValueError("function registration returned no descriptor")
        registry.functions[descriptor.id] = descriptor
        return jsonify(
            {
                "function": {
                    **_public_function(descriptor),
                    "implementation_uri": descriptor.implementation_uri,
                }
            }
        ), 201

    return app


def _json_object() -> dict[str, Any]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("JSON object required")
    return body


def aggregate_controller_decisions(
    *,
    proposal: Dataflow,
    resource_issuer: str,
    advisory_controllers: list[str] | tuple[str, ...],
    responses: dict[str, str],
    agent_jwk: dict,
    registry: SentinelRegistry,
    sentinel_issuer: str,
    sentinel_key: SigningKey,
    key_resolver: KeyResolver,
    authoritative_controllers: tuple[str, ...] | None = None,
    lifetime: int = 3600,
    now: Now = time.time,
) -> str:
    """Require unanimous controller approval and issue one final auth token.

    ``responses`` is keyed by the authoritative controller URL contacted by
    the caller. HTTP transport and initial agent/resource verification happen
    outside this aggregation boundary.
    """
    controllers = authoritative_controllers or registry.controllers.get(
        (resource_issuer, proposal.document)
    )
    if not controllers:
        _deny("no authoritative controllers registered for the eDoc")
    if len(set(controllers)) != len(controllers):
        _deny("authoritative controller registry contains duplicates")
    if set(responses) != set(controllers):
        _deny("controller responses do not exactly match the authoritative controller set")

    for controller in controllers:
        token = responses[controller]
        try:
            header, _ = peek_jwt(token)
            typ = header.get("typ")
            if typ == AUTH_TYP:
                claims = verify_auth_token(
                    token,
                    key_resolver,
                    aud=sentinel_issuer,
                    signing_jwk=agent_jwk,
                    source_agent=proposal.source,
                    scope=proposal.function,
                    edoc_id=proposal.document,
                    controllers=advisory_controllers,
                    function_args_hash=proposal.function_args_hash,
                    now=now,
                )
                if claims.get("iss") != controller:
                    raise AAuthError(DENIED, 403, "controller token issuer mismatch")
                if claims.get("agent") != proposal.destination:
                    raise AAuthError(DENIED, 403, "controller token agent mismatch")
            elif typ == CONDITIONAL_AUTH_TYP:
                prerequisite = verify_conditional_auth_token(
                    token,
                    key_resolver,
                    issuer=controller,
                    aud=sentinel_issuer,
                    agent=proposal.destination,
                    signing_jwk=agent_jwk,
                    source_agent=proposal.source,
                    scope=proposal.function,
                    edoc_id=proposal.document,
                    controllers=advisory_controllers,
                    function_args_hash=proposal.function_args_hash,
                    now=now,
                )
                if not any(
                    prerequisite.matches(materialized)
                    for materialized in registry.materialized
                ):
                    raise AAuthError(DENIED, 403, "controller prerequisite has not materialized")
            else:
                raise AAuthError(DENIED, 403, f"unsupported controller token type {typ!r}")
        except AAuthError as error:
            _deny(f"controller {controller} did not approve: {error}")

    token = issue_auth_token(
        issuer=sentinel_issuer,
        dwk=DWK_ACCESS,
        aud=resource_issuer,
        agent=proposal.destination,
        cnf_jwk=agent_jwk,
        scope=proposal.function,
        source_agent=proposal.source,
        edoc_id=proposal.document,
        controllers=controllers,
        function_args_hash=proposal.function_args_hash,
        key=sentinel_key,
        lifetime=lifetime,
        now=now,
    )
    return token


def _deny(detail: str) -> None:
    raise AAuthError(DENIED, 403, detail)
