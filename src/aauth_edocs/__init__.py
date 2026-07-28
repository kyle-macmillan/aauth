"""AAuth protocol primitives (draft-hardt-oauth-aauth-protocol-09) for
internal eDocs experimentation. See IMPLEMENTATION_PLAN.md for scope and
the simplifications relative to the spec."""

from .controller import ControllerPolicy, ControllerPolicyEvaluator, issue_controller_decision
from .coordinator import ApprovalRequired, AuthorizationCoordinator, resource_origin
from .deferred import PendingStore, poll
from .edocs import (
    EMPTY_FUNCTION_ARGS_HASH,
    MAX_FUNCTION_ARGS_BYTES,
    Dataflow,
    DataflowBinding,
    DerivedEdoc,
    ExactRule,
    FunctionDescriptor,
    OutputOf,
    ResourceBinding,
    SentinelRegistry,
    canonicalize_function_args,
    hash_function_args,
    register_materialization,
)
from .edocs_consent import EdocsApprovalHandler, EdocsApprovalRequest, EdocsConsentClient
from .errors import AAuthError
from .headers import (
    ACCESS_HEADER,
    CAPABILITIES_HEADER,
    MISSION_HEADER,
    REQUIREMENT_HEADER,
    MissionRef,
    build_authorization,
    build_capabilities,
    build_requirement,
    parse_authorization,
    parse_capabilities,
    parse_requirement,
)
from .httpsig import HttpHeaders, HttpRequest, VerifiedRequest, peek_jwt, sign, sign_server, verify, verify_jwt
from .ids import DWK_ACCESS, DWK_AGENT, DWK_PERSON, DWK_RESOURCE, agent_id, parse_agent_id, well_known_url
from .keys import SigningKey, jwk_thumbprint, verify_raw
from .metadata import JwksResolver, Metadata, build_metadata, fetch_metadata, static_resolver
from .policy_json import parse_dataflow, parse_rule, serialize_dataflow, serialize_rule
from .policy_store import MutableControllerPolicy, StoredRule
from .sentinel import aggregate_controller_decisions, create_sentinel
from .tokens import (
    AGENT_TYP,
    AUTH_TYP,
    CONDITIONAL_AUTH_TYP,
    RESOURCE_TYP,
    check_resource_challenge,
    issue_agent_token,
    issue_auth_token,
    issue_conditional_auth_token,
    issue_resource_token,
    verify_agent_token,
    verify_auth_token,
    verify_conditional_auth_token,
    verify_resource_token,
)

__all__ = [name for name in dir() if not name.startswith("_")]
