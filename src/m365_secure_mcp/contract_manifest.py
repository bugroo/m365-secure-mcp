"""Strict build-plane contracts and signature verification.

The compiler consumes only this fixed, tenant-neutral manifest. Runtime tool
registration remains static: this module never creates tools from remote or
tenant-provided metadata.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Sequence
from enum import StrEnum
from importlib.resources import files
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_trust import (
    CONTRACT_SIGNING_AUTHORITIES,
    ContractSigningAuthority,
    SigningAuthorityClass,
    SigningKeyState,
)


class RiskTier(StrEnum):
    """Operational impact tier.

    T0 is read-only; T1 is bounded and reversible; T2 is operationally
    disruptive; T3 is privileged/high-impact; T4 is prohibited.
    """

    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"


class AuthorizationMode(StrEnum):
    """Minimum authorization floor enforced before a contract can run."""

    AUTOMATIC_READ = "automatic_read"
    STANDING_POLICY = "standing_policy"
    EXPLICIT_PLAN = "explicit_plan"
    DUAL_CONTROL = "dual_control"
    BREAK_GLASS_ONLY = "break_glass_only"
    PROHIBITED = "prohibited"


AUTHORIZATION_STRENGTH: dict[AuthorizationMode, int] = {
    AuthorizationMode.AUTOMATIC_READ: 0,
    AuthorizationMode.STANDING_POLICY: 1,
    AuthorizationMode.EXPLICIT_PLAN: 2,
    AuthorizationMode.DUAL_CONTROL: 3,
    AuthorizationMode.BREAK_GLASS_ONLY: 4,
    AuthorizationMode.PROHIBITED: 5,
}


class VerificationMode(StrEnum):
    STRONG_READBACK = "strong_readback"
    ASYNC_STATUS = "async_status"
    RESOURCE_OBSERVED = "resource_observed"
    PROVIDER_ACKNOWLEDGED = "provider_acknowledged"
    NOT_VERIFIABLE = "not_verifiable"


class CompensationClass(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    CONDITIONAL_RESTORE = "conditional_restore"
    EXPLICIT_PLAYBOOK = "explicit_playbook"
    NOT_COMPENSATABLE = "not_compensatable"


class ContractLifecycleState(StrEnum):
    DRAFT = "draft"
    CANDIDATE = "candidate"
    ACTIVE = "active"
    RETIRED = "retired"


class ContractMaturity(StrEnum):
    EXPERIMENTAL = "experimental"
    PREVIEW = "preview"
    STABLE = "stable"
    DEPRECATED = "deprecated"


class AsyncBehavior(StrEnum):
    SYNCHRONOUS = "synchronous"
    PROVIDER_EVENTUAL = "provider_eventual"


class ContractPrivacyClass(StrEnum):
    OPAQUE_PUBLIC_PRIVATE_RECEIPT = "opaque_public_private_receipt"


class IdentityExecutorId(StrEnum):
    SYNTHETIC_STATE_TRANSITION_V1 = "synthetic.state_transition.v1"
    USER_SESSIONS_REVOKE_V1 = "identity.user_sessions_revoke.v1"
    USER_ACCOUNT_STATE_SET_V1 = "identity.user_account_state_set.v1"
    GROUP_USER_MEMBERSHIP_ADD_V1 = "identity.group_user_membership_add.v1"
    GROUP_USER_MEMBERSHIP_REMOVE_V1 = "identity.group_user_membership_remove.v1"
    USER_DIRECT_LICENSE_SET_V1 = "identity.user_direct_license_set.v1"


class ProtectedObjectPolicyId(StrEnum):
    SYNTHETIC_EXCLUDE_PROTECTED_V1 = "synthetic.exclude_protected.v1"
    NON_PRIVILEGED_MEMBER_USER_V1 = "identity.non_privileged_member_user.v1"
    NON_PRIVILEGED_MEMBER_USER_STATIC_GROUP_V1 = (
        "identity.non_privileged_member_user_static_group.v1"
    )


class ResourceFenceId(StrEnum):
    SYNTHETIC_TENANT_USER_V1 = "synthetic.tenant_user.v1"
    ALLOWLISTED_USER_V1 = "identity.allowlisted_user.v1"
    ALLOWLISTED_USER_AND_GROUP_V1 = "identity.allowlisted_user_and_group.v1"
    ALLOWLISTED_USER_AND_SKU_V1 = "identity.allowlisted_user_and_sku.v1"


class VerificationContractId(StrEnum):
    SYNTHETIC_READBACK_V1 = "synthetic.readback.v1"
    SESSION_REVOCATION_ACCEPTANCE_V1 = "identity.session_revocation_acceptance.v1"
    USER_ACCOUNT_STATE_READBACK_V1 = "identity.user_account_state_readback.v1"
    GROUP_MEMBERSHIP_READBACK_V1 = "identity.group_membership_readback.v1"
    DIRECT_LICENSE_READBACK_V1 = "identity.direct_license_readback.v1"


class ContractEffect(StrEnum):
    """Closed semantic effect vocabulary for compiled Graph contracts."""

    READ = "read"
    CREATE_OBJECT = "create_object"
    UPDATE_PROPERTIES = "update_properties"
    STATE_TRANSITION = "state_transition"
    RELATIONSHIP_ADD = "relationship_add"
    RELATIONSHIP_REMOVE = "relationship_remove"
    INVOKE_ACTION = "invoke_action"
    OBJECT_DELETE = "object_delete"


EFFECT_MODEL_SCHEMA_VERSION = "1.0"
CALLER_CONTROLLED_GRAPH_FIELDS = frozenset(
    {
        "api_version",
        "body",
        "endpoint",
        "graph_endpoint",
        "headers",
        "method",
        "query",
        "query_params",
        "request_body",
        "scope",
        "scopes",
        "suffix",
        "url",
    }
)
_V1_PLACEHOLDERS = frozenset(
    {
        "application_id",
        "resource_service_principal_id",
        "service_principal_id",
        "user_id",
    }
)
_V2_PLACEHOLDERS = _V1_PLACEHOLDERS | frozenset(
    {
        "directory_object_id",
        "group_id",
        "incident_id",
        "managed_device_id",
        "policy_id",
        "sku_id",
    }
)
_PLACEHOLDER = re.compile(r"^\{([a-z][a-z0-9_]*)\}$")
SAFE_GRAPH_PATH_PARAMETER_PATTERN = (
    r"^(?!\.{1,2}$)[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_fixed_graph_path(
    value: str,
    *,
    allowed_placeholders: frozenset[str],
) -> str:
    if (
        not value.startswith("/")
        or "://" in value
        or "/beta/" in value.lower()
        or value.lower().startswith("/beta")
        or any(character in value for character in ("\r", "\n", "\x00"))
        or any(character in value for character in ("?", "#", "\\", "%"))
    ):
        raise ValueError("contract endpoint must be a fixed Graph v1.0 path")

    for segment in value.split("/")[1:]:
        if not segment or segment in {".", ".."}:
            raise ValueError("contract endpoint contains an unsafe path segment")
        if "{" in segment or "}" in segment:
            match = _PLACEHOLDER.fullmatch(segment)
            if match is None or match.group(1) not in allowed_placeholders:
                raise ValueError(
                    "contract endpoint contains an unsupported placeholder"
                )
    return value


class GraphCall(StrictModel):
    method: Literal["GET", "POST", "PATCH"]
    endpoint: str = Field(min_length=2, max_length=300)
    api_version: Literal["v1.0"] | None = None

    @field_validator("endpoint")
    @classmethod
    def fixed_graph_path(cls, value: str) -> str:
        return _validate_fixed_graph_path(
            value,
            allowed_placeholders=_V1_PLACEHOLDERS,
        )


class EffectGraphCall(StrictModel):
    """Graph call schema reserved for future explicit-effect manifests."""

    method: Literal["GET", "POST", "PATCH", "DELETE"]
    endpoint: str = Field(min_length=2, max_length=300)
    api_version: Literal["v1.0"]

    @field_validator("endpoint")
    @classmethod
    def fixed_graph_path(cls, value: str) -> str:
        return _validate_fixed_graph_path(
            value,
            allowed_placeholders=_V2_PLACEHOLDERS,
        )


class PreflightGraphCallV2(StrictModel):
    method: Literal["GET"]
    endpoint: str = Field(min_length=2, max_length=300)
    api_version: Literal["v1.0"]

    @field_validator("endpoint")
    @classmethod
    def fixed_graph_path(cls, value: str) -> str:
        return _validate_fixed_graph_path(
            value,
            allowed_placeholders=_V2_PLACEHOLDERS,
        )


class ContractPermissions(StrictModel):
    delegated_scopes: list[str] = Field(min_length=1)
    operator_roles: list[str] = Field(default_factory=list)
    admin_consent_required: bool = True

    @field_validator("delegated_scopes")
    @classmethod
    def unique_scopes(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("delegated scopes must be unique and sorted")
        forbidden = {"Directory.ReadWrite.All", "Directory.AccessAsUser.All"}
        if forbidden & set(value):
            raise ValueError("contract requests a prohibited directory scope")
        return value

    @field_validator("operator_roles")
    @classmethod
    def unique_operator_roles(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("operator roles must be unique and sorted")
        return value


class ContractPermissionsV2(ContractPermissions):
    """Categorized schema-2.0 permission and operational-role metadata."""

    effect_delegated_scopes: list[str] = Field(default_factory=list)
    preflight_delegated_scopes: list[str] = Field(default_factory=list)
    readback_delegated_scopes: list[str] = Field(default_factory=list)
    protected_object_evidence_delegated_scopes: list[str] = Field(
        default_factory=list
    )
    microsoft_supported_roles: list[str] = Field(default_factory=list)
    microsoft_supported_evidence_roles: list[str] = Field(default_factory=list)
    project_required_role: str | None = Field(
        default=None,
        min_length=3,
        max_length=120,
    )
    project_required_evidence_role: str | None = Field(
        default=None,
        min_length=3,
        max_length=120,
    )
    project_role_rationale: str | None = Field(
        default=None,
        min_length=20,
        max_length=500,
    )
    project_evidence_role_rationale: str | None = Field(
        default=None,
        min_length=20,
        max_length=500,
    )

    @field_validator(
        "effect_delegated_scopes",
        "preflight_delegated_scopes",
        "readback_delegated_scopes",
        "protected_object_evidence_delegated_scopes",
    )
    @classmethod
    def unique_categorized_scopes(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("categorized delegated scopes must be unique and sorted")
        forbidden = {"Directory.ReadWrite.All", "Directory.AccessAsUser.All"}
        if forbidden & set(value):
            raise ValueError("contract requests a prohibited directory scope")
        return value

    @field_validator(
        "microsoft_supported_roles",
        "microsoft_supported_evidence_roles",
    )
    @classmethod
    def unique_supported_roles(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("Microsoft-supported roles must be unique and sorted")
        return value


class IdempotencyContract(StrictModel):
    key_required: bool
    retry: Literal[
        "bounded_read_retry",
        "never_after_uncertain",
        "provider_idempotency",
        "no_retry",
    ]


def _validate_common_contract_semantics(
    *,
    input_schema: dict[str, Any],
    preflight_graph_calls: list[GraphCall],
    graph_method: str,
    risk_tier: RiskTier,
    authorization_mode: AuthorizationMode,
) -> None:
    if (
        input_schema.get("type") != "object"
        or input_schema.get("additionalProperties") is not False
        or not isinstance(input_schema.get("properties"), dict)
    ):
        raise ValueError("contract input schema must be a closed JSON object")
    input_fields = set(input_schema["properties"])
    if input_fields & CALLER_CONTROLLED_GRAPH_FIELDS:
        raise ValueError(
            "contract input schema exposes caller-controlled Graph request fields"
        )
    if any(call.method != "GET" for call in preflight_graph_calls):
        raise ValueError("contract preflight Graph calls must be read-only")
    is_write = graph_method != "GET"
    if is_write and risk_tier is RiskTier.T0:
        raise ValueError("write contracts cannot be T0")
    if not is_write and authorization_mode is not AuthorizationMode.AUTOMATIC_READ:
        raise ValueError("initial read contracts must use automatic_read")
    if is_write and authorization_mode is AuthorizationMode.AUTOMATIC_READ:
        raise ValueError("write contracts cannot use automatic_read")
    if risk_tier is RiskTier.T4 and (
        authorization_mode is not AuthorizationMode.PROHIBITED
    ):
        raise ValueError("T4 contracts must be prohibited")


class ContractSpec(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    tool_name: str = Field(pattern=r"^m365_[a-z0-9_]{3,96}$")
    description: str = Field(min_length=20, max_length=500)
    module: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    graph: GraphCall
    preflight_graph_calls: list[GraphCall] = Field(default_factory=list)
    input_schema: dict[str, Any]
    output_fields: list[str] = Field(min_length=1)
    permissions: ContractPermissions
    risk_tier: RiskTier
    authorization_mode: AuthorizationMode
    resource_fences: list[str] = Field(min_length=1)
    preconditions: list[str] = Field(min_length=1)
    postconditions: list[str] = Field(min_length=1)
    plan_ttl_seconds: int = Field(ge=0, le=3_600)
    idempotency: IdempotencyContract
    verification: VerificationMode
    compensation: CompensationClass

    @model_validator(mode="after")
    def validate_contract_semantics(self) -> ContractSpec:
        if self.graph.method == "POST":
            raise ValueError(
                "contract schema 1.0 cannot infer a safe semantic effect for POST"
            )
        _validate_common_contract_semantics(
            input_schema=self.input_schema,
            preflight_graph_calls=self.preflight_graph_calls,
            graph_method=self.graph.method,
            risk_tier=self.risk_tier,
            authorization_mode=self.authorization_mode,
        )
        return self


class ContractSpecV2(StrictModel):
    """Future signed contract schema with an explicit semantic effect.

    No v2 manifest is shipped by Secure Operations 0. This closed schema makes
    the next reviewed manifest fail closed before any T2 or new Graph operation
    is introduced.
    """

    id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    tool_name: str = Field(pattern=r"^m365_[a-z0-9_]{3,96}$")
    description: str = Field(min_length=20, max_length=500)
    module: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    graph: EffectGraphCall
    preflight_graph_calls: list[GraphCall | PreflightGraphCallV2] = Field(
        default_factory=list
    )
    input_schema: dict[str, Any]
    output_fields: list[str] = Field(min_length=1)
    permissions: ContractPermissionsV2
    risk_tier: RiskTier
    authorization_mode: AuthorizationMode
    resource_fences: list[str] = Field(min_length=1)
    preconditions: list[str] = Field(min_length=1)
    postconditions: list[str] = Field(min_length=1)
    plan_ttl_seconds: int = Field(ge=0, le=3_600)
    idempotency: IdempotencyContract
    verification: VerificationMode
    compensation: CompensationClass
    effect: ContractEffect
    lifecycle_state: ContractLifecycleState = ContractLifecycleState.CANDIDATE
    executor_id: IdentityExecutorId = IdentityExecutorId.SYNTHETIC_STATE_TRANSITION_V1
    resource_fence_id: ResourceFenceId = ResourceFenceId.SYNTHETIC_TENANT_USER_V1
    protected_object_policy_id: ProtectedObjectPolicyId = (
        ProtectedObjectPolicyId.SYNTHETIC_EXCLUDE_PROTECTED_V1
    )
    verification_contract_id: VerificationContractId = (
        VerificationContractId.SYNTHETIC_READBACK_V1
    )
    async_behavior: AsyncBehavior = AsyncBehavior.SYNCHRONOUS
    ambiguity_handling: Literal["never_retry_automatically"] = (
        "never_retry_automatically"
    )
    privacy_class: ContractPrivacyClass = (
        ContractPrivacyClass.OPAQUE_PUBLIC_PRIVATE_RECEIPT
    )
    maturity: ContractMaturity = ContractMaturity.EXPERIMENTAL
    license_prerequisites: list[str] = Field(default_factory=list)
    official_references: list[str] = Field(default_factory=list)
    verified_on: str | None = Field(
        default=None,
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    )

    @field_validator("permissions", mode="before")
    @classmethod
    def accept_legacy_synthetic_permissions(
        cls,
        value: Any,
    ) -> Any:
        """Preserve schema-2.0 synthetic fixtures without changing schema 1.0."""
        if isinstance(value, ContractPermissions) and not isinstance(
            value,
            ContractPermissionsV2,
        ):
            return value.model_dump(mode="json")
        return value

    @model_validator(mode="after")
    def validate_explicit_effect(self) -> ContractSpecV2:
        _validate_common_contract_semantics(
            input_schema=self.input_schema,
            preflight_graph_calls=[],
            graph_method=self.graph.method,
            risk_tier=self.risk_tier,
            authorization_mode=self.authorization_mode,
        )
        if self.effect is ContractEffect.OBJECT_DELETE:
            raise ValueError("object_delete contracts are prohibited")

        properties = self.input_schema["properties"]
        placeholders = {
            match.group(1)
            for segment in self.graph.endpoint.split("/")
            if (match := _PLACEHOLDER.fullmatch(segment)) is not None
        }
        for placeholder in placeholders:
            field = properties.get(placeholder)
            if not isinstance(field, dict) or field.get("type") != "string":
                raise ValueError(
                    "endpoint placeholders require a closed string input field"
                )
            if (
                field.get("format") != "uuid"
                and field.get("pattern") != SAFE_GRAPH_PATH_PARAMETER_PATTERN
            ):
                raise ValueError(
                    "endpoint placeholders require a safe path-segment schema"
                )

        allowed_methods: dict[ContractEffect, frozenset[str]] = {
            ContractEffect.READ: frozenset({"GET"}),
            ContractEffect.CREATE_OBJECT: frozenset({"POST"}),
            ContractEffect.UPDATE_PROPERTIES: frozenset({"PATCH"}),
            ContractEffect.STATE_TRANSITION: frozenset({"POST", "PATCH"}),
            ContractEffect.RELATIONSHIP_ADD: frozenset({"POST"}),
            ContractEffect.RELATIONSHIP_REMOVE: frozenset({"DELETE"}),
            ContractEffect.INVOKE_ACTION: frozenset({"POST"}),
        }
        if self.graph.method not in allowed_methods[self.effect]:
            raise ValueError("contract effect and Graph method are incompatible")

        if self.effect is ContractEffect.READ and self.risk_tier is not RiskTier.T0:
            raise ValueError("read effects must be T0")

        if self.effect is ContractEffect.RELATIONSHIP_REMOVE:
            if not self.graph.endpoint.endswith("/$ref"):
                raise ValueError(
                    "relationship_remove endpoint must end literally in /$ref"
                )
        elif self.graph.method == "DELETE":
            raise ValueError("DELETE is reserved for relationship_remove")
        if self.lifecycle_state is ContractLifecycleState.ACTIVE:
            raise ValueError(
                "schema-2.0 candidate source cannot declare itself active"
            )
        if self.maturity is ContractMaturity.STABLE:
            raise ValueError("candidate contracts cannot be stable before live review")
        if self.risk_tier not in {RiskTier.T2, RiskTier.T3}:
            raise ValueError("Identity candidate writes must be T2 or T3")
        if self.authorization_mode not in {
            AuthorizationMode.EXPLICIT_PLAN,
            AuthorizationMode.DUAL_CONTROL,
        }:
            raise ValueError("Identity candidate writes require explicit authorization")
        if self.official_references != sorted(set(self.official_references)):
            raise ValueError("official references must be unique and sorted")
        if self.license_prerequisites != sorted(set(self.license_prerequisites)):
            raise ValueError("license prerequisites must be unique and sorted")
        synthetic_ids = {
            IdentityExecutorId.SYNTHETIC_STATE_TRANSITION_V1,
        }
        if self.module == "synthetic":
            if self.executor_id not in synthetic_ids:
                raise ValueError("synthetic contracts require a synthetic executor")
        elif (
            self.executor_id in synthetic_ids
            or not self.license_prerequisites
            or not self.official_references
            or self.verified_on is None
        ):
            raise ValueError(
                "reviewed workload contracts require explicit executor and references"
            )
        if self.module != "synthetic":
            permissions = self.permissions
            categorized_scopes = sorted(
                {
                    *permissions.effect_delegated_scopes,
                    *permissions.preflight_delegated_scopes,
                    *permissions.readback_delegated_scopes,
                    *permissions.protected_object_evidence_delegated_scopes,
                }
            )
            if not permissions.effect_delegated_scopes:
                raise ValueError(
                    "reviewed workload contracts require effect permissions"
                )
            if categorized_scopes != permissions.delegated_scopes:
                raise ValueError(
                    "categorized permission closure must equal delegated scopes"
                )
            if (
                not permissions.microsoft_supported_roles
                or not permissions.microsoft_supported_evidence_roles
                or permissions.project_required_role is None
                or permissions.project_required_evidence_role is None
                or permissions.project_role_rationale is None
                or permissions.project_evidence_role_rationale is None
            ):
                raise ValueError(
                    "reviewed workload contracts require effect and evidence roles"
                )
            if (
                permissions.project_required_role
                not in permissions.microsoft_supported_roles
            ):
                raise ValueError(
                    "project-required role must be Microsoft-supported"
                )
            if (
                permissions.project_required_evidence_role
                not in permissions.microsoft_supported_evidence_roles
            ):
                raise ValueError(
                    "project-required evidence role must be Microsoft-supported"
                )
            if permissions.operator_roles != sorted(
                {
                    permissions.project_required_role,
                    permissions.project_required_evidence_role,
                }
            ):
                raise ValueError(
                    "operator-role closure must equal effect and evidence roles"
                )
        return self


class ContractManifest(StrictModel):
    schema_version: Literal["1.0"]
    product: Literal["m365-secure-mcp"]
    contracts: list[ContractSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_contracts(self) -> ContractManifest:
        ids = [contract.id for contract in self.contracts]
        tools = [contract.tool_name for contract in self.contracts]
        if len(ids) != len(set(ids)):
            raise ValueError("contract manifest contains duplicate IDs")
        if len(tools) != len(set(tools)):
            raise ValueError("contract manifest contains duplicate tool names")
        return self

    def contract(self, contract_id: str) -> ContractSpec:
        for contract in self.contracts:
            if contract.id == contract_id:
                return contract
        raise KeyError(f"unknown compiled contract: {contract_id}")


class ContractManifestV2(StrictModel):
    """Future explicit-effect manifest schema; no v2 artifact is active yet."""

    schema_version: Literal["2.0"]
    product: Literal["m365-secure-mcp"]
    contracts: list[ContractSpecV2] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_contracts(self) -> ContractManifestV2:
        ids = [contract.id for contract in self.contracts]
        tools = [contract.tool_name for contract in self.contracts]
        if len(ids) != len(set(ids)):
            raise ValueError("contract manifest contains duplicate IDs")
        if len(tools) != len(set(tools)):
            raise ValueError("contract manifest contains duplicate tool names")
        return self

    def contract(self, contract_id: str) -> ContractSpecV2:
        for contract in self.contracts:
            if contract.id == contract_id:
                return contract
        raise KeyError(f"unknown compiled contract: {contract_id}")


ContractManifestDocument = ContractManifest | ContractManifestV2


class ManifestSignature(StrictModel):
    schema_version: Literal["1.0"]
    algorithm: Literal["ed25519"]
    key_id: str = Field(min_length=3, max_length=100)
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(min_length=80, max_length=128)


def canonical_json(document: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes for hashing and signing."""

    if isinstance(document, BaseModel):
        document = document.model_dump(mode="json")
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_digest(document: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"


def contract_effect(contract: ContractSpec | ContractSpecV2) -> ContractEffect:
    """Return the signed/derived effect without guessing ambiguous POST semantics."""

    if isinstance(contract, ContractSpecV2):
        return contract.effect
    if contract.graph.method == "GET":
        return ContractEffect.READ
    if contract.graph.method == "PATCH":
        return ContractEffect.UPDATE_PROPERTIES
    raise ValueError(
        "contract schema 1.0 cannot infer a safe semantic effect for POST"
    )


def effect_model_document() -> dict[str, object]:
    """Return canonical public rules bound into compiler provenance."""

    return {
        "schema_version": EFFECT_MODEL_SCHEMA_VERSION,
        "graph_api_version": "v1.0",
        "effects": sorted(effect.value for effect in ContractEffect),
        "legacy_schema_1_0_method_effects": {
            "GET": ContractEffect.READ.value,
            "PATCH": ContractEffect.UPDATE_PROPERTIES.value,
        },
        "explicit_effect_method_rules": {
            ContractEffect.CREATE_OBJECT.value: ["POST"],
            ContractEffect.INVOKE_ACTION.value: ["POST"],
            ContractEffect.READ.value: ["GET"],
            ContractEffect.RELATIONSHIP_ADD.value: ["POST"],
            ContractEffect.RELATIONSHIP_REMOVE.value: ["DELETE"],
            ContractEffect.STATE_TRANSITION.value: ["PATCH", "POST"],
            ContractEffect.UPDATE_PROPERTIES.value: ["PATCH"],
        },
        "object_delete": "prohibited",
        "relationship_remove_suffix": "/$ref",
        "safe_path_parameter_pattern": SAFE_GRAPH_PATH_PARAMETER_PATTERN,
        "supported_path_placeholders": sorted(_V2_PLACEHOLDERS),
        "caller_controlled_graph_fields": sorted(
            CALLER_CONTROLLED_GRAPH_FIELDS
        ),
        "beta_allowed": False,
    }


def effect_model_digest() -> str:
    return sha256_digest(effect_model_document())


def parse_contract_manifest(document: object) -> ContractManifestDocument:
    """Parse one closed manifest generation without version fallback."""

    if not isinstance(document, dict):
        raise ValueError("contract manifest must be a JSON object")
    version = document.get("schema_version")
    if version == "1.0":
        return ContractManifest.model_validate(document)
    if version == "2.0":
        return ContractManifestV2.model_validate(document)
    raise ValueError("contract manifest schema version is unsupported")


def validate_contract_signing_authorities(
    authorities: Sequence[ContractSigningAuthority],
    *,
    allow_test_authorities: bool = False,
) -> ContractSigningAuthority:
    """Validate one closed contract trust registry and return its sole current key."""

    if not authorities:
        raise RuntimeError("contract signing trust registry is empty")
    key_ids = [authority.key_id for authority in authorities]
    if len(key_ids) != len(set(key_ids)):
        raise RuntimeError("contract signing key IDs must be immutable and unique")
    classes = {authority.authority_class for authority in authorities}
    if len(classes) != 1:
        raise RuntimeError("production and test contract authorities cannot be mixed")
    if SigningAuthorityClass.TEST in classes and not allow_test_authorities:
        raise RuntimeError("test contract authority is not valid for production")
    current = [
        authority
        for authority in authorities
        if authority.state is SigningKeyState.CURRENT
    ]
    if len(current) != 1:
        raise RuntimeError(
            "contract signing trust registry requires exactly one current key"
        )
    return current[0]


def _contract_signing_authority(
    key_id: str,
    authorities: Sequence[ContractSigningAuthority],
) -> ContractSigningAuthority:
    matches = [authority for authority in authorities if authority.key_id == key_id]
    if len(matches) != 1:
        raise RuntimeError("global contract manifest signer is not trusted")
    return matches[0]


def sign_contract_manifest(
    manifest: ContractManifestDocument,
    signer: Ed25519PrivateKey,
    *,
    key_id: str,
    authorities: Sequence[ContractSigningAuthority] | None = None,
    allow_test_authorities: bool = False,
) -> ManifestSignature:
    """Sign canonical manifest bytes with the exact reviewed current authority."""

    selected = CONTRACT_SIGNING_AUTHORITIES if authorities is None else authorities
    current = validate_contract_signing_authorities(
        selected,
        allow_test_authorities=allow_test_authorities,
    )
    authority = _contract_signing_authority(key_id, selected)
    if authority is not current or authority.state is not SigningKeyState.CURRENT:
        raise RuntimeError("retired or compromised contract keys cannot sign manifests")
    signer_public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expected_public_key = base64.b64decode(
        authority.public_key_b64,
        validate=True,
    )
    if not hmac.compare_digest(signer_public_key, expected_public_key):
        raise RuntimeError("external signer does not match the contract trust anchor")
    return ManifestSignature(
        schema_version="1.0",
        algorithm="ed25519",
        key_id=authority.key_id,
        manifest_digest=sha256_digest(manifest),
        signature=base64.b64encode(
            signer.sign(canonical_json(manifest))
        ).decode("ascii"),
    )


def verify_contract_manifest_signature(
    manifest: ContractManifestDocument,
    signature: ManifestSignature,
    *,
    authorities: Sequence[ContractSigningAuthority] | None = None,
    historical: bool = False,
    allow_test_authorities: bool = False,
) -> ContractSigningAuthority:
    """Verify a current signature or an exact retired historical digest."""

    selected = CONTRACT_SIGNING_AUTHORITIES if authorities is None else authorities
    current = validate_contract_signing_authorities(
        selected,
        allow_test_authorities=allow_test_authorities,
    )
    authority = _contract_signing_authority(signature.key_id, selected)
    digest = sha256_digest(manifest)
    if signature.manifest_digest != digest:
        raise RuntimeError("global contract manifest digest mismatch")
    if authority.state is SigningKeyState.COMPROMISED:
        raise RuntimeError("contract manifest signer is compromised")
    if historical:
        if (
            authority.state is not SigningKeyState.RETIRED
            or digest not in authority.historical_manifest_digests
        ):
            raise RuntimeError(
                "contract manifest is not pinned to a retired historical signer"
            )
    elif authority is not current or authority.state is not SigningKeyState.CURRENT:
        raise RuntimeError("global contract manifest signer is not current")
    try:
        public_key = base64.b64decode(authority.public_key_b64, validate=True)
        signature_bytes = base64.b64decode(signature.signature, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes,
            canonical_json(manifest),
        )
    except (ValueError, InvalidSignature) as exc:
        raise RuntimeError("global contract manifest signature is invalid") from exc
    return authority


def authorize_candidate_activation(
    manifest: ContractManifestV2,
    signature: ManifestSignature | None,
    *,
    authorities: Sequence[ContractSigningAuthority] | None = None,
    allow_test_authorities: bool = False,
) -> ContractSigningAuthority:
    """Fail closed unless a candidate has a current production signature.

    This primitive does not register tools. The external cutover must add the
    signed artifact and call this gate from a separately reviewed runtime
    registration change.
    """

    if signature is None:
        raise RuntimeError("unsigned contract candidate cannot be activated")
    authority = verify_contract_manifest_signature(
        manifest,
        signature,
        authorities=authorities,
        allow_test_authorities=allow_test_authorities,
    )
    if authority.authority_class is not SigningAuthorityClass.PRODUCTION:
        raise RuntimeError("test contract authority cannot activate candidates")
    if any(
        contract.lifecycle_state is not ContractLifecycleState.CANDIDATE
        for contract in manifest.contracts
    ):
        raise RuntimeError("only reviewed contract candidates may be activated")
    return authority


def _data_bytes(name: str) -> bytes:
    return files("m365_secure_mcp.contract_data").joinpath(name).read_bytes()


def load_global_manifest() -> ContractManifest:
    """Load and verify the package-pinned global manifest, failing closed."""

    try:
        raw_manifest = json.loads(_data_bytes("global-manifest.json"))
        raw_signature = json.loads(_data_bytes("global-manifest.sig.json"))
        manifest = ContractManifest.model_validate(raw_manifest)
        signature = ManifestSignature.model_validate(raw_signature)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("global contract manifest is malformed") from exc

    authority = _contract_signing_authority(
        signature.key_id,
        CONTRACT_SIGNING_AUTHORITIES,
    )
    verify_contract_manifest_signature(
        manifest,
        signature,
        historical=authority.state is SigningKeyState.RETIRED,
    )
    return manifest


def load_active_identity_manifest() -> ContractManifestV2 | None:
    """Load the optional signed Identity manifest; absence means no tool surface."""

    try:
        raw_manifest = json.loads(_data_bytes("global-identity-manifest.json"))
        raw_signature = json.loads(_data_bytes("global-identity-manifest.sig.json"))
    except FileNotFoundError:
        return None
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("active Identity contract manifest is malformed") from exc
    try:
        manifest = ContractManifestV2.model_validate(raw_manifest)
        signature = ManifestSignature.model_validate(raw_signature)
    except ValueError as exc:
        raise RuntimeError("active Identity contract manifest is malformed") from exc
    authorize_candidate_activation(manifest, signature)
    return manifest


def authorization_is_at_least(
    candidate: AuthorizationMode,
    minimum: AuthorizationMode,
) -> bool:
    return AUTHORIZATION_STRENGTH[candidate] >= AUTHORIZATION_STRENGTH[minimum]
