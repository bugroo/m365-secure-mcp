"""Strict build-plane contracts and signature verification.

The compiler consumes only this fixed, tenant-neutral manifest. Runtime tool
registration remains static: this module never creates tools from remote or
tenant-provided metadata.
"""

from __future__ import annotations

import base64
import hashlib
import json
from enum import StrEnum
from importlib.resources import files
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_trust import (
    CONTRACT_SIGNING_KEY_ID,
    CONTRACT_SIGNING_PUBLIC_KEY_B64,
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


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GraphCall(StrictModel):
    method: Literal["GET", "POST", "PATCH"]
    endpoint: str = Field(min_length=2, max_length=300)
    api_version: Literal["v1.0"] | None = None

    @field_validator("endpoint")
    @classmethod
    def fixed_graph_path(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or "://" in value
            or "/beta/" in value.lower()
            or value.startswith("/beta")
            or any(character in value for character in ("\r", "\n", "\x00"))
        ):
            raise ValueError("contract endpoint must be a fixed Graph v1.0 path")
        placeholders = {
            segment[1:-1]
            for segment in value.split("/")
            if segment.startswith("{") and segment.endswith("}")
        }
        if placeholders - {
            "resource_service_principal_id",
            "service_principal_id",
            "user_id",
        }:
            raise ValueError("contract endpoint contains an unsupported placeholder")
        return value


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


class IdempotencyContract(StrictModel):
    key_required: bool
    retry: Literal[
        "bounded_read_retry",
        "never_after_uncertain",
        "provider_idempotency",
        "no_retry",
    ]


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
        schema = self.input_schema
        if (
            schema.get("type") != "object"
            or schema.get("additionalProperties") is not False
            or not isinstance(schema.get("properties"), dict)
        ):
            raise ValueError("contract input schema must be a closed JSON object")
        is_write = self.graph.method in {"POST", "PATCH"}
        if is_write and self.risk_tier is RiskTier.T0:
            raise ValueError("write contracts cannot be T0")
        if not is_write and self.authorization_mode is not AuthorizationMode.AUTOMATIC_READ:
            raise ValueError("initial read contracts must use automatic_read")
        if is_write and self.authorization_mode is AuthorizationMode.AUTOMATIC_READ:
            raise ValueError("write contracts cannot use automatic_read")
        if self.risk_tier is RiskTier.T4 and (
            self.authorization_mode is not AuthorizationMode.PROHIBITED
        ):
            raise ValueError("T4 contracts must be prohibited")
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


def _data_bytes(name: str) -> bytes:
    return files("m365_secure_mcp.contract_data").joinpath(name).read_bytes()


def load_global_manifest() -> ContractManifest:
    """Load and verify the package-pinned global manifest, failing closed."""

    try:
        raw_manifest = json.loads(_data_bytes("global-manifest.json"))
        raw_signature = json.loads(_data_bytes("global-manifest.sig.json"))
        manifest = ContractManifest.model_validate(raw_manifest)
        signature = ManifestSignature.model_validate(raw_signature)
        public_key_bytes = base64.b64decode(
            CONTRACT_SIGNING_PUBLIC_KEY_B64,
            validate=True,
        )
        signature_bytes = base64.b64decode(signature.signature, validate=True)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("global contract manifest is malformed") from exc

    digest = sha256_digest(manifest)
    if signature.key_id != CONTRACT_SIGNING_KEY_ID:
        raise RuntimeError("global contract manifest signer is not trusted")
    if signature.manifest_digest != digest:
        raise RuntimeError("global contract manifest digest mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes,
            canonical_json(manifest),
        )
    except (ValueError, InvalidSignature) as exc:
        raise RuntimeError("global contract manifest signature is invalid") from exc
    return manifest


def authorization_is_at_least(
    candidate: AuthorizationMode,
    minimum: AuthorizationMode,
) -> bool:
    return AUTHORIZATION_STRENGTH[candidate] >= AUTHORIZATION_STRENGTH[minimum]
