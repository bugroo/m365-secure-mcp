"""Exact T2/T3 plans and externally controlled approval authority.

This module contains no Graph client and cannot construct a request. It binds
future compiled operations to immutable private plans and verifies approvals
from tenant-controlled authorities before ``ChangeSafeOperator`` may execute.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_manifest import (
    AuthorizationMode,
    CompensationClass,
    ContractEffect,
    VerificationMode,
    canonical_json,
    sha256_digest,
)
from .governance import (
    EffectiveOperationGovernance,
    GovernanceProfileName,
    ResourceFenceType,
)
from .security import SecurityError, open_private_file

MAX_PLAN_LIFETIME_SECONDS = 3_600
MAX_APPROVAL_LIFETIME_SECONDS = 600


class StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PlanParameter(StrictFrozenModel):
    """One canonical private parameter; Graph request components are forbidden."""

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    value: str | bool | int | tuple[str, ...]

    @field_validator("name")
    @classmethod
    def parameter_is_not_graph_control(cls, value: str) -> str:
        forbidden = {
            "api_version",
            "body",
            "endpoint",
            "headers",
            "method",
            "query",
            "raw_body",
            "scope",
            "suffix",
            "url",
        }
        if value in forbidden:
            raise ValueError("plan parameters cannot control a Graph request")
        return value

    @field_validator("value")
    @classmethod
    def bounded_value(
        cls,
        value: str | bool | int | tuple[str, ...],
    ) -> str | bool | int | tuple[str, ...]:
        if isinstance(value, str) and (not value or len(value) > 512):
            raise ValueError("plan parameter string is empty or too long")
        if isinstance(value, tuple):
            if not value or len(value) > 100 or value != tuple(sorted(set(value))):
                raise ValueError("plan parameter lists must be non-empty, unique and sorted")
            if any(not item or len(item) > 512 for item in value):
                raise ValueError("plan parameter list contains an invalid string")
        return value


class TargetReference(StrictFrozenModel):
    """Exact private target. Public output uses only ``opaque_reference``."""

    resource_type: ResourceFenceType
    object_id: UUID
    opaque_reference: str = Field(pattern=r"^target:[0-9a-f]{32,64}$")


class PreconditionBinding(StrictFrozenModel):
    check_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")
    evidence_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ExpectedPostcondition(StrictFrozenModel):
    check_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")
    expected_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class CompensationDeclaration(StrictFrozenModel):
    classification: CompensationClass
    operation_id: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_.]{5,120}$",
    )
    manual_handoff_id: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_.-]{2,95}$",
    )

    @model_validator(mode="after")
    def explicit_compensation_is_separate(self) -> CompensationDeclaration:
        if (
            self.classification is CompensationClass.EXPLICIT_PLAYBOOK
            and self.operation_id is None
        ):
            raise ValueError("explicit compensation requires a separate operation ID")
        if self.classification is CompensationClass.NOT_COMPENSATABLE:
            if self.operation_id is not None or self.manual_handoff_id is None:
                raise ValueError(
                    "non-compensatable effects require a manual handoff and no operation"
                )
        return self


class OperatorPlan(StrictFrozenModel):
    """Immutable canonical T2/T3 plan stored only in tenant-local private state."""

    schema_version: Literal["2.0"] = "2.0"
    plan_id: UUID
    nonce: UUID
    operation_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effect_model_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    tenant_id: UUID
    deployment_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")
    profile: GovernanceProfileName
    intended_operator_id: UUID
    effect: ContractEffect
    risk_tier: Literal["T2", "T3"]
    authorization_mode: Literal[
        AuthorizationMode.EXPLICIT_PLAN,
        AuthorizationMode.DUAL_CONTROL,
    ]
    target: TargetReference
    parameters: tuple[PlanParameter, ...] = Field(default_factory=tuple, max_length=100)
    preconditions: tuple[PreconditionBinding, ...] = Field(
        min_length=1,
        max_length=100,
    )
    expected_postcondition: ExpectedPostcondition
    verification: VerificationMode
    compensation: CompensationDeclaration
    created_at: datetime
    not_before: datetime
    expires_at: datetime

    @field_validator("parameters")
    @classmethod
    def parameters_are_unique_sorted(
        cls,
        value: tuple[PlanParameter, ...],
    ) -> tuple[PlanParameter, ...]:
        names = [item.name for item in value]
        if names != sorted(set(names)):
            raise ValueError("plan parameters must be unique and sorted")
        return value

    @field_validator("preconditions")
    @classmethod
    def preconditions_are_unique_sorted(
        cls,
        value: tuple[PreconditionBinding, ...],
    ) -> tuple[PreconditionBinding, ...]:
        names = [item.check_id for item in value]
        if names != sorted(set(names)):
            raise ValueError("plan preconditions must be unique and sorted")
        return value

    @model_validator(mode="after")
    def exact_semantics_and_lifetime(self) -> OperatorPlan:
        timestamps = (self.created_at, self.not_before, self.expires_at)
        if any(item.tzinfo is None or item.utcoffset() is None for item in timestamps):
            raise ValueError("operator plan timestamps must be timezone-aware")
        if not self.created_at <= self.not_before < self.expires_at:
            raise ValueError("operator plan has an invalid write window")
        if (
            self.expires_at - self.created_at
        ).total_seconds() > MAX_PLAN_LIFETIME_SECONDS:
            raise ValueError("operator plan lifetime exceeds the hard maximum")
        if self.operation_id != self.contract_id:
            raise ValueError("operator plan operation must equal the compiled contract")
        if self.risk_tier == "T2" and (
            self.authorization_mode is not AuthorizationMode.EXPLICIT_PLAN
        ):
            raise ValueError("T2 plan requires explicit_plan")
        if self.risk_tier == "T3" and (
            self.authorization_mode is not AuthorizationMode.DUAL_CONTROL
        ):
            raise ValueError("T3 plan requires dual_control")
        if self.effect is ContractEffect.OBJECT_DELETE:
            raise ValueError("object deletion is prohibited")
        if self.verification is VerificationMode.NOT_VERIFIABLE:
            raise ValueError("effectful plans require representable verification")
        return self

    @property
    def digest(self) -> str:
        return sha256_digest(self)

    def validate_governance(self, governance: EffectiveOperationGovernance) -> None:
        if (
            self.operation_id != governance.operation_id
            or self.contract_digest != governance.contract_digest
            or self.contract_manifest_digest != governance.contract_manifest_digest
            or self.effect_model_digest != governance.effect_model_digest
            or self.policy_digest != governance.policy_digest
            or self.tenant_id != governance.tenant_id
            or self.profile is not governance.profile
            or self.effect is not governance.effect
            or self.authorization_mode is not governance.authorization_mode
            or self.verification is not governance.verification
            or self.target.resource_type not in governance.resource_fence_types
        ):
            raise SecurityError("operator plan does not match signed Governance")


class OperatorApprovalGrant(StrictFrozenModel):
    """External single-use approval bound to one exact private plan digest."""

    schema_version: Literal["2.0"] = "2.0"
    approval_id: UUID
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authority_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    tenant_id: UUID
    profile: GovernanceProfileName
    intended_operator_id: UUID
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def bounded_lifetime(self) -> OperatorApprovalGrant:
        if (
            self.issued_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or self.expires_at <= self.issued_at
            or (self.expires_at - self.issued_at).total_seconds()
            > MAX_APPROVAL_LIFETIME_SECONDS
        ):
            raise ValueError("operator approval has an invalid lifetime")
        return self


class OperatorApprovalSignature(StrictFrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,99}$")
    grant_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(min_length=80, max_length=128)


class SignedOperatorApproval(StrictFrozenModel):
    grant: OperatorApprovalGrant
    signature: OperatorApprovalSignature


class ApprovalAuthorityState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    COMPROMISED = "compromised"


class ApprovalAuthorityRecord(StrictFrozenModel):
    """Public trust metadata loaded from an operator-controlled secure boundary."""

    authority_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    identity_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    key_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,99}$")
    signer_group: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    public_key_b64: str = Field(min_length=43, max_length=44)
    state: ApprovalAuthorityState
    activated_at: datetime
    retired_at: datetime | None = None
    compromised_at: datetime | None = None

    @field_validator("public_key_b64")
    @classmethod
    def valid_ed25519_key(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
            Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("approval authority public key is invalid") from exc
        return value

    @model_validator(mode="after")
    def valid_trust_lifecycle(self) -> ApprovalAuthorityRecord:
        if self.activated_at.tzinfo is None:
            raise ValueError("approval authority activation must be timezone-aware")
        if self.state is ApprovalAuthorityState.ACTIVE:
            if self.retired_at is not None or self.compromised_at is not None:
                raise ValueError("active authority cannot have a terminal timestamp")
        elif self.state is ApprovalAuthorityState.RETIRED:
            if (
                self.retired_at is None
                or self.retired_at.tzinfo is None
                or self.retired_at <= self.activated_at
                or self.compromised_at is not None
            ):
                raise ValueError("retired authority requires one valid retirement time")
        elif (
            self.compromised_at is None
            or self.compromised_at.tzinfo is None
            or self.compromised_at < self.activated_at
            or self.retired_at is not None
        ):
            raise ValueError("compromised authority requires one valid compromise time")
        return self

    @property
    def public_key_sha256(self) -> str:
        raw = base64.b64decode(self.public_key_b64, validate=True)
        return f"sha256:{hashlib.sha256(raw).hexdigest()}"

    @property
    def verifier(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(
            base64.b64decode(self.public_key_b64, validate=True)
        )


class ApprovalTrustRegistry(StrictFrozenModel):
    """Closed trust registry. It is never fetched or modified by runtime."""

    schema_version: Literal["1.0"] = "1.0"
    authorities: tuple[ApprovalAuthorityRecord, ...] = Field(
        min_length=1,
        max_length=32,
    )

    @model_validator(mode="after")
    def no_aliases(self) -> ApprovalTrustRegistry:
        authority_ids = [item.authority_id for item in self.authorities]
        identity_ids = [item.identity_id for item in self.authorities]
        key_ids = [item.key_id for item in self.authorities]
        keys = [item.public_key_b64 for item in self.authorities]
        if authority_ids != sorted(set(authority_ids)):
            raise ValueError("trust authority IDs must be unique and sorted")
        if len(identity_ids) != len(set(identity_ids)):
            raise ValueError("trust authorities cannot alias one identity")
        if len(key_ids) != len(set(key_ids)) or len(keys) != len(set(keys)):
            raise ValueError("trust authorities cannot alias one signing key")
        return self

    def authority(self, authority_id: str) -> ApprovalAuthorityRecord:
        for authority in self.authorities:
            if authority.authority_id == authority_id:
                return authority
        raise SecurityError("approval references an unknown authority")


def sign_operator_approval(
    grant: OperatorApprovalGrant,
    signer: Ed25519PrivateKey,
    *,
    key_id: str,
) -> SignedOperatorApproval:
    return SignedOperatorApproval(
        grant=grant,
        signature=OperatorApprovalSignature(
            key_id=key_id,
            grant_digest=sha256_digest(grant),
            signature=base64.b64encode(signer.sign(canonical_json(grant))).decode("ascii"),
        ),
    )


class ApprovalReplayStore:
    """Atomic tenant-local consumption ledger for one or two approvals."""

    def __init__(self, path: Path, deployment_namespace: str) -> None:
        self.path = path
        self.deployment_namespace = deployment_namespace

    def _connect(self) -> sqlite3.Connection:
        descriptor = open_private_file(self.path, os.O_RDWR)
        os.close(descriptor)
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                deployment_namespace TEXT NOT NULL
            )
            """
        )
        row = connection.execute(
            "SELECT deployment_namespace FROM replay_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO replay_metadata (singleton, deployment_namespace)
                VALUES (1, ?)
                """,
                (self.deployment_namespace,),
            )
        elif str(row[0]) != self.deployment_namespace:
            connection.close()
            raise SecurityError("approval ledger belongs to another deployment")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_operator_approvals (
                approval_id TEXT PRIMARY KEY,
                plan_digest TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            )
            """
        )
        return connection

    def consume(
        self,
        approvals: tuple[SignedOperatorApproval, ...],
        *,
        consumed_at: datetime,
    ) -> None:
        if consumed_at.tzinfo is None:
            raise ValueError("approval consumption timestamp must be timezone-aware")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for approval in approvals:
                existing = connection.execute(
                    """
                    SELECT approval_id
                    FROM consumed_operator_approvals
                    WHERE approval_id = ?
                    """,
                    (str(approval.grant.approval_id),),
                ).fetchone()
                if existing is not None:
                    raise SecurityError("operator approval was already consumed")
            for approval in approvals:
                connection.execute(
                    """
                    INSERT INTO consumed_operator_approvals (
                        approval_id, plan_digest, authority_id, consumed_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        str(approval.grant.approval_id),
                        approval.grant.plan_digest,
                        approval.grant.authority_id,
                        consumed_at.isoformat(),
                    ),
                )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


class ApprovalSetValidator:
    """Verify exact T2/T3 authority and optionally consume it atomically."""

    def __init__(
        self,
        *,
        trust_registry: ApprovalTrustRegistry,
        replay_store: ApprovalReplayStore,
    ) -> None:
        self.trust_registry = trust_registry
        self.replay_store = replay_store

    def validate(
        self,
        plan: OperatorPlan,
        governance: EffectiveOperationGovernance,
        approvals: tuple[SignedOperatorApproval, ...],
        *,
        as_of: datetime,
        purpose: Literal["execution", "historical"] = "execution",
        consume: bool = False,
    ) -> tuple[str, ...]:
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError("approval evaluation time must be timezone-aware")
        plan.validate_governance(governance)
        expected = (
            1
            if governance.authorization_mode is AuthorizationMode.EXPLICIT_PLAN
            else 2
        )
        if len(approvals) != expected:
            raise SecurityError("required approval count is not satisfied")
        authority_ids: list[str] = []
        identity_ids: list[str] = []
        key_ids: list[str] = []
        groups: list[str] = []
        for bundle in approvals:
            grant = bundle.grant
            authority = self.trust_registry.authority(grant.authority_id)
            try:
                policy_authority = next(
                    item
                    for item in governance.approval_authorities
                    if item.authority_id == grant.authority_id
                )
            except StopIteration as exc:
                raise SecurityError("approval authority is outside signed Governance") from exc
            if (
                policy_authority.identity_id != authority.identity_id
                or policy_authority.key_id != authority.key_id
                or policy_authority.signer_group != authority.signer_group
                or policy_authority.public_key_sha256 != authority.public_key_sha256
                or bundle.signature.key_id != authority.key_id
            ):
                raise SecurityError("approval authority trust binding changed")
            if authority.state is ApprovalAuthorityState.COMPROMISED:
                raise SecurityError("compromised approval authority is not trusted")
            if purpose == "execution" and authority.state is not ApprovalAuthorityState.ACTIVE:
                raise SecurityError("only active approval authorities may authorize execution")
            if purpose == "historical" and (
                authority.state is ApprovalAuthorityState.RETIRED
                and (
                    authority.retired_at is None
                    or grant.issued_at >= authority.retired_at
                )
            ):
                raise SecurityError("retired authority did not sign during its active lifetime")
            if (
                grant.plan_digest != plan.digest
                or grant.tenant_id != plan.tenant_id
                or grant.profile is not plan.profile
                or grant.intended_operator_id != plan.intended_operator_id
                or grant.issued_at < plan.not_before
                or grant.issued_at > as_of
                or grant.expires_at <= as_of
                or grant.expires_at > plan.expires_at
                or as_of < plan.not_before
                or as_of >= plan.expires_at
            ):
                raise SecurityError("approval does not bind the current exact plan")
            if bundle.signature.grant_digest != sha256_digest(grant):
                raise SecurityError("operator approval digest mismatch")
            try:
                authority.verifier.verify(
                    base64.b64decode(bundle.signature.signature, validate=True),
                    canonical_json(grant),
                )
            except (ValueError, InvalidSignature) as exc:
                raise SecurityError("operator approval signature is invalid") from exc
            authority_ids.append(authority.authority_id)
            identity_ids.append(authority.identity_id)
            key_ids.append(authority.key_id)
            groups.append(authority.signer_group)
        if (
            len(authority_ids) != len(set(authority_ids))
            or len(identity_ids) != len(set(identity_ids))
            or len(key_ids) != len(set(key_ids))
        ):
            raise SecurityError("dual control requires independent signer identities")
        if not set(governance.required_signer_groups).issubset(groups):
            raise SecurityError("required separation-of-duties signer groups are missing")
        if consume:
            if purpose != "execution":
                raise SecurityError("historical verification cannot consume approvals")
            self.replay_store.consume(approvals, consumed_at=as_of)
        return tuple(sorted(authority_ids))
