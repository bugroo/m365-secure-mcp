"""Reusable deterministic safety machinery for governed Microsoft 365 writes.

The model never supplies an approval flag or a Graph operation. A signed
standing policy authorizes routine T1 execution. When Governance tightens a
contract to ``explicit_plan``, an external host/broker signs the exact private
plan request and runtime consumes that approval once immediately before effect.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Generic, Literal, TypeVar, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_manifest import (
    AuthorizationMode,
    CompensationClass,
    ContractSpec,
    VerificationMode,
    canonical_json,
    sha256_digest,
)
from .governance import (
    AuthorizationDecision,
    EffectiveOperationGovernance,
    GovernanceProfileName,
)
from .operations import (
    ChangeRecord,
    GovernedReceipt,
    OperationRecord,
    OperationStatus,
    PermissionImpactPreview,
    ResponsibleParty,
)
from .operator_authority import (
    ApprovalSetValidator,
    CompensationDeclaration,
    ExpectedPostcondition,
    OperatorPlan,
    PlanParameter,
    PreconditionBinding,
    SignedOperatorApproval,
    TargetReference,
)
from .security import (
    PrivateStateError,
    SecurityError,
    WriteVerificationError,
    open_private_file,
    read_private_file,
)

MAX_APPROVAL_DOCUMENT_BYTES = 128_000
SnapshotT = TypeVar("SnapshotT")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GovernedOperationError(SecurityError):
    """A pre-write governed outcome carrying deterministic operator guidance."""

    def __init__(self, message: str, operation_record: OperationRecord) -> None:
        super().__init__(message)
        self.operation_record = operation_record
        self.reason_code = operation_record.reason_code


class GovernedWriteUncertainError(WriteVerificationError):
    """A write may have committed but its contract did not prove the outcome."""

    def __init__(self, message: str, operation_record: OperationRecord) -> None:
        super().__init__(message)
        self.operation_record = operation_record
        self.reason_code = operation_record.reason_code


class ChangePlanBinding(StrictModel):
    """Private exact-plan material bound into an external approval signature."""

    schema_version: Literal["1.0"] = "1.0"
    plan_id: UUID
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tenant_id: UUID
    deployment_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")
    profile: GovernanceProfileName
    operator_id: UUID
    authorization_mode: Literal["explicit_plan"]
    normalized_parameters_digest: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )
    target_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    precondition_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    permission_impact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    changed_fields: list[str] = Field(min_length=1, max_length=50)
    verification: VerificationMode
    compensation: CompensationClass
    created_at: datetime
    expires_at: datetime

    @field_validator("changed_fields")
    @classmethod
    def changed_fields_are_unique_and_sorted(
        cls,
        value: list[str],
    ) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("plan changed fields must be unique and sorted")
        return value

    @model_validator(mode="after")
    def valid_lifetime(self) -> ChangePlanBinding:
        if (
            self.created_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or self.expires_at <= self.created_at
        ):
            raise ValueError("change plan requires an increasing UTC lifetime")
        return self

    @property
    def digest(self) -> str:
        return sha256_digest(self)

    @property
    def semantic_digest(self) -> str:
        """Compare exact plan meaning while allowing persisted timestamps."""

        material = self.model_dump(mode="json")
        material.pop("created_at")
        material.pop("expires_at")
        return sha256_digest(material)


class ApprovalRequest(StrictModel):
    """Private broker request emitted by runtime; never returned through MCP."""

    schema_version: Literal["1.0"] = "1.0"
    plan: ChangePlanBinding
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    permission_impact: PermissionImpactPreview
    requested_at: datetime

    @model_validator(mode="after")
    def digest_matches_plan(self) -> ApprovalRequest:
        if self.plan_digest != self.plan.digest:
            raise ValueError("approval request plan digest does not match")
        if self.plan.permission_impact_digest != sha256_digest(
            self.permission_impact
        ):
            raise ValueError("approval request impact preview does not match")
        if (
            self.requested_at.tzinfo is None
            or self.requested_at < self.plan.created_at
            or self.requested_at > self.plan.expires_at
        ):
            raise ValueError(
                "approval request timestamp must be inside the plan lifetime"
            )
        return self


class ApprovalGrant(StrictModel):
    """The exact external authorization consumed once by runtime."""

    schema_version: Literal["1.0"] = "1.0"
    approval_id: UUID
    plan: ChangePlanBinding
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def valid_binding_and_lifetime(self) -> ApprovalGrant:
        if self.plan_digest != self.plan.digest:
            raise ValueError("approval grant plan digest does not match")
        if (
            self.issued_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or self.expires_at <= self.issued_at
            or self.issued_at < self.plan.created_at
            or self.expires_at > self.plan.expires_at
        ):
            raise ValueError("approval lifetime is outside the exact plan lifetime")
        return self


class ApprovalSignature(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str = Field(min_length=3, max_length=100)
    grant_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(min_length=80, max_length=128)


class SignedApprovalGrant(StrictModel):
    grant: ApprovalGrant
    signature: ApprovalSignature


@dataclass(frozen=True)
class ChangeSafePlan(Generic[SnapshotT]):
    """In-process plan: public metadata plus domain-private state."""

    plan_id: UUID
    created_at: datetime
    expires_at: datetime
    snapshot: SnapshotT
    requested: dict[str, str]
    changed_fields: list[str]
    permission_impact: PermissionImpactPreview
    authorization: AuthorizationDecision
    contract_digest: str
    binding: ChangePlanBinding | None

    @property
    def plan_digest(self) -> str | None:
        return self.binding.digest if self.binding is not None else None


@dataclass(frozen=True)
class ApprovalValidation:
    grant: ApprovalGrant
    source_path: Path


def sign_approval_grant(
    grant: ApprovalGrant,
    signer: Ed25519PrivateKey,
    *,
    key_id: str,
) -> SignedApprovalGrant:
    return SignedApprovalGrant(
        grant=grant,
        signature=ApprovalSignature(
            key_id=key_id,
            grant_digest=sha256_digest(grant),
            signature=base64.b64encode(
                signer.sign(canonical_json(grant))
            ).decode("ascii"),
        ),
    )


def verify_approval_grant(
    bundle: SignedApprovalGrant,
    verifier: Ed25519PublicKey,
) -> None:
    if bundle.signature.grant_digest != sha256_digest(bundle.grant):
        raise SecurityError("external approval grant digest mismatch")
    try:
        verifier.verify(
            base64.b64decode(bundle.signature.signature, validate=True),
            canonical_json(bundle.grant),
        )
    except (ValueError, InvalidSignature) as exc:
        raise SecurityError("external approval signature is invalid") from exc


def _load_approval_verifier(path: Path) -> Ed25519PublicKey:
    payload = read_private_file(
        path,
        max_bytes=4_096,
        label="approval public key",
    )
    try:
        raw = base64.b64decode(payload.strip(), validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise PrivateStateError("approval public key is invalid") from exc


class ApprovalConsumptionStore:
    """Tenant-local replay prevention for externally signed approvals."""

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
            CREATE TABLE IF NOT EXISTS approval_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                deployment_namespace TEXT NOT NULL
            )
            """
        )
        row = connection.execute(
            "SELECT deployment_namespace FROM approval_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO approval_metadata (singleton, deployment_namespace)
                VALUES (1, ?)
                """,
                (self.deployment_namespace,),
            )
        elif str(row[0]) != self.deployment_namespace:
            connection.close()
            raise SecurityError(
                "approval replay ledger belongs to another deployment"
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_approvals (
                approval_id TEXT PRIMARY KEY,
                plan_digest TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            )
            """
        )
        return connection

    def consume(self, grant: ApprovalGrant) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT plan_digest
                FROM consumed_approvals
                WHERE approval_id = ?
                """,
                (str(grant.approval_id),),
            ).fetchone()
            if existing is not None:
                raise SecurityError(
                    "external approval was already consumed; issue a new exact plan"
                )
            connection.execute(
                """
                INSERT INTO consumed_approvals (
                    approval_id,
                    plan_digest,
                    consumed_at
                ) VALUES (?, ?, ?)
                """,
                (
                    str(grant.approval_id),
                    grant.plan_digest,
                    datetime.now(UTC).isoformat(),
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


class ExternalApprovalBroker:
    """Owner-only filesystem boundary between MCP runtime and a host approver."""

    def __init__(
        self,
        *,
        directory: Path,
        public_key_path: Path,
        deployment_namespace: str,
    ) -> None:
        self.directory = directory.expanduser()
        self.public_key_path = public_key_path.expanduser()
        self.deployment_namespace = deployment_namespace
        self.consumption = ApprovalConsumptionStore(
            self.directory / "consumed.sqlite3",
            deployment_namespace,
        )

    def _request_path(self, plan_id: UUID) -> Path:
        return self.directory / f"{plan_id}.request.json"

    def _approval_path(self, plan_id: UUID) -> Path:
        return self.directory / f"{plan_id}.approval.json"

    @staticmethod
    def _write_request(path: Path, request: ApprovalRequest) -> None:
        payload = (
            json.dumps(
                request.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        descriptor = open_private_file(
            path,
            os.O_WRONLY | os.O_TRUNC,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def prepare(self, plan: ChangeSafePlan[SnapshotT]) -> ChangeSafePlan[SnapshotT]:
        """Persist or reuse one unexpired exact request for a stable plan ID."""

        if plan.binding is None:
            return plan
        if plan.binding.deployment_namespace != self.deployment_namespace:
            raise SecurityError("approval request belongs to another deployment")
        path = self._request_path(plan.plan_id)
        if path.exists():
            try:
                request = ApprovalRequest.model_validate_json(
                    read_private_file(
                        path,
                        max_bytes=MAX_APPROVAL_DOCUMENT_BYTES,
                        label="approval request",
                    )
                )
            except ValueError as exc:
                raise PrivateStateError("approval request is malformed") from exc
            now = datetime.now(UTC)
            if (
                request.plan.semantic_digest == plan.binding.semantic_digest
                and request.plan.expires_at > now
            ):
                return replace(
                    plan,
                    created_at=request.plan.created_at,
                    expires_at=request.plan.expires_at,
                    binding=request.plan,
                )
        request = ApprovalRequest(
            plan=plan.binding,
            plan_digest=plan.binding.digest,
            permission_impact=plan.permission_impact,
            requested_at=datetime.now(UTC),
        )
        self._write_request(path, request)
        return plan

    def validate(self, plan: ChangeSafePlan[Any]) -> ApprovalValidation | None:
        """Return a verified exact approval, or ``None`` while host action is pending."""

        if plan.binding is None:
            return None
        if plan.binding.deployment_namespace != self.deployment_namespace:
            raise SecurityError("external approval belongs to another deployment")
        approval_path = self._approval_path(plan.plan_id)
        if not approval_path.exists():
            return None
        try:
            bundle = SignedApprovalGrant.model_validate_json(
                read_private_file(
                    approval_path,
                    max_bytes=MAX_APPROVAL_DOCUMENT_BYTES,
                    label="external approval",
                )
            )
        except ValueError as exc:
            raise PrivateStateError("external approval document is malformed") from exc
        verify_approval_grant(
            bundle,
            _load_approval_verifier(self.public_key_path),
        )
        now = datetime.now(UTC)
        if bundle.grant.plan != plan.binding:
            raise SecurityError("external approval does not bind the current exact plan")
        if (
            bundle.grant.issued_at > now
            or bundle.grant.expires_at <= now
            or plan.expires_at <= now
        ):
            raise SecurityError(
                "external approval is outside the current exact-plan lifetime"
            )
        return ApprovalValidation(
            grant=bundle.grant,
            source_path=approval_path,
        )

    def consume(self, approval: ApprovalValidation) -> None:
        """Burn approval before effect so a crash cannot replay it."""

        self.consumption.consume(approval.grant)


class ChangeSafeOperator:
    """Contract-independent plan, gate, evidence, and outcome helpers."""

    def __init__(
        self,
        *,
        tenant_id: str,
        deployment_namespace: str,
        approval_broker: ExternalApprovalBroker | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.deployment_namespace = deployment_namespace
        self.approval_broker = approval_broker

    def build_effectful_plan(
        self,
        *,
        governance: EffectiveOperationGovernance,
        plan_id: UUID,
        nonce: UUID,
        intended_operator_id: UUID,
        target: TargetReference,
        parameters: tuple[PlanParameter, ...],
        preconditions: tuple[PreconditionBinding, ...],
        expected_postcondition: ExpectedPostcondition,
        compensation: CompensationDeclaration,
        created_at: datetime,
        not_before: datetime,
        expires_at: datetime,
        playbook_digest: str | None = None,
    ) -> OperatorPlan:
        """Build one immutable T2/T3 plan from resolved signed Governance.

        ``governance`` is intentionally accepted as the resolved immutable
        record rather than raw policy text. No Graph request component exists
        in this API.
        """

        if governance.authorization_mode not in {
            AuthorizationMode.EXPLICIT_PLAN,
            AuthorizationMode.DUAL_CONTROL,
        }:
            raise SecurityError(
                "Operator Foundation cannot fall back from T2/T3 to standing policy"
            )
        plan = OperatorPlan(
            plan_id=plan_id,
            nonce=nonce,
            operation_id=governance.operation_id,
            contract_id=governance.operation_id,
            contract_digest=governance.contract_digest,
            contract_manifest_digest=governance.contract_manifest_digest,
            effect_model_digest=governance.effect_model_digest,
            policy_digest=governance.policy_digest,
            playbook_digest=playbook_digest,
            tenant_id=governance.tenant_id,
            deployment_namespace=self.deployment_namespace,
            profile=governance.profile,
            intended_operator_id=intended_operator_id,
            effect=governance.effect,
            risk_tier=cast(Literal["T2", "T3"], governance.risk_tier.value),
            authorization_mode=cast(
                Literal[
                    AuthorizationMode.EXPLICIT_PLAN,
                    AuthorizationMode.DUAL_CONTROL,
                ],
                governance.authorization_mode,
            ),
            target=target,
            parameters=parameters,
            preconditions=preconditions,
            expected_postcondition=expected_postcondition,
            verification=governance.verification,
            compensation=compensation,
            created_at=created_at,
            not_before=not_before,
            expires_at=expires_at,
        )
        plan.validate_governance(governance)
        return plan

    @staticmethod
    def authorize_effectful_plan(
        *,
        plan: OperatorPlan,
        governance: EffectiveOperationGovernance,
        approvals: tuple[SignedOperatorApproval, ...],
        validator: ApprovalSetValidator,
        as_of: datetime,
    ) -> tuple[str, ...]:
        """Validate and atomically burn exact approval before any effect."""

        return validator.validate(
            plan,
            governance,
            approvals,
            as_of=as_of,
            purpose="execution",
            consume=True,
        )

    @staticmethod
    def permission_impact(
        contract: ContractSpec,
        *,
        changed_fields: list[str],
        excludes: list[str],
        target_count: int = 1,
    ) -> PermissionImpactPreview:
        return PermissionImpactPreview(
            contract_id=contract.id,
            risk_tier=contract.risk_tier,
            graph_method=contract.graph.method,
            graph_endpoint_template=contract.graph.endpoint,
            delegated_scopes=contract.permissions.delegated_scopes,
            operator_roles=contract.permissions.operator_roles,
            target_count=target_count,
            changed_fields=changed_fields,
            fences=contract.resource_fences,
            excludes=excludes,
        )

    def build_plan(
        self,
        *,
        contract: ContractSpec,
        authorization: AuthorizationDecision,
        operator_id: str,
        idempotency_key: UUID,
        snapshot: SnapshotT,
        precondition_digest: str,
        requested: dict[str, str],
        normalized_parameters: dict[str, Any],
        target_fingerprint: str,
        changed_fields: list[str],
        permission_impact: PermissionImpactPreview,
        now: datetime,
    ) -> ChangeSafePlan[SnapshotT]:
        plan_id = uuid5(
            NAMESPACE_URL,
            (
                f"m365-secure-mcp:{self.deployment_namespace}:"
                f"{contract.id}:{idempotency_key}"
            ),
        )
        expires_at = now + timedelta(seconds=contract.plan_ttl_seconds)
        binding = None
        if authorization.mode is AuthorizationMode.EXPLICIT_PLAN:
            binding = ChangePlanBinding(
                plan_id=plan_id,
                contract_id=contract.id,
                contract_digest=sha256_digest(contract),
                policy_digest=authorization.policy_digest,
                tenant_id=UUID(self.tenant_id),
                deployment_namespace=self.deployment_namespace,
                profile=authorization.profile,
                operator_id=UUID(operator_id),
                authorization_mode="explicit_plan",
                normalized_parameters_digest=sha256_digest(
                    normalized_parameters
                ),
                target_fingerprint=target_fingerprint,
                precondition_digest=precondition_digest,
                permission_impact_digest=sha256_digest(permission_impact),
                changed_fields=changed_fields,
                verification=contract.verification,
                compensation=contract.compensation,
                created_at=now,
                expires_at=expires_at,
            )
        plan = ChangeSafePlan(
            plan_id=plan_id,
            created_at=now,
            expires_at=expires_at,
            snapshot=snapshot,
            requested=requested,
            changed_fields=changed_fields,
            permission_impact=permission_impact,
            authorization=authorization,
            contract_digest=sha256_digest(contract),
            binding=binding,
        )
        if self.approval_broker is not None and binding is not None:
            return self.approval_broker.prepare(plan)
        return plan

    @staticmethod
    def base_record(
        *,
        status: OperationStatus,
        reason_code: str,
        operator_action: str,
        responsible_party: ResponsibleParty,
        plan: ChangeSafePlan[Any],
        evidence_reference: str,
        safe_to_retry: bool,
        new_plan_required: bool,
        policy_change_required: bool = False,
        contract_change_required: bool = False,
    ) -> OperationRecord:
        details: dict[str, Any] = {}
        if plan.plan_digest is not None:
            details["plan_digest"] = plan.plan_digest
            details["approval_is_external"] = True
            details["approval_is_tool_argument"] = False
        return OperationRecord(
            status=status,
            reason_code=reason_code,
            operator_action=operator_action,
            responsible_party=responsible_party,
            authorization_mode=plan.authorization.mode,
            authorization_basis=plan.authorization.basis,
            required_profile=plan.authorization.profile.value,
            policy_change_required=policy_change_required,
            contract_change_required=contract_change_required,
            new_plan_required=new_plan_required,
            safe_to_retry=safe_to_retry,
            evidence_reference=evidence_reference,
            plan_id=plan.plan_id,
            plan_expires_at=plan.expires_at,
            permission_impact=plan.permission_impact,
            changed_fields=plan.changed_fields,
            details=details,
        )

    def authorization_gate(
        self,
        plan: ChangeSafePlan[Any],
        *,
        evidence_reference: str,
    ) -> ApprovalValidation | None:
        if plan.authorization.mode is AuthorizationMode.STANDING_POLICY:
            return None
        if plan.authorization.mode is not AuthorizationMode.EXPLICIT_PLAN:
            raise GovernedOperationError(
                "authorization mode is not implemented for this T1 engine",
                self.base_record(
                    status=OperationStatus.DENIED_BY_POLICY,
                    reason_code="STRONGER_AUTHORIZATION_NOT_AVAILABLE",
                    operator_action=(
                        "Use a host integration implementing the signed "
                        "dual-control or break-glass contract."
                    ),
                    responsible_party=ResponsibleParty.GOVERNANCE_OWNER,
                    plan=plan,
                    evidence_reference=evidence_reference,
                    safe_to_retry=False,
                    new_plan_required=False,
                    policy_change_required=False,
                ),
            )
        try:
            approval = (
                self.approval_broker.validate(plan)
                if self.approval_broker is not None
                else None
            )
        except SecurityError as exc:
            raise GovernedOperationError(
                str(exc),
                self.base_record(
                    status=OperationStatus.BLOCKED_PRECONDITION,
                    reason_code="EXTERNAL_APPROVAL_INVALID",
                    operator_action=(
                        "Reject the approval artifact. Generate a fresh exact "
                        "plan and have the external host sign only that request."
                    ),
                    responsible_party=ResponsibleParty.OPERATOR,
                    plan=plan,
                    evidence_reference=evidence_reference,
                    safe_to_retry=False,
                    new_plan_required=True,
                ),
            ) from exc
        if approval is None:
            broker_configured = self.approval_broker is not None
            raise GovernedOperationError(
                "host approval is required",
                self.base_record(
                    status=OperationStatus.AWAITING_APPROVAL,
                    reason_code=(
                        "HOST_APPROVAL_REQUIRED"
                        if broker_configured
                        else "APPROVAL_BROKER_NOT_CONFIGURED"
                    ),
                    operator_action=(
                        (
                            "Approve the exact private plan through the configured "
                            "external host broker; approval is never a tool argument."
                        )
                        if broker_configured
                        else (
                            "Configure an external approval broker and Ed25519 "
                            "trust anchor for this write process."
                        )
                    ),
                    responsible_party=(
                        ResponsibleParty.OPERATOR
                        if broker_configured
                        else ResponsibleParty.GOVERNANCE_OWNER
                    ),
                    plan=plan,
                    evidence_reference=evidence_reference,
                    safe_to_retry=False,
                    new_plan_required=False,
                ),
            )
        return approval

    def ensure_fresh(
        self,
        plan: ChangeSafePlan[Any],
        *,
        evidence_reference: str,
    ) -> None:
        if datetime.now(UTC) >= plan.expires_at:
            raise GovernedOperationError(
                "operation plan expired",
                self.base_record(
                    status=OperationStatus.PLAN_EXPIRED,
                    reason_code="PLAN_EXPIRED",
                    operator_action=(
                        "Regenerate the plan with a new idempotency key and "
                        "fresh preconditions."
                    ),
                    responsible_party=ResponsibleParty.OPERATOR,
                    plan=plan,
                    evidence_reference=evidence_reference,
                    safe_to_retry=True,
                    new_plan_required=True,
                ),
            )

    def consume_approval(
        self,
        approval: ApprovalValidation | None,
    ) -> None:
        if approval is None:
            return
        if self.approval_broker is None:
            raise SecurityError("external approval broker is unavailable")
        self.approval_broker.consume(approval)

    @staticmethod
    def uncertain_record(
        *,
        plan: ChangeSafePlan[Any],
        evidence_reference: str,
        reason_code: str,
        operator_action: str,
    ) -> OperationRecord:
        return ChangeSafeOperator.base_record(
            status=OperationStatus.EXECUTED_UNCERTAIN,
            reason_code=reason_code,
            operator_action=operator_action,
            responsible_party=ResponsibleParty.OPERATOR,
            plan=plan,
            evidence_reference=evidence_reference,
            safe_to_retry=False,
            new_plan_required=False,
        )

    @staticmethod
    def verified_record(
        *,
        operation_id: UUID,
        plan: ChangeSafePlan[Any],
        contract: ContractSpec,
        evidence_reference: str,
        target_fingerprint: str,
        capsule_reference: str | None,
    ) -> OperationRecord:
        created_at = datetime.now(UTC)
        change = ChangeRecord(
            operation_id=operation_id,
            contract_id=contract.id,
            contract_digest=plan.contract_digest,
            policy_digest=plan.authorization.policy_digest,
            target_fingerprint=target_fingerprint,
            changed_fields=plan.changed_fields,
            authorization_mode=plan.authorization.mode,
            authorization_basis=plan.authorization.basis,
            verification=contract.verification,
            compensation=contract.compensation.value,
            recovery_capsule_reference=capsule_reference,
            created_at=created_at,
        )
        receipt = GovernedReceipt(
            operation_id=operation_id,
            contract_id=contract.id,
            status=OperationStatus.EXECUTED_VERIFIED,
            contract_digest=plan.contract_digest,
            policy_digest=plan.authorization.policy_digest,
            authorization_basis=plan.authorization.basis,
            verification=contract.verification,
            change_record_reference=f"change:{operation_id}",
            evidence_reference=evidence_reference,
            created_at=created_at,
        )
        return OperationRecord(
            status=OperationStatus.EXECUTED_VERIFIED,
            reason_code="POST_READ_MATCHED",
            operator_action="No further action is required.",
            responsible_party=ResponsibleParty.NONE,
            authorization_mode=plan.authorization.mode,
            authorization_basis=plan.authorization.basis,
            required_profile=plan.authorization.profile.value,
            policy_change_required=False,
            contract_change_required=False,
            new_plan_required=False,
            safe_to_retry=False,
            evidence_reference=evidence_reference,
            plan_id=plan.plan_id,
            plan_expires_at=plan.expires_at,
            permission_impact=plan.permission_impact,
            changed_fields=plan.changed_fields,
            receipt=receipt,
            change_record=change,
            details={
                "target_count": 1,
                "stored_m365_values_in_receipt": False,
                "admin_consent_is_manual": True,
                "verification_mode": contract.verification.value,
            },
        )
