"""Common deterministic operation, finding, receipt, and change schemas."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .contract_manifest import AuthorizationMode, RiskTier, VerificationMode


class OperationStatus(StrEnum):
    DENIED_OUT_OF_CONTRACT = "DENIED_OUT_OF_CONTRACT"
    DENIED_BY_POLICY = "DENIED_BY_POLICY"
    BLOCKED_PRECONDITION = "BLOCKED_PRECONDITION"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    PLAN_EXPIRED = "PLAN_EXPIRED"
    EXECUTED_VERIFIED = "EXECUTED_VERIFIED"
    EXECUTED_ACCEPTED = "EXECUTED_ACCEPTED"
    EXECUTED_UNCERTAIN = "EXECUTED_UNCERTAIN"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    HALTED_BY_OPERATOR = "HALTED_BY_OPERATOR"
    CANCELLED_BEFORE_EFFECT = "CANCELLED_BEFORE_EFFECT"


class PlaybookStatus(StrEnum):
    PLAYBOOK_PLANNED = "PLAYBOOK_PLANNED"
    PLAYBOOK_RUNNING = "PLAYBOOK_RUNNING"
    PLAYBOOK_PARTIALLY_APPLIED = "PLAYBOOK_PARTIALLY_APPLIED"
    PLAYBOOK_COMPENSATION_REQUIRED = "PLAYBOOK_COMPENSATION_REQUIRED"
    PLAYBOOK_COMPLETED_VERIFIED = "PLAYBOOK_COMPLETED_VERIFIED"
    PLAYBOOK_HALTED = "PLAYBOOK_HALTED"


class ResponsibleParty(StrEnum):
    OPERATOR = "OPERATOR"
    TENANT_ADMIN = "TENANT_ADMIN"
    GOVERNANCE_OWNER = "GOVERNANCE_OWNER"
    PRODUCT_MAINTAINER = "PRODUCT_MAINTAINER"
    NONE = "NONE"


class AlignmentStatus(StrEnum):
    ALIGNED = "aligned"
    NOT_ALIGNED = "not_aligned"
    NOT_APPLICABLE = "not_applicable"
    NOT_EVALUATED = "not_evaluated"
    EXCEPTION_APPROVED = "exception_approved"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Finding(StrictModel):
    finding_id: str = Field(min_length=3, max_length=128)
    control_id: str = Field(min_length=3, max_length=128)
    status: str = Field(min_length=2, max_length=64)
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    summary: str = Field(min_length=3, max_length=500)
    evidence_reference: str | None = Field(default=None, max_length=256)
    remediation_contract_id: str | None = Field(default=None, max_length=128)
    alignment: AlignmentStatus = AlignmentStatus.NOT_EVALUATED
    operator_action: str = Field(
        default="Review the referenced evidence.",
        min_length=3,
        max_length=500,
    )
    responsible_party: ResponsibleParty = ResponsibleParty.OPERATOR
    baseline_reference: str | None = Field(default=None, max_length=128)


class PermissionImpactPreview(StrictModel):
    contract_id: str
    risk_tier: RiskTier
    graph_method: str
    graph_endpoint_template: str
    delegated_scopes: list[str]
    operator_roles: list[str]
    target_count: int = Field(ge=0, le=100)
    changed_fields: list[str]
    fences: list[str]
    excludes: list[str]
    admin_consent_is_manual: bool = True


class ChangeRecord(StrictModel):
    schema_version: str = "1.0"
    operation_id: UUID
    contract_id: str
    contract_digest: str
    policy_digest: str
    target_fingerprint: str
    changed_fields: list[str]
    authorization_mode: AuthorizationMode
    authorization_basis: str
    verification: VerificationMode
    compensation: str
    recovery_capsule_reference: str | None = None
    created_at: datetime


class GovernedReceipt(StrictModel):
    schema_version: str = "1.0"
    operation_id: UUID
    contract_id: str
    status: OperationStatus
    contract_digest: str
    policy_digest: str
    authorization_basis: str
    verification: VerificationMode
    change_record_reference: str
    evidence_reference: str
    created_at: datetime


class OperationRecord(StrictModel):
    """Operator-facing result with one explicit next safe action."""

    schema_version: str = "1.0"
    status: OperationStatus
    reason_code: str
    operator_action: str
    responsible_party: ResponsibleParty
    authorization_mode: AuthorizationMode
    authorization_basis: str
    required_profile: str
    policy_change_required: bool
    contract_change_required: bool
    new_plan_required: bool
    safe_to_retry: bool
    retry_after: float | None = None
    evidence_reference: str
    plan_id: UUID | None = None
    plan_expires_at: datetime | None = None
    permission_impact: PermissionImpactPreview | None = None
    changed_fields: list[str] = Field(default_factory=list)
    receipt: GovernedReceipt | None = None
    change_record: ChangeRecord | None = None
    details: dict[str, Any] = Field(default_factory=dict)
