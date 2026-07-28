"""Machine-readable experience metadata derived from canonical contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .contract_manifest import (
    AuthorizationMode,
    CompensationClass,
    ContractEffect,
    ContractSpec,
    ContractSpecV2,
    RiskTier,
    VerificationMode,
    contract_effect,
)
from .operator_lifecycle import OperatorLifecycleStatus


class StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OperationMaturity(StrEnum):
    EXPERIMENTAL = "experimental"
    PREVIEW = "preview"
    STABLE = "stable"
    DEPRECATED = "deprecated"


class OperationReversibility(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    CONDITIONAL = "conditional"
    EXPLICIT_SEPARATE_OPERATION = "explicit_separate_operation"
    NOT_COMPENSATABLE = "not_compensatable"


class OperationPrivacyClass(StrEnum):
    OPAQUE_PUBLIC_PRIVATE_CAPSULE = "opaque_public_private_capsule"


class MCPAnnotationProjection(StrictFrozenModel):
    """Protocol hints only; Governance and runtime remain authoritative."""

    readOnlyHint: bool  # noqa: N815 - MCP wire field
    destructiveHint: bool  # noqa: N815 - MCP wire field
    idempotentHint: bool  # noqa: N815 - MCP wire field
    openWorldHint: bool  # noqa: N815 - MCP wire field


class OperationExperienceMetadata(StrictFrozenModel):
    schema_version: str = "1.0"
    operation_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    effect: ContractEffect
    authorization_tier: RiskTier
    approval_requirement: AuthorizationMode
    asynchronous: bool
    reversibility: OperationReversibility
    verification_mode: VerificationMode
    maturity: OperationMaturity
    privacy_class: OperationPrivacyClass
    public_terminal_states: tuple[OperatorLifecycleStatus, ...]
    annotations: MCPAnnotationProjection


_REVERSIBILITY = {
    CompensationClass.NOT_APPLICABLE: OperationReversibility.NOT_APPLICABLE,
    CompensationClass.CONDITIONAL_RESTORE: OperationReversibility.CONDITIONAL,
    CompensationClass.EXPLICIT_PLAYBOOK: (
        OperationReversibility.EXPLICIT_SEPARATE_OPERATION
    ),
    CompensationClass.NOT_COMPENSATABLE: (
        OperationReversibility.NOT_COMPENSATABLE
    ),
}


def project_operation_metadata(
    contract: ContractSpec | ContractSpecV2,
    *,
    maturity: OperationMaturity,
) -> OperationExperienceMetadata:
    """Project stable UX metadata without creating a runtime tool."""

    effect = contract_effect(contract)
    is_read = effect is ContractEffect.READ
    destructive_hint = effect in {
        ContractEffect.RELATIONSHIP_REMOVE,
        ContractEffect.STATE_TRANSITION,
        ContractEffect.INVOKE_ACTION,
    }
    asynchronous = contract.verification in {
        VerificationMode.ASYNC_STATUS,
        VerificationMode.RESOURCE_OBSERVED,
        VerificationMode.PROVIDER_ACKNOWLEDGED,
    }
    return OperationExperienceMetadata(
        operation_id=contract.id,
        effect=effect,
        authorization_tier=contract.risk_tier,
        approval_requirement=contract.authorization_mode,
        asynchronous=asynchronous,
        reversibility=_REVERSIBILITY[contract.compensation],
        verification_mode=contract.verification,
        maturity=maturity,
        privacy_class=OperationPrivacyClass.OPAQUE_PUBLIC_PRIVATE_CAPSULE,
        public_terminal_states=(
            OperatorLifecycleStatus.COMPLETED,
            OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
            OperatorLifecycleStatus.COMPENSATION_REQUIRED,
        ),
        annotations=MCPAnnotationProjection(
            readOnlyHint=is_read,
            destructiveHint=destructive_hint,
            idempotentHint=contract.idempotency.key_required or is_read,
            openWorldHint=True,
        ),
    )
