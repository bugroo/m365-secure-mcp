"""Signed, tenant-private governance policies.

The tenant administrator owns this policy and its signing material. Runtime
may enforce it but cannot edit, sign, relax, or replace it.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_manifest import (
    AuthorizationMode,
    ContractManifest,
    ContractSpec,
    RiskTier,
    authorization_is_at_least,
    canonical_json,
    sha256_digest,
)
from .playbook_manifest import PlaybookManifest, PlaybookSpec
from .security import PrivateStateError, SecurityError, read_private_file

MAX_GOVERNANCE_POLICY_BYTES = 512_000
MAX_PUBLIC_KEY_BYTES = 4_096


class GovernanceProfileName(StrEnum):
    ROUTINE_READ = "routine-read"
    ROUTINE_WRITE = "routine-write"
    PRIVILEGED_READ = "privileged-read"
    SELECTED_WRITE = "selected-write"
    BREAK_GLASS = "break-glass"


class AssuranceDomainName(StrEnum):
    """Tenant-private baseline domains emitted by the Entra posture contract."""

    CONDITIONAL_ACCESS = "conditional_access"
    PERMANENT_ROLE_ASSIGNMENTS = "permanent_role_assignments"
    ACTIVE_ROLE_ASSIGNMENTS = "active_role_assignments"
    ELIGIBLE_ROLE_ASSIGNMENTS = "eligible_role_assignments"


class PermissionGrantKind(StrEnum):
    """Permission grant types compared by the signed tenant baseline."""

    DELEGATED = "delegated"
    APPLICATION = "application"


class ApplicationCredentialKind(StrEnum):
    """Credential metadata classes evaluated by the application baseline."""

    PASSWORD = "password"  # noqa: S105
    KEY = "key"


class DriftSeverity(StrEnum):
    """Administrator-governed severity for a mismatch with a signed baseline."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GovernanceProfile(StrictModel):
    """One administrator-approved profile within a tenant policy."""

    enabled_contracts: list[str] = Field(default_factory=list)
    enabled_playbooks: list[str] = Field(default_factory=list)
    maximum_targets_per_operation: int = Field(default=1, ge=1, le=100)
    write_window_utc: str | None = Field(
        default=None,
        pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]-(?:[01][0-9]|2[0-3]):[0-5][0-9]$",
    )
    break_glass_ttl_seconds: int | None = Field(default=None, ge=300, le=3_600)

    @field_validator("enabled_contracts")
    @classmethod
    def unique_contracts(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("enabled contracts must be unique and sorted")
        return value

    @field_validator("enabled_playbooks")
    @classmethod
    def unique_playbooks(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("enabled playbooks must be unique and sorted")
        return value


class GovernanceResources(StrictModel):
    """Tenant-private allowlists and explicit protected-resource fences."""

    tenants: list[UUID] = Field(min_length=1, max_length=1)
    users: list[UUID] = Field(default_factory=list, max_length=10_000)
    groups: list[UUID] = Field(default_factory=list, max_length=10_000)
    applications: list[UUID] = Field(default_factory=list, max_length=100)
    service_principals: list[UUID] = Field(default_factory=list, max_length=100)
    protected_user_ids: list[UUID] = Field(default_factory=list, max_length=1_000)

    @field_validator("applications", "service_principals")
    @classmethod
    def directory_resources_are_unique_and_sorted(
        cls,
        value: list[UUID],
    ) -> list[UUID]:
        if [str(item) for item in value] != sorted(
            {str(item) for item in value}
        ):
            raise ValueError(
                "application and service-principal resources must be unique and sorted"
            )
        return value

    @model_validator(mode="after")
    def protected_users_are_known(self) -> GovernanceResources:
        protected = set(self.protected_user_ids)
        if protected - set(self.users):
            raise ValueError("protected users must also be present in the user allowlist")
        return self


class AssuranceDomainBaseline(StrictModel):
    """Expected keyed digest for one complete, minimized posture domain."""

    expected_digest: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    drift_severity: DriftSeverity


class AssuranceException(StrictModel):
    """Explicit, expiring exception approved in the signed Governance plane."""

    exception_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    control_id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_.-]{2,127}$")
    domain: AssuranceDomainName
    rationale: str = Field(min_length=8, max_length=500)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def expiry_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("assurance exception expiry must include a UTC offset")
        return value


class IdentityGovernanceBaseline(StrictModel):
    """Signed tenant baseline containing digests, never raw Microsoft 365 data."""

    baseline_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    version: int = Field(ge=1, le=1_000_000)
    captured_at: datetime
    source_snapshot_reference: str = Field(
        pattern=r"^snapshot:[0-9a-f-]{36}$",
    )
    domains: dict[AssuranceDomainName, AssuranceDomainBaseline]
    exceptions: list[AssuranceException] = Field(default_factory=list, max_length=100)

    @field_validator("captured_at")
    @classmethod
    def captured_at_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("baseline capture time must include a UTC offset")
        return value

    @model_validator(mode="after")
    def complete_and_unique(self) -> IdentityGovernanceBaseline:
        if set(self.domains) != set(AssuranceDomainName):
            raise ValueError(
                "identity-governance baseline must cover all posture domains"
            )
        exception_ids = [item.exception_id for item in self.exceptions]
        if exception_ids != sorted(set(exception_ids)):
            raise ValueError("assurance exceptions must be unique and sorted")
        return self


def _default_delegated_consent_types() -> list[
    Literal["AllPrincipals", "Principal"]
]:
    return ["AllPrincipals"]


class PermissionGrantTarget(StrictModel):
    """One allowlisted service principal and its contract-derived permissions."""

    service_principal_id: UUID
    contract_ids: list[str] = Field(min_length=1, max_length=100)
    allowed_delegated_consent_types: list[
        Literal["AllPrincipals", "Principal"]
    ] = Field(default_factory=_default_delegated_consent_types)

    @field_validator("contract_ids")
    @classmethod
    def contract_ids_are_unique_and_sorted(
        cls,
        value: list[str],
    ) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("permission baseline contracts must be unique and sorted")
        return value

    @field_validator("allowed_delegated_consent_types")
    @classmethod
    def consent_types_are_unique_and_sorted(
        cls,
        value: list[Literal["AllPrincipals", "Principal"]],
    ) -> list[Literal["AllPrincipals", "Principal"]]:
        if not value or value != sorted(set(value)):
            raise ValueError(
                "allowed delegated consent types must be non-empty, unique, and sorted"
            )
        return value


class PermissionGrantException(StrictModel):
    """Exact, temporary exception for one observed permission grant."""

    exception_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    service_principal_id: UUID
    kind: PermissionGrantKind
    resource_app_id: UUID
    permission_value: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
    )
    consent_type: Literal["AllPrincipals", "Principal"] | None = None
    rationale: str = Field(min_length=8, max_length=500)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def expiry_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("permission-grant exception expiry must include a UTC offset")
        return value

    @model_validator(mode="after")
    def consent_type_matches_kind(self) -> PermissionGrantException:
        if self.kind is PermissionGrantKind.DELEGATED:
            if self.consent_type is None:
                raise ValueError(
                    "delegated permission exceptions require a consent type"
                )
        elif self.consent_type is not None:
            raise ValueError(
                "application permission exceptions cannot have a consent type"
            )
        return self


class PermissionGrantBaseline(StrictModel):
    """Signed desired state derived from exact global contract IDs."""

    baseline_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    version: int = Field(ge=1, le=1_000_000)
    targets: list[PermissionGrantTarget] = Field(min_length=1, max_length=100)
    exceptions: list[PermissionGrantException] = Field(
        default_factory=list,
        max_length=500,
    )

    @model_validator(mode="after")
    def targets_and_exceptions_are_bounded(
        self,
    ) -> PermissionGrantBaseline:
        target_ids = [str(item.service_principal_id) for item in self.targets]
        if target_ids != sorted(set(target_ids)):
            raise ValueError(
                "permission-grant baseline targets must be unique and sorted"
            )
        exception_ids = [item.exception_id for item in self.exceptions]
        if exception_ids != sorted(set(exception_ids)):
            raise ValueError(
                "permission-grant exceptions must be unique and sorted"
            )
        if {
            item.service_principal_id for item in self.exceptions
        } - {
            item.service_principal_id for item in self.targets
        }:
            raise ValueError(
                "permission-grant exceptions must reference baseline targets"
            )
        return self


class ApplicationCredentialTarget(StrictModel):
    """Signed credential and ownership posture for one application object."""

    application_id: UUID
    minimum_owner_count: int = Field(default=2, ge=1, le=20)
    expiry_warning_days: int = Field(default=30, ge=1, le=365)
    password_credentials_allowed: bool = False
    maximum_active_password_credentials: int = Field(default=0, ge=0, le=20)
    maximum_active_key_credentials: int = Field(default=2, ge=0, le=20)

    @model_validator(mode="after")
    def password_limit_matches_policy(self) -> ApplicationCredentialTarget:
        if (
            not self.password_credentials_allowed
            and self.maximum_active_password_credentials != 0
        ):
            raise ValueError(
                "prohibited password credentials require a zero active limit"
            )
        return self


class ApplicationCredentialException(StrictModel):
    """Exact, expiring exception for one application posture control."""

    exception_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    application_id: UUID
    control_id: str = Field(pattern=r"^APP_[A-Z0-9_]{3,100}$")
    credential_kind: ApplicationCredentialKind | None = None
    credential_key_id: UUID | None = None
    rationale: str = Field(min_length=8, max_length=500)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def expiry_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "application-credential exception expiry must include a UTC offset"
            )
        return value

    @model_validator(mode="after")
    def credential_selector_is_complete(
        self,
    ) -> ApplicationCredentialException:
        credential_controls = {
            "APP_CREDENTIAL_INVALID_WINDOW",
            "APP_CREDENTIAL_NO_EXPIRY",
            "APP_CREDENTIAL_EXPIRED",
            "APP_CREDENTIAL_EXPIRING",
            "APP_PASSWORD_CREDENTIAL_PROHIBITED",
        }
        application_controls = {
            "APP_OWNER_COUNT_BELOW_MINIMUM",
            "APP_ACTIVE_PASSWORD_CREDENTIALS_EXCEED_MAXIMUM",
            "APP_ACTIVE_KEY_CREDENTIALS_EXCEED_MAXIMUM",
        }
        if self.control_id not in credential_controls | application_controls:
            raise ValueError(
                "application-credential exception references an unknown control"
            )
        if (self.credential_kind is None) != (self.credential_key_id is None):
            raise ValueError(
                "credential exceptions require both kind and key ID"
            )
        if (
            self.control_id in credential_controls
            and self.credential_key_id is None
        ):
            raise ValueError(
                "credential-specific controls require an exact credential selector"
            )
        if (
            self.control_id in application_controls
            and self.credential_key_id is not None
        ):
            raise ValueError(
                "application-level controls cannot select one credential"
            )
        return self


class ApplicationCredentialBaseline(StrictModel):
    """Signed posture expectations for an exact application allowlist."""

    baseline_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    version: int = Field(ge=1, le=1_000_000)
    targets: list[ApplicationCredentialTarget] = Field(
        min_length=1,
        max_length=100,
    )
    exceptions: list[ApplicationCredentialException] = Field(
        default_factory=list,
        max_length=500,
    )

    @model_validator(mode="after")
    def targets_and_exceptions_are_bounded(
        self,
    ) -> ApplicationCredentialBaseline:
        target_ids = [str(item.application_id) for item in self.targets]
        if target_ids != sorted(set(target_ids)):
            raise ValueError(
                "application-credential targets must be unique and sorted"
            )
        exception_ids = [item.exception_id for item in self.exceptions]
        if exception_ids != sorted(set(exception_ids)):
            raise ValueError(
                "application-credential exceptions must be unique and sorted"
            )
        if {
            item.application_id for item in self.exceptions
        } - {
            item.application_id for item in self.targets
        }:
            raise ValueError(
                "application-credential exceptions must reference baseline targets"
            )
        return self


class GovernancePolicy(StrictModel):
    """Unsigned governance policy body; signatures wrap this exact object."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: UUID
    active_profile: GovernanceProfileName
    profiles: dict[GovernanceProfileName, GovernanceProfile]
    resources: GovernanceResources
    authorization_overrides: dict[str, AuthorizationMode] = Field(default_factory=dict)
    identity_governance_baseline: IdentityGovernanceBaseline | None = None
    permission_grant_baseline: PermissionGrantBaseline | None = None
    application_credential_baseline: ApplicationCredentialBaseline | None = None
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_manifest_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    issued_at: datetime
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_policy(self) -> GovernancePolicy:
        if self.tenant_id.int == 0:
            raise ValueError("placeholder tenant IDs are prohibited")
        if self.resources.tenants != [self.tenant_id]:
            raise ValueError("governance policy must fence exactly its own tenant")
        if self.active_profile not in self.profiles:
            raise ValueError("active governance profile is missing")
        if set(self.profiles) != set(GovernanceProfileName):
            raise ValueError(
                "governance policy must define all five standard profiles"
            )
        for name, profile in self.profiles.items():
            if name is GovernanceProfileName.BREAK_GLASS:
                if profile.break_glass_ttl_seconds is None:
                    raise ValueError(
                        "break-glass profile requires a bounded activation TTL"
                    )
            elif profile.break_glass_ttl_seconds is not None:
                raise ValueError(
                    "break-glass TTL is valid only on the break-glass profile"
                )
        if (
            any(profile.enabled_playbooks for profile in self.profiles.values())
            and self.playbook_manifest_digest is None
        ):
            raise ValueError(
                "enabled playbooks require a signed playbook manifest digest"
            )
        if self.issued_at.tzinfo is None:
            raise ValueError("issued_at must include a UTC offset")
        if self.identity_governance_baseline is not None:
            baseline = self.identity_governance_baseline
            if baseline.captured_at > self.issued_at:
                raise ValueError(
                    "assurance baseline cannot be captured after policy issuance"
                )
        if self.permission_grant_baseline is not None:
            target_ids = {
                item.service_principal_id
                for item in self.permission_grant_baseline.targets
            }
            if target_ids - set(self.resources.service_principals):
                raise ValueError(
                    "permission-grant baseline targets must be service-principal resources"
                )
        if self.application_credential_baseline is not None:
            target_ids = {
                item.application_id
                for item in self.application_credential_baseline.targets
            }
            if target_ids - set(self.resources.applications):
                raise ValueError(
                    "application-credential targets must be application resources"
                )
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise ValueError("expires_at must include a UTC offset")
            if self.expires_at <= self.issued_at:
                raise ValueError("governance policy expiry must follow issuance")
        if self.active_profile is GovernanceProfileName.BREAK_GLASS:
            ttl = self.profiles[
                GovernanceProfileName.BREAK_GLASS
            ].break_glass_ttl_seconds
            if (
                ttl is None
                or self.expires_at is None
                or (self.expires_at - self.issued_at).total_seconds() > ttl
            ):
                raise ValueError(
                    "active break-glass policy must expire within its signed TTL"
                )
        return self


class GovernanceSignature(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str = Field(min_length=3, max_length=100)
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signed_at: datetime
    signature: str = Field(min_length=80, max_length=128)

    @field_validator("signed_at")
    @classmethod
    def signed_at_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("governance signature time must include a UTC offset")
        return value


class SignedGovernancePolicy(StrictModel):
    policy: GovernancePolicy
    signature: GovernanceSignature


class GovernancePolicyError(SecurityError):
    """A signed tenant policy rejected an operation."""

    def __init__(self, message: str, *, reason_code: str = "DENIED_BY_POLICY") -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class AuthorizationDecision:
    mode: AuthorizationMode
    basis: Literal[
        "standing_policy",
        "explicit_plan",
        "dual_control",
        "break_glass",
        "prohibited",
    ]
    profile: GovernanceProfileName
    policy_digest: str


@dataclass(frozen=True)
class ReadAuthorizationDecision:
    mode: Literal["automatic_read"]
    basis: Literal["signed_policy"]
    profile: GovernanceProfileName
    policy_digest: str


@dataclass(frozen=True)
class VerifiedGovernancePolicy:
    """Verified policy plus its external trust anchor for TOCTOU revalidation."""

    bundle: SignedGovernancePolicy
    policy_digest: str
    source_path: Path
    public_key_path: Path

    @property
    def policy(self) -> GovernancePolicy:
        return self.bundle.policy

    def refresh(self) -> VerifiedGovernancePolicy:
        refreshed = load_verified_governance_policy(
            self.source_path,
            self.public_key_path,
        )
        if refreshed.policy_digest != self.policy_digest:
            raise GovernancePolicyError(
                "governance policy changed after preflight",
                reason_code="POLICY_CHANGED",
            )
        return refreshed

    def authorize_read(
        self,
        contract: ContractSpec,
        *,
        tenant_id: str,
    ) -> ReadAuthorizationDecision:
        """Authorize one automatic read from a signed read profile."""

        policy = self.policy
        now = datetime.now(UTC)
        if str(policy.tenant_id) != tenant_id:
            raise GovernancePolicyError(
                "governance policy tenant does not match the runtime tenant",
                reason_code="TENANT_FENCE_MISMATCH",
            )
        if policy.expires_at is not None and policy.expires_at <= now:
            raise GovernancePolicyError(
                "governance policy has expired",
                reason_code="POLICY_EXPIRED",
            )
        if policy.active_profile not in {
            GovernanceProfileName.ROUTINE_READ,
            GovernanceProfileName.PRIVILEGED_READ,
        }:
            raise GovernancePolicyError(
                "automatic read requires an active signed read profile",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )
        profile = policy.profiles[policy.active_profile]
        if contract.id not in profile.enabled_contracts:
            raise GovernancePolicyError(
                "contract is not enabled in the active governance profile",
                reason_code="DENIED_OUT_OF_CONTRACT",
            )
        if contract.graph.method != "GET":
            raise GovernancePolicyError(
                "read authorization cannot execute a write contract",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )
        mode = policy.authorization_overrides.get(
            contract.id,
            contract.authorization_mode,
        )
        if not authorization_is_at_least(mode, contract.authorization_mode):
            raise GovernancePolicyError(
                "governance policy attempts to weaken the contract authorization floor",
                reason_code="POLICY_DOWNGRADE_REJECTED",
            )
        if mode is not AuthorizationMode.AUTOMATIC_READ:
            raise GovernancePolicyError(
                "automatic read was hardened or prohibited by tenant policy",
                reason_code="DENIED_BY_POLICY",
            )
        return ReadAuthorizationDecision(
            mode="automatic_read",
            basis="signed_policy",
            profile=policy.active_profile,
            policy_digest=self.policy_digest,
        )

    def authorize_permission_grant_read(
        self,
        contract: ContractSpec,
        *,
        tenant_id: str,
        local_service_principal_ids: frozenset[str],
    ) -> tuple[ReadAuthorizationDecision, PermissionGrantBaseline]:
        """Authorize a complete scan of the exact signed and local target set."""

        decision = self.authorize_read(contract, tenant_id=tenant_id)
        baseline = self.policy.permission_grant_baseline
        if baseline is None:
            raise GovernancePolicyError(
                "permission-grant drift requires a signed target baseline",
                reason_code="BASELINE_NOT_CONFIGURED",
            )
        target_ids = {
            str(item.service_principal_id)
            for item in baseline.targets
        }
        if not target_ids.issubset(local_service_principal_ids):
            raise GovernancePolicyError(
                "permission-grant targets are not all allowlisted by runtime policy",
                reason_code="RESOURCE_FENCE_MISMATCH",
            )
        return decision, baseline

    def authorize_application_credential_read(
        self,
        contract: ContractSpec,
        *,
        tenant_id: str,
        local_application_ids: frozenset[str],
    ) -> tuple[ReadAuthorizationDecision, ApplicationCredentialBaseline]:
        """Authorize posture collection for the exact signed/local app set."""

        decision = self.authorize_read(contract, tenant_id=tenant_id)
        baseline = self.policy.application_credential_baseline
        if baseline is None:
            raise GovernancePolicyError(
                "application credential posture requires a signed target baseline",
                reason_code="BASELINE_NOT_CONFIGURED",
            )
        maximum_targets = self.policy.profiles[
            decision.profile
        ].maximum_targets_per_operation
        if len(baseline.targets) > maximum_targets:
            raise GovernancePolicyError(
                "application target count exceeds the signed profile limit",
                reason_code="TARGET_LIMIT_EXCEEDED",
            )
        target_ids = {
            str(item.application_id)
            for item in baseline.targets
        }
        if not target_ids.issubset(local_application_ids):
            raise GovernancePolicyError(
                "application targets are not all allowlisted by runtime policy",
                reason_code="RESOURCE_FENCE_MISMATCH",
            )
        return decision, baseline

    def authorize_playbook_read(
        self,
        playbook: PlaybookSpec,
        *,
        contract_manifest: ContractManifest,
        tenant_id: str,
    ) -> ReadAuthorizationDecision:
        """Authorize one fixed T0 playbook and all of its compiled nodes."""

        policy = self.policy
        now = datetime.now(UTC)
        if str(policy.tenant_id) != tenant_id:
            raise GovernancePolicyError(
                "governance policy tenant does not match the runtime tenant",
                reason_code="TENANT_FENCE_MISMATCH",
            )
        if policy.expires_at is not None and policy.expires_at <= now:
            raise GovernancePolicyError(
                "governance policy has expired",
                reason_code="POLICY_EXPIRED",
            )
        if policy.active_profile is not GovernanceProfileName.PRIVILEGED_READ:
            raise GovernancePolicyError(
                "workload-identity readiness requires privileged-read",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )
        profile = policy.profiles[policy.active_profile]
        if playbook.id not in profile.enabled_playbooks:
            raise GovernancePolicyError(
                "playbook is not enabled in the active governance profile",
                reason_code="DENIED_OUT_OF_CONTRACT",
            )
        if (
            playbook.risk_tier is not RiskTier.T0
            or playbook.authorization_mode is not AuthorizationMode.AUTOMATIC_READ
            or playbook.writes_permitted
        ):
            raise GovernancePolicyError(
                "read authorization cannot execute an effectful playbook",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )
        node_contracts = {
            node.contract_id
            for node in playbook.nodes
        }
        if not node_contracts.issubset(profile.enabled_contracts):
            raise GovernancePolicyError(
                "playbook node contract is not enabled in the active profile",
                reason_code="DENIED_OUT_OF_CONTRACT",
            )
        for contract_id in sorted(node_contracts):
            self.authorize_read(
                contract_manifest.contract(contract_id),
                tenant_id=tenant_id,
            )
        if (
            self.policy.permission_grant_baseline is None
            or self.policy.application_credential_baseline is None
        ):
            raise GovernancePolicyError(
                "workload-identity readiness requires both signed baselines",
                reason_code="BASELINE_NOT_CONFIGURED",
            )
        return ReadAuthorizationDecision(
            mode="automatic_read",
            basis="signed_policy",
            profile=policy.active_profile,
            policy_digest=self.policy_digest,
        )

    def authorize(
        self,
        contract: ContractSpec,
        *,
        tenant_id: str,
        target_user_id: str,
        local_target_user_ids: frozenset[str],
    ) -> AuthorizationDecision:
        policy = self.policy
        now = datetime.now(UTC)
        if str(policy.tenant_id) != tenant_id:
            raise GovernancePolicyError(
                "governance policy tenant does not match the runtime tenant",
                reason_code="TENANT_FENCE_MISMATCH",
            )
        if policy.expires_at is not None and policy.expires_at <= now:
            raise GovernancePolicyError(
                "governance policy has expired",
                reason_code="POLICY_EXPIRED",
            )
        profile = policy.profiles[policy.active_profile]
        if contract.id not in profile.enabled_contracts:
            raise GovernancePolicyError(
                "contract is not enabled in the active governance profile",
                reason_code="DENIED_OUT_OF_CONTRACT",
            )
        if profile.write_window_utc is not None:
            start_text, end_text = profile.write_window_utc.split("-", 1)
            start_hour, start_minute = (int(part) for part in start_text.split(":"))
            end_hour, end_minute = (int(part) for part in end_text.split(":"))
            start = (start_hour * 60) + start_minute
            end = (end_hour * 60) + end_minute
            current = (now.hour * 60) + now.minute
            inside_window = (
                start <= current < end
                if start < end
                else current >= start or current < end
            )
            if not inside_window:
                raise GovernancePolicyError(
                    "write is outside the signed governance window",
                    reason_code="WRITE_WINDOW_CLOSED",
                )
        target = UUID(target_user_id)
        if target not in policy.resources.users:
            raise GovernancePolicyError(
                "target user is not allowlisted by signed governance policy",
                reason_code="RESOURCE_FENCE_MISMATCH",
            )
        if target_user_id not in local_target_user_ids:
            raise GovernancePolicyError(
                "target user is not allowlisted by runtime policy",
                reason_code="RESOURCE_FENCE_MISMATCH",
            )
        if target in policy.resources.protected_user_ids:
            raise GovernancePolicyError(
                "target user is protected from this contract",
                reason_code="PROTECTED_RESOURCE",
            )

        mode = policy.authorization_overrides.get(
            contract.id,
            contract.authorization_mode,
        )
        if not authorization_is_at_least(mode, contract.authorization_mode):
            raise GovernancePolicyError(
                "governance policy attempts to weaken the contract authorization floor",
                reason_code="POLICY_DOWNGRADE_REJECTED",
            )
        basis_by_mode: dict[
            AuthorizationMode,
            Literal[
                "standing_policy",
                "explicit_plan",
                "dual_control",
                "break_glass",
                "prohibited",
            ],
        ] = {
            AuthorizationMode.STANDING_POLICY: "standing_policy",
            AuthorizationMode.EXPLICIT_PLAN: "explicit_plan",
            AuthorizationMode.DUAL_CONTROL: "dual_control",
            AuthorizationMode.BREAK_GLASS_ONLY: "break_glass",
            AuthorizationMode.PROHIBITED: "prohibited",
        }
        if mode in {AuthorizationMode.AUTOMATIC_READ, AuthorizationMode.PROHIBITED}:
            raise GovernancePolicyError(
                "write contract resolved to an invalid authorization mode",
                reason_code="DENIED_BY_POLICY",
            )
        return AuthorizationDecision(
            mode=mode,
            basis=basis_by_mode[mode],
            profile=policy.active_profile,
            policy_digest=self.policy_digest,
        )


def validate_policy_against_manifest(
    policy: GovernancePolicy,
    manifest: ContractManifest,
    playbook_manifest: PlaybookManifest | None = None,
) -> None:
    """Reject unknown contracts, profile misuse, and authorization downgrades."""

    contracts = {contract.id: contract for contract in manifest.contracts}
    playbooks = (
        {playbook.id: playbook for playbook in playbook_manifest.playbooks}
        if playbook_manifest is not None
        else {}
    )
    for profile_name, profile in policy.profiles.items():
        for contract_id in profile.enabled_contracts:
            contract = contracts.get(contract_id)
            if contract is None:
                raise GovernancePolicyError(
                    "governance profile references an unknown contract",
                    reason_code="UNKNOWN_CONTRACT",
                )
            if (
                profile_name
                in {
                    GovernanceProfileName.ROUTINE_READ,
                    GovernanceProfileName.PRIVILEGED_READ,
                }
                and contract.graph.method != "GET"
            ):
                raise GovernancePolicyError(
                    "read-only governance profile contains a write contract",
                    reason_code="PROFILE_CONTRACT_MISMATCH",
                )
            if (
                profile_name is GovernanceProfileName.ROUTINE_WRITE
                and contract.risk_tier not in {RiskTier.T0, RiskTier.T1}
            ):
                raise GovernancePolicyError(
                    "routine-write profile may contain only T0 or T1 contracts",
                    reason_code="PROFILE_CONTRACT_MISMATCH",
                )
            if contract.risk_tier is RiskTier.T4:
                raise GovernancePolicyError(
                    "prohibited T4 contracts cannot be enabled by tenant policy",
                    reason_code="DENIED_OUT_OF_CONTRACT",
                )
        for playbook_id in profile.enabled_playbooks:
            playbook = playbooks.get(playbook_id)
            if playbook is None:
                raise GovernancePolicyError(
                    "governance profile references an unknown playbook",
                    reason_code="UNKNOWN_PLAYBOOK",
                )
            if profile_name is not GovernanceProfileName.PRIVILEGED_READ:
                raise GovernancePolicyError(
                    "initial T0 playbooks require privileged-read",
                    reason_code="PROFILE_CONTRACT_MISMATCH",
                )
            if (
                playbook.risk_tier is not RiskTier.T0
                or playbook.authorization_mode
                is not AuthorizationMode.AUTOMATIC_READ
                or playbook.writes_permitted
            ):
                raise GovernancePolicyError(
                    "read profile contains an effectful playbook",
                    reason_code="PROFILE_CONTRACT_MISMATCH",
                )
            if {
                node.contract_id for node in playbook.nodes
            } - set(profile.enabled_contracts):
                raise GovernancePolicyError(
                    "playbook nodes must be enabled contracts in the same profile",
                    reason_code="PROFILE_CONTRACT_MISMATCH",
                )

    enabled_playbooks = {
        playbook_id
        for profile in policy.profiles.values()
        for playbook_id in profile.enabled_playbooks
    }
    if enabled_playbooks:
        if playbook_manifest is None:
            raise GovernancePolicyError(
                "enabled playbooks require the global playbook manifest",
                reason_code="PLAYBOOK_MANIFEST_REQUIRED",
            )
        if policy.playbook_manifest_digest != sha256_digest(playbook_manifest):
            raise GovernancePolicyError(
                "governance policy is bound to a different playbook manifest",
                reason_code="PLAYBOOK_MANIFEST_CHANGED",
            )

    for contract_id, override in policy.authorization_overrides.items():
        contract = contracts.get(contract_id)
        if contract is None:
            raise GovernancePolicyError(
                "authorization override references an unknown contract",
                reason_code="UNKNOWN_CONTRACT",
            )
        if not authorization_is_at_least(override, contract.authorization_mode):
            raise GovernancePolicyError(
                "governance policy attempts to weaken a contract authorization floor",
                reason_code="POLICY_DOWNGRADE_REJECTED",
            )

    if policy.permission_grant_baseline is not None:
        for target in policy.permission_grant_baseline.targets:
            for contract_id in target.contract_ids:
                contract = contracts.get(contract_id)
                if contract is None:
                    raise GovernancePolicyError(
                        "permission baseline references an unknown contract",
                        reason_code="UNKNOWN_CONTRACT",
                    )
                if contract.risk_tier is RiskTier.T4:
                    raise GovernancePolicyError(
                        "permission baseline cannot derive permissions from T4 contracts",
                        reason_code="DENIED_OUT_OF_CONTRACT",
                    )


def _load_verifier(path: Path) -> Ed25519PublicKey:
    try:
        encoded = read_private_file(
            path,
            max_bytes=MAX_PUBLIC_KEY_BYTES,
            label="governance public key",
        ).strip()
        raw = base64.b64decode(encoded, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise PrivateStateError("governance public key is invalid") from exc


def load_policy_signer(
    path: Path,
    *,
    passphrase: bytes,
) -> Ed25519PrivateKey:
    """Load owner-only Ed25519 signing material for an explicit CLI action."""

    payload = read_private_file(
        path,
        max_bytes=16_384,
        label="governance signing material",
    )
    try:
        signer = serialization.load_pem_private_key(
            payload,
            password=passphrase,
        )
    except (TypeError, ValueError) as exc:
        raise PrivateStateError("governance signing material is invalid") from exc
    if not isinstance(signer, Ed25519PrivateKey):
        raise PrivateStateError("governance signer must use Ed25519")
    return signer


def sign_governance_policy(
    policy: GovernancePolicy,
    signer: Ed25519PrivateKey,
    *,
    key_id: str,
    signed_at: datetime | None = None,
) -> SignedGovernancePolicy:
    canonical = canonical_json(policy)
    timestamp = signed_at or datetime.now(UTC)
    return SignedGovernancePolicy(
        policy=policy,
        signature=GovernanceSignature(
            key_id=key_id,
            policy_digest=sha256_digest(policy),
            signed_at=timestamp,
            signature=base64.b64encode(signer.sign(canonical)).decode("ascii"),
        ),
    )


def verify_governance_policy(
    bundle: SignedGovernancePolicy,
    verifier: Ed25519PublicKey,
) -> str:
    digest = sha256_digest(bundle.policy)
    if bundle.signature.policy_digest != digest:
        raise GovernancePolicyError(
            "governance policy digest mismatch",
            reason_code="POLICY_SIGNATURE_INVALID",
        )
    try:
        verifier.verify(
            base64.b64decode(bundle.signature.signature, validate=True),
            canonical_json(bundle.policy),
        )
    except (ValueError, InvalidSignature) as exc:
        raise GovernancePolicyError(
            "governance policy signature is invalid",
            reason_code="POLICY_SIGNATURE_INVALID",
        ) from exc
    return digest


def load_verified_governance_policy(
    path: Path,
    public_key_path: Path,
) -> VerifiedGovernancePolicy:
    try:
        document = json.loads(
            read_private_file(
                path,
                max_bytes=MAX_GOVERNANCE_POLICY_BYTES,
                label="governance policy",
            )
        )
        bundle = SignedGovernancePolicy.model_validate(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PrivateStateError("governance policy is malformed") from exc
    digest = verify_governance_policy(bundle, _load_verifier(public_key_path))
    return VerifiedGovernancePolicy(
        bundle=bundle,
        policy_digest=digest,
        source_path=path.expanduser(),
        public_key_path=public_key_path.expanduser(),
    )


def public_key_text(signer: Ed25519PrivateKey) -> str:
    raw = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii") + "\n"
