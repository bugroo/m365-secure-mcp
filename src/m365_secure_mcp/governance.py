"""Signed, tenant-private governance policies.

The tenant administrator owns this policy and its signing material. Runtime
may enforce it but cannot edit, sign, relax, or replace it.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Final, Literal, Self
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
    ContractEffect,
    ContractManifest,
    ContractSpec,
    ContractSpecV2,
    RiskTier,
    VerificationMode,
    authorization_is_at_least,
    canonical_json,
    effect_model_digest,
    effect_model_document,
    sha256_digest,
)
from .control_compatibility import (
    MAX_CONTROL_EVIDENCE_AGE_SECONDS,
    ControlCompatibilityMetadata,
    control_compatibility_digest,
    load_control_compatibility_metadata,
)
from .control_manifest import (
    CONTROL_ID_PATTERN,
    ControlLifecycleState,
    ControlManifest,
    load_global_control_manifest,
)
from .playbook_manifest import PlaybookManifest, PlaybookSpec
from .security import PrivateStateError, SecurityError, read_private_file

MAX_GOVERNANCE_POLICY_BYTES = 512_000
MAX_PUBLIC_KEY_BYTES = 4_096

CONTROL_EXCEPTION_SUBJECT_KINDS: Final[
    Mapping[tuple[str, int], frozenset[str]]
] = MappingProxyType(
    {
        ("entra.applications.active_credential_count", 1): frozenset(
            {"application"}
        ),
        ("entra.applications.credential_expiry_posture", 1): frozenset(
            {"application"}
        ),
        ("entra.applications.owner_coverage", 1): frozenset({"application"}),
        ("entra.applications.password_credential_policy", 1): frozenset(
            {"application"}
        ),
        ("entra.applications.permission_contract_closure", 1): frozenset(
            {"service_principal"}
        ),
        ("entra.conditional_access.mfa_policy_coverage", 1): frozenset(
            {"user", "group"}
        ),
        ("entra.directory_roles.permanent_active_assignment", 1): frozenset(
            {"user", "group", "application", "service_principal"}
        ),
        ("entra.profiles.contract_closure", 1): frozenset({"profile"}),
        ("entra.profiles.resource_fence_closure", 1): frozenset({"profile"}),
        ("entra.profiles.scope_closure", 1): frozenset({"profile"}),
    }
)


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


class ProfileDebtControl(StrEnum):
    """Deterministic profile-debt controls governed by the tenant baseline."""

    CURRENT_APP_BASELINE_MISSING = "PROFILE_CURRENT_APP_BASELINE_MISSING"
    PERMISSION_GRANT_DRIFT = "PROFILE_PERMISSION_GRANT_DRIFT"
    TOKEN_SCOPE_MISSING = "PROFILE_TOKEN_SCOPE_MISSING"  # noqa: S105
    TOKEN_SCOPE_UNEXPECTED = "PROFILE_TOKEN_SCOPE_UNEXPECTED"  # noqa: S105
    CONTRACT_BASELINE_MISMATCH = "PROFILE_CONTRACT_BASELINE_MISMATCH"
    POLICY_VERSION_STALE = "PROFILE_POLICY_VERSION_STALE"
    POLICY_AGE_STALE = "PROFILE_POLICY_AGE_STALE"
    CONTRACT_NO_RECENT_EVIDENCE = "PROFILE_CONTRACT_NO_RECENT_EVIDENCE"
    CONTRACT_PERSISTENT_FAILURE = "PROFILE_CONTRACT_PERSISTENT_FAILURE"
    RESOURCE_ALLOWLIST_UNUSED = "PROFILE_RESOURCE_ALLOWLIST_UNUSED"
    RESOURCE_FENCE_MISMATCH = "PROFILE_RESOURCE_FENCE_MISMATCH"


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


class ProfileDebtException(StrictModel):
    """Exact, expiring exception for one public scope/contract/resource subject."""

    exception_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    control_id: ProfileDebtControl
    subject: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
    )
    rationale: str = Field(min_length=8, max_length=500)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def expiry_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "profile-debt exception expiry must include a UTC offset"
            )
        return value


class ProfileDebtBaseline(StrictModel):
    """Signed customer thresholds for read-only profile debt analysis."""

    baseline_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    version: int = Field(ge=1, le=1_000_000)
    minimum_policy_version: int = Field(default=1, ge=1, le=1_000_000)
    maximum_policy_age_days: int = Field(default=90, ge=1, le=365)
    evidence_window_days: int = Field(default=30, ge=1, le=90)
    persistent_failure_threshold: int = Field(default=3, ge=1, le=100)
    severities: dict[ProfileDebtControl, DriftSeverity]
    exceptions: list[ProfileDebtException] = Field(
        default_factory=list,
        max_length=500,
    )

    @model_validator(mode="after")
    def controls_and_exceptions_are_complete(
        self,
    ) -> ProfileDebtBaseline:
        if set(self.severities) != set(ProfileDebtControl):
            raise ValueError(
                "profile-debt baseline must set severity for every control"
            )
        exception_ids = [item.exception_id for item in self.exceptions]
        if exception_ids != sorted(set(exception_ids)):
            raise ValueError(
                "profile-debt exceptions must be unique and sorted"
            )
        selectors = [
            (item.control_id.value, item.subject)
            for item in self.exceptions
        ]
        if len(selectors) != len(set(selectors)):
            raise ValueError(
                "profile-debt exceptions must have unique control subjects"
            )
        return self


class ControlSeverity(StrEnum):
    """Customer-approved authority for future Control Library assessments."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ControlGovernanceSetting(StrictModel):
    """Signed customer settings for one exact public control major version."""

    definition_major_version: int = Field(ge=1, le=1_000_000)
    severity: ControlSeverity
    maximum_evidence_age_seconds: int | None = Field(
        default=None,
        strict=True,
        ge=1,
        le=MAX_CONTROL_EVIDENCE_AGE_SECONDS,
    )
    allow_control_wide_exception: bool = False


class ControlWideSubjectSelector(StrictModel):
    """Explicit selector for the whole control, disabled unless policy opts in."""

    kind: Literal["control_wide"]


class DirectoryObjectSubjectSelector(StrictModel):
    """Exact tenant-fenced directory object selector; names and UPNs are absent."""

    kind: Literal["user", "group", "application", "service_principal"]
    object_id: UUID


class ProfileSubjectSelector(StrictModel):
    """Exact selector for the one active Governance profile."""

    kind: Literal["profile"]
    profile: GovernanceProfileName


ControlExceptionSubject = Annotated[
    ControlWideSubjectSelector
    | DirectoryObjectSubjectSelector
    | ProfileSubjectSelector,
    Field(discriminator="kind"),
]


def _subject_key(subject: ControlExceptionSubject) -> tuple[str, str]:
    if isinstance(subject, ControlWideSubjectSelector):
        return (subject.kind, "*")
    if isinstance(subject, ProfileSubjectSelector):
        return (subject.kind, subject.profile.value)
    return (subject.kind, str(subject.object_id))


class ControlException(StrictModel):
    """Exact, signed and expiring exception; never an authorization input."""

    exception_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    control_id: str = Field(pattern=CONTROL_ID_PATTERN)
    definition_major_version: int = Field(ge=1, le=1_000_000)
    subject: ControlExceptionSubject
    applies_to_status: Literal["not_aligned"]
    rationale: str = Field(min_length=8, max_length=1_000)
    approving_party_reference: str = Field(
        pattern=r"^approver:[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$"
    )
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("control exception timestamps must include a UTC offset")
        return value

    @model_validator(mode="after")
    def expiry_follows_issuance(self) -> ControlException:
        if self.expires_at <= self.issued_at:
            raise ValueError("control exception expiry must follow issuance")
        return self


class ControlLibraryGovernance(StrictModel):
    """Tenant-private binding and settings for the public Control Library."""

    control_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    control_manifest_schema_version: Literal["1.0"]
    control_library_version: str = Field(
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
    )
    control_compatibility_digest: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )
    enabled_control_ids: list[str] = Field(min_length=1, max_length=500)
    controls: dict[str, ControlGovernanceSetting]
    exceptions: list[ControlException] = Field(default_factory=list, max_length=1_000)

    @field_validator("enabled_control_ids")
    @classmethod
    def normalize_enabled_control_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("enabled control IDs must be unique")
        if any(re.fullmatch(CONTROL_ID_PATTERN, item) is None for item in value):
            raise ValueError("enabled control ID is malformed")
        return sorted(value)

    @field_validator("exceptions")
    @classmethod
    def normalize_exceptions(
        cls,
        value: list[ControlException],
    ) -> list[ControlException]:
        exception_ids = [item.exception_id for item in value]
        if len(exception_ids) != len(set(exception_ids)):
            raise ValueError("control exception IDs must be unique")
        return sorted(value, key=lambda item: item.exception_id)

    @model_validator(mode="after")
    def settings_and_exceptions_are_exact(self) -> ControlLibraryGovernance:
        if set(self.controls) != set(self.enabled_control_ids):
            raise ValueError(
                "every enabled control requires exactly one signed control setting"
            )
        selector_groups: dict[tuple[str, int], list[tuple[str, str]]] = {}
        for exception in self.exceptions:
            setting = self.controls.get(exception.control_id)
            if setting is None:
                raise ValueError("control exception references a disabled control")
            if (
                exception.definition_major_version
                != setting.definition_major_version
            ):
                raise ValueError(
                    "control exception definition major does not match its setting"
                )
            key = (
                exception.control_id,
                exception.definition_major_version,
            )
            selector_groups.setdefault(key, []).append(
                _subject_key(exception.subject)
            )
        for selectors in selector_groups.values():
            if len(selectors) != len(set(selectors)):
                raise ValueError("control exceptions contain an ambiguous overlap")
            if any(kind == "control_wide" for kind, _ in selectors) and len(
                selectors
            ) > 1:
                raise ValueError("control-wide and exact exceptions cannot overlap")
        return self


class ResourceFenceType(StrEnum):
    """Closed resource classes supported by operational Governance."""

    TENANT = "tenant"
    USER = "user"
    GROUP = "group"
    DEVICE = "device"
    POLICY = "policy"
    APPLICATION = "application"
    SERVICE_PRINCIPAL = "service_principal"


class ProtectedObjectPolicy(StrEnum):
    """How a compiled operation treats protected resources."""

    EXCLUDE_PROTECTED = "exclude_protected"
    NOT_APPLICABLE = "not_applicable"


class AsyncRequirement(StrEnum):
    """Provider-completion requirement fixed by signed Governance."""

    SYNCHRONOUS_ONLY = "synchronous_only"
    PROVIDER_ASYNC_ALLOWED = "provider_async_allowed"
    PROVIDER_ASYNC_REQUIRED = "provider_async_required"


class ApprovalAuthorityBinding(StrictModel):
    """One approval public-key identity pinned by signed tenant Governance."""

    authority_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    identity_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    key_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,99}$")
    signer_group: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    public_key_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class OperationGovernanceBinding(StrictModel):
    """Exact signed authority for one future compiled effectful contract."""

    operation_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effect: ContractEffect
    minimum_risk_tier: RiskTier
    authorization_mode: AuthorizationMode
    resource_fence_types: list[ResourceFenceType] = Field(min_length=1, max_length=8)
    protected_object_policy: ProtectedObjectPolicy
    async_requirement: AsyncRequirement
    verification: VerificationMode
    approval_authority_ids: list[str] = Field(min_length=1, max_length=8)
    required_signer_groups: list[str] = Field(min_length=1, max_length=8)

    @field_validator(
        "resource_fence_types",
        "approval_authority_ids",
        "required_signer_groups",
    )
    @classmethod
    def sorted_unique_values(cls, value: list[object]) -> list[object]:
        if value != sorted(set(value), key=str):
            raise ValueError("operation Governance lists must be unique and sorted")
        return value

    @model_validator(mode="after")
    def authorization_matches_tier(self) -> OperationGovernanceBinding:
        if self.operation_id != self.contract_id:
            raise ValueError("operation ID must equal its exact compiled contract ID")
        if self.minimum_risk_tier is RiskTier.T4:
            if self.authorization_mode is not AuthorizationMode.PROHIBITED:
                raise ValueError("T4 operation Governance must be prohibited")
            return self
        if self.minimum_risk_tier not in {RiskTier.T2, RiskTier.T3}:
            raise ValueError("Operator Foundation Governance supports only T2 or T3")
        minimum = (
            AuthorizationMode.EXPLICIT_PLAN
            if self.minimum_risk_tier is RiskTier.T2
            else AuthorizationMode.DUAL_CONTROL
        )
        if not authorization_is_at_least(self.authorization_mode, minimum):
            raise ValueError("operation Governance weakens the tier authorization floor")
        if self.authorization_mode is AuthorizationMode.EXPLICIT_PLAN:
            if (
                len(self.approval_authority_ids) < 1
                or len(self.required_signer_groups) != 1
            ):
                raise ValueError("explicit-plan authority requires one signer group")
        elif self.authorization_mode is AuthorizationMode.DUAL_CONTROL:
            if (
                len(self.approval_authority_ids) < 2
                or len(self.required_signer_groups) < 2
            ):
                raise ValueError("dual control requires two distinct authorities and groups")
        elif self.authorization_mode not in {
            AuthorizationMode.BREAK_GLASS_ONLY,
            AuthorizationMode.PROHIBITED,
        }:
            raise ValueError("effectful operation has an unsupported authorization mode")
        if self.verification is VerificationMode.NOT_VERIFIABLE:
            raise ValueError("effectful operation must define representable verification")
        return self


class OperationsGovernance(StrictModel):
    """Signed operational bindings for future schema-v2 contracts."""

    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_schema_versions: list[Literal["2.0"]] = Field(
        min_length=1,
        max_length=1,
    )
    effect_model_schema_version: Literal["1.0"]
    effect_model_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approval_authorities: list[ApprovalAuthorityBinding] = Field(
        min_length=1,
        max_length=32,
    )
    operations: list[OperationGovernanceBinding] = Field(min_length=1, max_length=500)

    @field_validator("contract_manifest_schema_versions")
    @classmethod
    def exact_schema_versions(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("contract schema versions must be unique and sorted")
        return value

    @model_validator(mode="after")
    def exact_authority_and_operation_bindings(self) -> OperationsGovernance:
        authority_ids = [item.authority_id for item in self.approval_authorities]
        identity_ids = [item.identity_id for item in self.approval_authorities]
        key_ids = [item.key_id for item in self.approval_authorities]
        key_fingerprints = [
            item.public_key_sha256 for item in self.approval_authorities
        ]
        operation_ids = [item.operation_id for item in self.operations]
        if authority_ids != sorted(set(authority_ids)):
            raise ValueError("approval authority IDs must be unique and sorted")
        if len(identity_ids) != len(set(identity_ids)):
            raise ValueError("approval authorities cannot alias one identity")
        if len(key_ids) != len(set(key_ids)):
            raise ValueError("approval authority key IDs must be unique")
        if len(key_fingerprints) != len(set(key_fingerprints)):
            raise ValueError("approval authorities cannot alias one public key")
        if operation_ids != sorted(set(operation_ids)):
            raise ValueError("operation Governance bindings must be unique and sorted")
        known = set(authority_ids)
        for operation in self.operations:
            if set(operation.approval_authority_ids) - known:
                raise ValueError("operation references an unknown approval authority")
        return self

    def operation(self, operation_id: str) -> OperationGovernanceBinding:
        for operation in self.operations:
            if operation.operation_id == operation_id:
                return operation
        raise KeyError(f"unknown governed operation: {operation_id}")

    def authority(self, authority_id: str) -> ApprovalAuthorityBinding:
        for authority in self.approval_authorities:
            if authority.authority_id == authority_id:
                return authority
        raise KeyError(f"unknown approval authority: {authority_id}")


class GovernancePolicyBase(StrictModel):
    """Common signed tenant policy fields shared by v1 and v2."""

    policy_version: int = Field(default=1, ge=1, le=1_000_000)
    tenant_id: UUID
    active_profile: GovernanceProfileName
    profiles: dict[GovernanceProfileName, GovernanceProfile]
    resources: GovernanceResources
    authorization_overrides: dict[str, AuthorizationMode] = Field(default_factory=dict)
    identity_governance_baseline: IdentityGovernanceBaseline | None = None
    permission_grant_baseline: PermissionGrantBaseline | None = None
    application_credential_baseline: ApplicationCredentialBaseline | None = None
    profile_debt_baseline: ProfileDebtBaseline | None = None
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_manifest_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    issued_at: datetime
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
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


class GovernancePolicy(GovernancePolicyBase):
    """Backward-compatible Governance v1 policy body."""

    schema_version: Literal["1.0"] = "1.0"


class GovernancePolicyV2(GovernancePolicyBase):
    """Governance v2 adds signed Posture Control Library configuration only."""

    schema_version: Literal["2.0"] = "2.0"
    control_library: ControlLibraryGovernance

    @model_validator(mode="after")
    def control_exceptions_stay_inside_policy_fences(self) -> GovernancePolicyV2:
        for exception in self.control_library.exceptions:
            if exception.issued_at > self.issued_at:
                raise ValueError(
                    "control exception cannot be issued after the policy"
                )
            subject = exception.subject
            if isinstance(subject, ControlWideSubjectSelector):
                setting = self.control_library.controls[exception.control_id]
                if not setting.allow_control_wide_exception:
                    raise ValueError(
                        "control-wide exception is not explicitly allowed"
                    )
                continue
            if isinstance(subject, ProfileSubjectSelector):
                if subject.profile is not self.active_profile:
                    raise ValueError(
                        "control exception cannot select another profile"
                    )
                continue
            allowed_by_kind = {
                "user": self.resources.users,
                "group": self.resources.groups,
                "application": self.resources.applications,
                "service_principal": self.resources.service_principals,
            }
            if subject.object_id not in allowed_by_kind[subject.kind]:
                raise ValueError(
                    "control exception subject is outside tenant resource fences"
                )
        return self


class GovernancePolicyV3(GovernancePolicyBase):
    """Governance v3 adds exact future operational bindings.

    V3 is inactive until a reviewed schema-v2 contract manifest exists. It does
    not migrate or alter Governance v1/v2 policy semantics.
    """

    schema_version: Literal["3.0"] = "3.0"
    control_library: ControlLibraryGovernance | None = None
    operations: OperationsGovernance

    @model_validator(mode="after")
    def operational_bindings_are_closed(self) -> GovernancePolicyV3:
        if (
            self.operations.contract_manifest_digest
            != self.contract_manifest_digest
        ):
            raise ValueError(
                "operational Governance must bind the policy contract manifest"
            )
        if self.operations.effect_model_digest != effect_model_digest():
            raise ValueError("operational Governance effect-model digest is outdated")
        if (
            self.operations.effect_model_schema_version
            != effect_model_document()["schema_version"]
        ):
            raise ValueError("operational Governance effect-model schema is unsupported")
        enabled = {
            contract_id
            for profile in self.profiles.values()
            for contract_id in profile.enabled_contracts
        }
        operation_ids = {item.operation_id for item in self.operations.operations}
        if not operation_ids.issubset(enabled):
            raise ValueError(
                "every governed operation must be enabled by an exact profile"
            )
        if self.control_library is not None:
            for exception in self.control_library.exceptions:
                if exception.issued_at > self.issued_at:
                    raise ValueError(
                        "control exception cannot be issued after the policy"
                    )
                subject = exception.subject
                if isinstance(subject, ControlWideSubjectSelector):
                    setting = self.control_library.controls[exception.control_id]
                    if not setting.allow_control_wide_exception:
                        raise ValueError(
                            "control-wide exception is not explicitly allowed"
                        )
                    continue
                if isinstance(subject, ProfileSubjectSelector):
                    if subject.profile is not self.active_profile:
                        raise ValueError(
                            "control exception cannot select another profile"
                        )
                    continue
                allowed_by_kind = {
                    "user": self.resources.users,
                    "group": self.resources.groups,
                    "application": self.resources.applications,
                    "service_principal": self.resources.service_principals,
                }
                if subject.object_id not in allowed_by_kind[subject.kind]:
                    raise ValueError(
                        "control exception subject is outside tenant resource fences"
                    )
        return self


GovernancePolicyDocument = Annotated[
    GovernancePolicy | GovernancePolicyV2 | GovernancePolicyV3,
    Field(discriminator="schema_version"),
]


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
    policy: GovernancePolicyDocument
    signature: GovernanceSignature


class GovernancePolicyError(SecurityError):
    """A signed tenant policy rejected an operation."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "DENIED_BY_POLICY",
        operator_action: str = "Review and re-sign the tenant Governance policy.",
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.operator_action = operator_action


@dataclass(frozen=True)
class EffectiveControlSetting:
    """Validated configuration for one future deterministic evaluator."""

    control_id: str
    definition_major_version: int
    severity: ControlSeverity
    maximum_evidence_age_seconds: int
    allow_control_wide_exception: bool


@dataclass(frozen=True)
class EffectiveControlLibraryConfiguration:
    """Validated M2 configuration; it does not evaluate evidence or statuses."""

    manifest_digest: str
    library_version: str
    compatibility_schema_version: str
    compatibility_digest: str
    tenant_id: UUID
    profile: GovernanceProfileName
    settings: tuple[EffectiveControlSetting, ...]
    exceptions: tuple[ControlException, ...]

    def setting(self, control_id: str) -> EffectiveControlSetting:
        for setting in self.settings:
            if setting.control_id == control_id:
                return setting
        raise KeyError(f"unknown enabled control: {control_id}")


@dataclass(frozen=True)
class EffectiveOperationGovernance:
    """Validated operational authority for one exact schema-v2 contract."""

    operation_id: str
    contract_digest: str
    contract_manifest_digest: str
    effect_model_digest: str
    policy_digest: str
    tenant_id: UUID
    profile: GovernanceProfileName
    effect: ContractEffect
    risk_tier: RiskTier
    authorization_mode: AuthorizationMode
    resource_fence_types: tuple[ResourceFenceType, ...]
    protected_object_policy: ProtectedObjectPolicy
    async_requirement: AsyncRequirement
    verification: VerificationMode
    approval_authorities: tuple[ApprovalAuthorityBinding, ...]
    required_signer_groups: tuple[str, ...]


@dataclass(frozen=True)
class ControlExceptionMatch:
    """Minimized match result; private rationale and approver stay in policy."""

    exception_id: str
    control_id: str
    definition_major_version: int
    expires_at: datetime


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
    def policy(self) -> GovernancePolicyDocument:
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

    def authorize_profile_debt_read(
        self,
        contract: ContractSpec,
        *,
        tenant_id: str,
    ) -> tuple[ReadAuthorizationDecision, ProfileDebtBaseline]:
        """Authorize read-only profile debt analysis under signed thresholds."""

        decision = self.authorize_read(contract, tenant_id=tenant_id)
        baseline = self.policy.profile_debt_baseline
        if baseline is None:
            raise GovernancePolicyError(
                "profile debt analysis requires a signed customer baseline",
                reason_code="BASELINE_NOT_CONFIGURED",
            )
        if self.policy.permission_grant_baseline is None:
            raise GovernancePolicyError(
                "profile debt analysis requires a signed permission baseline",
                reason_code="BASELINE_NOT_CONFIGURED",
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


_RISK_TIER_STRENGTH: Final[dict[RiskTier, int]] = {
    RiskTier.T0: 0,
    RiskTier.T1: 1,
    RiskTier.T2: 2,
    RiskTier.T3: 3,
    RiskTier.T4: 4,
}
_RESOURCE_FENCE_TOKENS: Final[dict[ResourceFenceType, frozenset[str]]] = {
    ResourceFenceType.TENANT: frozenset({"tenant", "tenant_id"}),
    ResourceFenceType.USER: frozenset({"user", "user_id", "target_user_id"}),
    ResourceFenceType.GROUP: frozenset({"group", "group_id", "target_group_id"}),
    ResourceFenceType.DEVICE: frozenset({"device", "device_id", "managed_device_id"}),
    ResourceFenceType.POLICY: frozenset({"policy", "policy_id"}),
    ResourceFenceType.APPLICATION: frozenset({"application", "application_id"}),
    ResourceFenceType.SERVICE_PRINCIPAL: frozenset(
        {"service_principal", "service_principal_id"}
    ),
}


def resolve_operation_governance(
    policy: GovernancePolicyDocument,
    contract: ContractSpecV2,
    *,
    contract_manifest_digest: str,
) -> EffectiveOperationGovernance:
    """Resolve one exact future operation without activating a Graph surface."""

    if not isinstance(policy, GovernancePolicyV3):
        raise GovernancePolicyError(
            "effectful Operator Foundation requires Governance v3",
            reason_code="OPERATIONS_REQUIRE_GOVERNANCE_V3",
            operator_action=(
                "Create and sign a Governance v3 policy for the exact reviewed "
                "contract and effect-model digests; keep the existing policy unchanged."
            ),
        )
    if policy.contract_manifest_digest != contract_manifest_digest:
        raise GovernancePolicyError(
            "operational Governance contract manifest binding changed",
            reason_code="CONTRACT_MANIFEST_CHANGED",
        )
    operations = policy.operations
    if operations.contract_manifest_digest != contract_manifest_digest:
        raise GovernancePolicyError(
            "operational Governance uses another contract manifest",
            reason_code="CONTRACT_MANIFEST_CHANGED",
        )
    if operations.effect_model_digest != effect_model_digest():
        raise GovernancePolicyError(
            "operational Governance effect model changed",
            reason_code="EFFECT_MODEL_CHANGED",
        )
    if "2.0" not in operations.contract_manifest_schema_versions:
        raise GovernancePolicyError(
            "operational Governance does not support the contract schema",
            reason_code="CONTRACT_SCHEMA_INCOMPATIBLE",
        )
    try:
        binding = operations.operation(contract.id)
    except KeyError as exc:
        raise GovernancePolicyError(
            "operation is not bound by signed Governance",
            reason_code="DENIED_OUT_OF_CONTRACT",
        ) from exc
    if contract.id not in policy.profiles[policy.active_profile].enabled_contracts:
        raise GovernancePolicyError(
            "operation is not enabled in the active Governance profile",
            reason_code="DENIED_OUT_OF_CONTRACT",
        )
    if binding.contract_digest != sha256_digest(contract):
        raise GovernancePolicyError(
            "operation contract digest changed",
            reason_code="CONTRACT_CHANGED",
        )
    if binding.effect is not contract.effect:
        raise GovernancePolicyError(
            "operation effect differs from signed Governance",
            reason_code="EFFECT_CHANGED",
        )
    if _RISK_TIER_STRENGTH[binding.minimum_risk_tier] < _RISK_TIER_STRENGTH[
        contract.risk_tier
    ]:
        raise GovernancePolicyError(
            "operational Governance weakens the contract risk tier",
            reason_code="POLICY_DOWNGRADE_REJECTED",
        )
    effective_mode = policy.authorization_overrides.get(
        contract.id,
        binding.authorization_mode,
    )
    if not authorization_is_at_least(
        binding.authorization_mode,
        contract.authorization_mode,
    ) or not authorization_is_at_least(
        effective_mode,
        binding.authorization_mode,
    ):
        raise GovernancePolicyError(
            "operational Governance weakens the authorization floor",
            reason_code="POLICY_DOWNGRADE_REJECTED",
        )
    if binding.verification is not contract.verification:
        raise GovernancePolicyError(
            "operation verification differs from the compiled contract",
            reason_code="VERIFICATION_CHANGED",
        )
    if (
        binding.async_requirement is AsyncRequirement.PROVIDER_ASYNC_REQUIRED
        and binding.verification
        not in {VerificationMode.ASYNC_STATUS, VerificationMode.RESOURCE_OBSERVED}
    ):
        raise GovernancePolicyError(
            "asynchronous operation lacks an observable verification contract",
            reason_code="VERIFICATION_UNREPRESENTABLE",
        )
    contract_fences = set(contract.resource_fences)
    for fence_type in binding.resource_fence_types:
        if not (_RESOURCE_FENCE_TOKENS[fence_type] & contract_fences):
            raise GovernancePolicyError(
                "operation resource-fence type is absent from the contract",
                reason_code="RESOURCE_FENCE_MISMATCH",
            )
    if (
        set(binding.resource_fence_types)
        & {
            ResourceFenceType.USER,
            ResourceFenceType.GROUP,
            ResourceFenceType.DEVICE,
            ResourceFenceType.POLICY,
        }
        and binding.protected_object_policy
        is not ProtectedObjectPolicy.EXCLUDE_PROTECTED
    ):
        raise GovernancePolicyError(
            "protected resource class lacks a fail-closed exclusion",
            reason_code="PROTECTED_RESOURCE_POLICY_MISSING",
        )
    authorities = tuple(
        operations.authority(authority_id)
        for authority_id in binding.approval_authority_ids
    )
    return EffectiveOperationGovernance(
        operation_id=binding.operation_id,
        contract_digest=binding.contract_digest,
        contract_manifest_digest=contract_manifest_digest,
        effect_model_digest=operations.effect_model_digest,
        policy_digest=sha256_digest(policy),
        tenant_id=policy.tenant_id,
        profile=policy.active_profile,
        effect=binding.effect,
        risk_tier=binding.minimum_risk_tier,
        authorization_mode=effective_mode,
        resource_fence_types=tuple(binding.resource_fence_types),
        protected_object_policy=binding.protected_object_policy,
        async_requirement=binding.async_requirement,
        verification=binding.verification,
        approval_authorities=authorities,
        required_signer_groups=tuple(binding.required_signer_groups),
    )


def parse_governance_policy(document: object) -> GovernancePolicyDocument:
    """Select one exact schema without fallback or automatic migration."""

    if not isinstance(document, dict):
        raise GovernancePolicyError(
            "governance policy root must be an object",
            reason_code="GOVERNANCE_SCHEMA_UNSUPPORTED",
        )
    schema_version = document.get("schema_version")
    if schema_version == "1.0":
        if "control_library" in document:
            raise GovernancePolicyError(
                "Governance v1 cannot enable the Posture Control Library",
                reason_code="CONTROL_LIBRARY_REQUIRES_GOVERNANCE_V2",
                operator_action=(
                    "Create and sign a Governance v2 policy; keep the v1 policy unchanged."
                ),
            )
        return GovernancePolicy.model_validate(document)
    if schema_version == "2.0":
        return GovernancePolicyV2.model_validate(document)
    if schema_version == "3.0":
        return GovernancePolicyV3.model_validate(document)
    raise GovernancePolicyError(
        "governance policy schema version is unsupported",
        reason_code="GOVERNANCE_SCHEMA_UNSUPPORTED",
        operator_action=(
            "Use a supported Governance schema and sign it with the tenant authority."
        ),
    )


def parse_signed_governance_policy(document: object) -> SignedGovernancePolicy:
    """Parse a closed signed bundle while preserving stable schema errors."""

    if not isinstance(document, dict) or set(document) != {"policy", "signature"}:
        raise PrivateStateError("governance policy is malformed")
    policy = parse_governance_policy(document["policy"])
    signature = GovernanceSignature.model_validate(document["signature"])
    return SignedGovernancePolicy(policy=policy, signature=signature)


def _definition_major(version: str) -> int:
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
        version,
    )
    if match is None:
        raise GovernancePolicyError(
            "control definition version is malformed",
            reason_code="CONTROL_DEFINITION_INCOMPATIBLE",
        )
    return int(match.group(1))


def resolve_control_library_configuration(
    policy: GovernancePolicyDocument,
    control_manifest: ControlManifest | None = None,
    compatibility_metadata: ControlCompatibilityMetadata | None = None,
) -> EffectiveControlLibraryConfiguration:
    """Validate signed v2 configuration against exact local M1 semantics."""

    if not isinstance(policy, (GovernancePolicyV2, GovernancePolicyV3)):
        raise GovernancePolicyError(
            "Governance v1 cannot enable the Posture Control Library",
            reason_code="CONTROL_LIBRARY_REQUIRES_GOVERNANCE_V2",
            operator_action=(
                "Create and sign a Governance v2 policy; keep the v1 policy unchanged."
            ),
        )
    manifest = control_manifest or load_global_control_manifest()
    configuration = policy.control_library
    if configuration is None:
        raise GovernancePolicyError(
            "Governance v3 policy does not enable the Posture Control Library",
            reason_code="CONTROL_LIBRARY_NOT_CONFIGURED",
        )
    manifest_digest = sha256_digest(manifest)
    if configuration.control_manifest_digest != manifest_digest:
        raise GovernancePolicyError(
            "Governance control manifest binding does not match",
            reason_code="CONTROL_MANIFEST_CHANGED",
            operator_action=(
                "Review the installed signed control manifest and reissue the tenant "
                "policy only for that exact digest."
            ),
        )
    if configuration.control_manifest_schema_version != manifest.schema_version:
        raise GovernancePolicyError(
            "Governance control manifest schema is unsupported",
            reason_code="CONTROL_MANIFEST_SCHEMA_INCOMPATIBLE",
        )
    if configuration.control_library_version != manifest.library_version:
        raise GovernancePolicyError(
            "Governance control library version does not match",
            reason_code="CONTROL_LIBRARY_VERSION_INCOMPATIBLE",
            operator_action=(
                "Pin the policy to the installed library version; do not select a "
                "newest or future version automatically."
            ),
        )
    definitions = {item.control_id: item for item in manifest.controls}
    validated_controls: list[
        tuple[str, int, ControlGovernanceSetting]
    ] = []
    for control_id in configuration.enabled_control_ids:
        definition = definitions.get(control_id)
        if definition is None:
            raise GovernancePolicyError(
                "Governance references an unknown control",
                reason_code="UNKNOWN_CONTROL",
            )
        if definition.lifecycle.state is ControlLifecycleState.RETIRED:
            raise GovernancePolicyError(
                "Governance cannot enable a retired control",
                reason_code="CONTROL_RETIRED",
            )
        setting = configuration.controls[control_id]
        definition_major = _definition_major(definition.definition_version)
        if setting.definition_major_version != definition_major:
            raise GovernancePolicyError(
                "Governance control definition major is incompatible",
                reason_code="CONTROL_DEFINITION_INCOMPATIBLE",
            )
        validated_controls.append(
            (control_id, definition_major, setting)
        )
    try:
        compatibility = (
            compatibility_metadata
            if compatibility_metadata is not None
            else load_control_compatibility_metadata(manifest)
        )
        compatibility.validate_manifest_binding(manifest)
    except (RuntimeError, ValueError) as exc:
        raise GovernancePolicyError(
            "Control compatibility metadata is unavailable or incompatible",
            reason_code="CONTROL_COMPATIBILITY_UNAVAILABLE",
            operator_action=(
                "Keep Control Library evaluation disabled until reviewed "
                "compatibility metadata for this exact manifest is installed."
            ),
        ) from exc
    installed_compatibility_digest = control_compatibility_digest(
        compatibility
    )
    if (
        configuration.control_compatibility_digest
        != installed_compatibility_digest
    ):
        raise GovernancePolicyError(
            "Governance control compatibility binding does not match",
            reason_code="CONTROL_COMPATIBILITY_CHANGED",
            operator_action=(
                "Review the installed compatibility metadata and reissue the "
                "tenant policy only for its exact canonical digest."
            ),
        )
    effective: list[EffectiveControlSetting] = []
    for control_id, definition_major, setting in validated_controls:
        try:
            global_maximum = compatibility.maximum_age(
                control_id,
                definition_major,
            )
        except KeyError as exc:
            raise GovernancePolicyError(
                "Control freshness metadata is unavailable",
                reason_code="CONTROL_FRESHNESS_UNAVAILABLE",
                operator_action=(
                    "Keep the control disabled until reviewed public freshness "
                    "metadata is installed."
                ),
            ) from exc
        customer_maximum = setting.maximum_evidence_age_seconds
        if customer_maximum is not None and customer_maximum > global_maximum:
            raise GovernancePolicyError(
                "Customer evidence freshness cannot loosen the public maximum",
                reason_code="CONTROL_FRESHNESS_LOOSENED",
            )
        effective.append(
            EffectiveControlSetting(
                control_id=control_id,
                definition_major_version=definition_major,
                severity=setting.severity,
                maximum_evidence_age_seconds=(
                    global_maximum
                    if customer_maximum is None
                    else min(global_maximum, customer_maximum)
                ),
                allow_control_wide_exception=(
                    setting.allow_control_wide_exception
                ),
            )
        )

    for exception in configuration.exceptions:
        allowed_kinds = CONTROL_EXCEPTION_SUBJECT_KINDS.get(
            (exception.control_id, exception.definition_major_version)
        )
        if allowed_kinds is None:
            raise GovernancePolicyError(
                "Control exception selector metadata is unavailable",
                reason_code="CONTROL_EXCEPTION_SELECTOR_UNAVAILABLE",
            )
        if isinstance(exception.subject, ControlWideSubjectSelector):
            continue
        if exception.subject.kind not in allowed_kinds:
            raise GovernancePolicyError(
                "Control exception subject kind is incompatible",
                reason_code="CONTROL_EXCEPTION_SUBJECT_INCOMPATIBLE",
            )

    return EffectiveControlLibraryConfiguration(
        manifest_digest=manifest_digest,
        library_version=manifest.library_version,
        compatibility_schema_version=compatibility.schema_version,
        compatibility_digest=installed_compatibility_digest,
        tenant_id=policy.tenant_id,
        profile=policy.active_profile,
        settings=tuple(sorted(effective, key=lambda item: item.control_id)),
        exceptions=tuple(configuration.exceptions),
    )


def matching_control_exception(
    configuration: EffectiveControlLibraryConfiguration,
    *,
    control_id: str,
    definition_major_version: int,
    subject: ControlExceptionSubject,
    status: Literal["not_aligned"],
    evaluated_at: datetime,
    tenant_id: str,
    profile: GovernanceProfileName,
) -> ControlExceptionMatch | None:
    """Return one exact effective exception without changing assessment status."""

    if status != "not_aligned":
        raise GovernancePolicyError(
            "Control exceptions apply only to not_aligned",
            reason_code="CONTROL_EXCEPTION_STATUS_INCOMPATIBLE",
        )
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise GovernancePolicyError(
            "Exception matching requires a timezone-aware timestamp",
            reason_code="CONTROL_EXCEPTION_TIME_INVALID",
        )
    if str(configuration.tenant_id) != tenant_id:
        raise GovernancePolicyError(
            "Control exception tenant boundary does not match",
            reason_code="TENANT_FENCE_MISMATCH",
        )
    if configuration.profile is not profile:
        raise GovernancePolicyError(
            "Control exception profile boundary does not match",
            reason_code="PROFILE_CONTRACT_MISMATCH",
        )
    subject_key = _subject_key(subject)
    for exception in configuration.exceptions:
        if (
            exception.control_id != control_id
            or exception.definition_major_version != definition_major_version
            or evaluated_at < exception.issued_at
            or evaluated_at >= exception.expires_at
        ):
            continue
        exception_key = _subject_key(exception.subject)
        if exception_key == ("control_wide", "*") or exception_key == subject_key:
            return ControlExceptionMatch(
                exception_id=exception.exception_id,
                control_id=exception.control_id,
                definition_major_version=exception.definition_major_version,
                expires_at=exception.expires_at,
            )
    return None


def validate_policy_against_manifest(
    policy: GovernancePolicyDocument,
    manifest: ContractManifest,
    playbook_manifest: PlaybookManifest | None = None,
    control_manifest: ControlManifest | None = None,
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
    profile_debt_contract = "entra.profile_debt.posture.snapshot"
    permission_drift_contract = "entra.permission_grants.drift.snapshot"
    debt_profiles = [
        name
        for name, profile in policy.profiles.items()
        if profile_debt_contract in profile.enabled_contracts
    ]
    if debt_profiles:
        if debt_profiles != [GovernanceProfileName.PRIVILEGED_READ]:
            raise GovernancePolicyError(
                "profile debt is valid only in privileged-read",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )
        debt_profile = policy.profiles[GovernanceProfileName.PRIVILEGED_READ]
        if permission_drift_contract not in debt_profile.enabled_contracts:
            raise GovernancePolicyError(
                "profile debt requires permission drift in the same profile",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )
        if (
            policy.permission_grant_baseline is None
            or policy.profile_debt_baseline is None
        ):
            raise GovernancePolicyError(
                "profile debt requires both signed customer baselines",
                reason_code="BASELINE_NOT_CONFIGURED",
            )
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

    if isinstance(policy, GovernancePolicyV2) or (
        isinstance(policy, GovernancePolicyV3)
        and policy.control_library is not None
    ):
        resolve_control_library_configuration(policy, control_manifest)


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
    policy: GovernancePolicyDocument,
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
        bundle = parse_signed_governance_policy(document)
    except GovernancePolicyError:
        raise
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
