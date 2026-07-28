"""Fail-closed boundary and privacy models for Identity Slice live-lab runs.

This module never registers an MCP tool and never signs or executes a plan.
It validates an externally stored, dedicated-lab inventory before a separate
reviewed runner may authenticate or call Microsoft Graph.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, TypedDict
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .contract_compiler import load_identity_candidate
from .contract_manifest import effect_model_digest, sha256_digest
from .governance import (
    GovernancePolicy,
    GovernancePolicyV3,
    GovernanceProfileName,
    load_verified_governance_policy,
    resolve_operation_governance,
)
from .security import PrivateStateError, SecurityError, read_private_file

LAB_ENABLE_ENV = "M365_IDENTITY_LIVE_LAB"
LAB_PROFILE_ENV = "M365_LAB_PROFILE"
LAB_TENANT_ENV = "M365_LAB_TENANT_ID"
LAB_INVENTORY_ENV = "M365_IDENTITY_LIVE_LAB_INVENTORY"
LAB_OPERATOR_PROFILE_ENV = "M365_LAB_OPERATOR_PROFILE"
LAB_WRITE_ACK_ENV = "M365_IDENTITY_LIVE_LAB_WRITE_ACK"
LAB_WRITE_ACK = "DEDICATED_NONPRODUCTION_IDENTITY_LAB"
LAB_PROFILE = "live-lab"
LAB_REDIRECT_URI = "http://localhost"
LAB_AUTHORITY_PREFIX = "https://login.microsoftonline.com/"
MAX_INVENTORY_BYTES = 64 * 1024
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"

REQUIRED_EXTERNAL_ENV = (
    "M365_ALLOWED_USER_OBJECT_IDS",
    "M365_CLIENT_ID",
    "M365_GOVERNANCE_POLICY_PATH",
    "M365_GOVERNANCE_PUBLIC_KEY_PATH",
    "M365_KEYRING_SERVICE",
    "M365_TENANT_ID",
    "M365_TOKEN_CACHE_MODE",
)
FORBIDDEN_AUTH_ENV = frozenset(
    {
        "M365_CLIENT_SECRET",
        "M365_PASSWORD",
        "M365_USERNAME",
    }
)

REQUIRED_DELEGATED_SCOPES = frozenset(
    {
        "GroupMember.ReadWrite.All",
        "LicenseAssignment.Read.All",
        "LicenseAssignment.ReadWrite.All",
        "RoleManagement.Read.Directory",
        "User.EnableDisableAccount.All",
        "User.Read.All",
        "User.RevokeSessions.All",
    }
)
IDENTITY_OPERATIONS = (
    "entra.group.user_membership.add",
    "entra.group.user_membership.remove",
    "entra.user.account_state.set",
    "entra.user.direct_license.set",
    "entra.user.sessions.revoke",
)


class LiveLabOperatorProfileName(StrEnum):
    SESSION = "session-operator"
    ACCOUNT = "account-operator"
    GROUP = "group-operator"
    LICENSE = "license-operator"
    NEGATIVE = "negative-operator"


class LiveLabLevel(StrEnum):
    CORE = "core"
    EXTENDED = "extended"


class OperatorProfileRequirement(TypedDict):
    roles: tuple[str, ...]
    operations: tuple[str, ...]


OPERATOR_PROFILE_REQUIREMENTS: dict[
    LiveLabOperatorProfileName,
    OperatorProfileRequirement,
] = {
    LiveLabOperatorProfileName.SESSION: {
        "roles": ("Global Reader", "Helpdesk Administrator"),
        "operations": ("entra.user.sessions.revoke",),
    },
    LiveLabOperatorProfileName.ACCOUNT: {
        "roles": ("Global Reader", "User Administrator"),
        "operations": ("entra.user.account_state.set",),
    },
    LiveLabOperatorProfileName.GROUP: {
        "roles": ("Global Reader", "Groups Administrator"),
        "operations": (
            "entra.group.user_membership.add",
            "entra.group.user_membership.remove",
        ),
    },
    LiveLabOperatorProfileName.LICENSE: {
        "roles": ("Global Reader", "License Administrator"),
        "operations": ("entra.user.direct_license.set",),
    },
    LiveLabOperatorProfileName.NEGATIVE: {
        "roles": ("Global Reader",),
        "operations": (),
    },
}

CORE_REQUIRED_SCENARIOS = (
    "account.disable",
    "account.enable",
    "account.noop",
    "account.toctou_rejected",
    "allowlist.cross_tenant_rejected",
    "allowlist.outside_resource_rejected",
    "license.assign_direct",
    "license.capacity_rejected",
    "license.noop",
    "license.remove_direct",
    "license.service_plan_rejected",
    "license.usage_location_rejected",
    "membership.add",
    "membership.add_noop",
    "membership.remove",
    "membership.remove_noop",
    "operator.effect_role_missing",
    "operator.evidence_role_missing",
    "operator.profile_isolation",
    "protected_object.rejected",
    "session.accepted_not_verified",
    "session.uncertain_no_retry",
)
EXTENDED_REQUIRED_SCENARIOS = (
    "extended.group.dynamic_rejected",
    "extended.group.role_assignable_rejected",
    "extended.license.inherited_not_removed",
    "extended.membership.concurrent_change",
    "extended.membership.replication_observed",
    "extended.user.pim_active_rejected",
    "extended.user.pim_eligible_rejected",
    "extended.user.synchronized_rejected",
)

_UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_EMAIL_PATTERN = re.compile(r"\b[^@\s]+@[^@\s]+\.[^@\s]+\b")
_IPV4_PATTERN = re.compile(
    r"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])"
)
_JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "client_id",
        "device_id",
        "display_name",
        "ip_address",
        "name",
        "object_id",
        "request_id",
        "subscription_id",
        "tenant_id",
        "token",
        "upn",
        "user_principal_name",
    }
)


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LiveLabMarker(FrozenModel):
    group_id: UUID
    description_digest: str = Field(pattern=SHA256_PATTERN)


class CoreLiveLabUsers(FrozenModel):
    normal_enabled_user_id: UUID
    normal_disabled_user_id: UUID
    direct_license_user_id: UUID
    guest_user_id: UUID
    administrator_user_id: UUID
    break_glass_user_id: UUID
    no_usage_location_user_id: UUID
    outside_allowlist_user_id: UUID


class CoreLiveLabGroups(FrozenModel):
    allowed_static_group_id: UUID
    protected_static_group_id: UUID
    outside_allowlist_group_id: UUID


class CoreLiveLabRelationships(FrozenModel):
    already_member_user_id: UUID
    already_member_group_id: UUID
    non_member_user_id: UUID
    non_member_group_id: UUID


class ExtendedLiveLabUsers(FrozenModel):
    synchronized_user_id: UUID
    pim_active_user_id: UUID
    pim_eligible_user_id: UUID
    inherited_license_user_id: UUID


class ExtendedLiveLabGroups(FrozenModel):
    dynamic_group_id: UUID
    role_assignable_group_id: UUID
    inherited_license_group_id: UUID


class ExtendedLiveLabRelationships(FrozenModel):
    inherited_license_user_id: UUID
    inherited_license_group_id: UUID


class ExtendedLabUnavailable(FrozenModel):
    state: Literal["not_provisioned"]


class ExtendedLabProvisioned(FrozenModel):
    state: Literal["provisioned"]
    users: ExtendedLiveLabUsers
    groups: ExtendedLiveLabGroups
    relationships: ExtendedLiveLabRelationships


ExtendedLiveLabInventory = Annotated[
    ExtendedLabUnavailable | ExtendedLabProvisioned,
    Field(discriminator="state"),
]


class LiveLabLicenses(FrozenModel):
    allowed_sku_id: UUID
    disallowed_sku_id: UUID
    allowed_service_plan_ids: tuple[UUID, ...] = Field(min_length=1)
    disallowed_service_plan_id: UUID


class LiveLabAuthentication(FrozenModel):
    application_type: Literal["single-tenant-public-client"]
    primary_flow: Literal["system-browser-pkce"]
    fallback_flow: Literal["device-code-explicit"]
    redirect_uri: Literal["http://localhost"]
    token_cache: Literal["os-keychain-owner-only"]
    mfa_compatible: Literal[True]
    client_secret_prohibited: Literal[True]
    ropc_prohibited: Literal[True]


class LiveLabOperatorProfile(FrozenModel):
    profile_id: LiveLabOperatorProfileName
    subject_id: UUID
    governance_policy_digest: str = Field(pattern=SHA256_PATTERN)
    approval_public_key_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
    )
    keyring_service: str = Field(
        pattern=r"^m365-secure-mcp-live-lab-[a-z-]{3,32}$",
    )
    required_roles: tuple[str, ...] = Field(min_length=1, max_length=4)
    allowed_operation_ids: tuple[str, ...] = Field(max_length=2)

    @model_validator(mode="after")
    def exact_profile_authority(self) -> LiveLabOperatorProfile:
        expected = OPERATOR_PROFILE_REQUIREMENTS[self.profile_id]
        if self.required_roles != expected["roles"]:
            raise ValueError("live-lab operator role closure differs from profile")
        if self.allowed_operation_ids != expected["operations"]:
            raise ValueError("live-lab operation closure differs from profile")
        if self.profile_id is LiveLabOperatorProfileName.NEGATIVE:
            if self.approval_public_key_sha256 is not None:
                raise ValueError("negative operator cannot have approval authority")
        elif self.approval_public_key_sha256 is None:
            raise ValueError("effect operator requires approval authority")
        return self


class LiveLabOperators(FrozenModel):
    session: LiveLabOperatorProfile
    account: LiveLabOperatorProfile
    group: LiveLabOperatorProfile
    license: LiveLabOperatorProfile
    negative: LiveLabOperatorProfile

    @model_validator(mode="after")
    def isolated_operator_authorities(self) -> LiveLabOperators:
        profiles = (
            self.session,
            self.account,
            self.group,
            self.license,
            self.negative,
        )
        expected = (
            LiveLabOperatorProfileName.SESSION,
            LiveLabOperatorProfileName.ACCOUNT,
            LiveLabOperatorProfileName.GROUP,
            LiveLabOperatorProfileName.LICENSE,
            LiveLabOperatorProfileName.NEGATIVE,
        )
        if tuple(item.profile_id for item in profiles) != expected:
            raise ValueError("live-lab operator fields use another profile")
        if len({item.subject_id for item in profiles}) != len(profiles):
            raise ValueError("live-lab operator subjects must be distinct")
        if len({item.governance_policy_digest for item in profiles}) != len(profiles):
            raise ValueError("live-lab Governance policies must be profile-specific")
        if len({item.keyring_service for item in profiles}) != len(profiles):
            raise ValueError("live-lab token-cache namespaces must be distinct")
        approval_fingerprints = {
            item.approval_public_key_sha256
            for item in profiles
            if item.approval_public_key_sha256 is not None
        }
        if len(approval_fingerprints) != 4:
            raise ValueError("effect profiles require distinct approval authorities")
        return self

    def get(
        self,
        profile_id: LiveLabOperatorProfileName,
    ) -> LiveLabOperatorProfile:
        for profile in (
            self.session,
            self.account,
            self.group,
            self.license,
            self.negative,
        ):
            if profile.profile_id is profile_id:
                return profile
        raise KeyError("unknown live-lab operator profile")


class IdentityLiveLabInventory(FrozenModel):
    """Private external inventory. It contains identifiers and is never committed."""

    schema_version: Literal["2.0"]
    environment: Literal["dedicated-nonproduction"]
    profile: Literal["live-lab"]
    tenant_id: UUID
    client_id: UUID
    authentication: LiveLabAuthentication
    operators: LiveLabOperators
    candidate_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    effect_model_digest: str = Field(pattern=SHA256_PATTERN)
    marker: LiveLabMarker
    core_users: CoreLiveLabUsers
    core_groups: CoreLiveLabGroups
    core_relationships: CoreLiveLabRelationships
    extended: ExtendedLiveLabInventory
    licenses: LiveLabLicenses
    allowlisted_user_ids: tuple[UUID, ...] = Field(min_length=1)
    allowlisted_group_ids: tuple[UUID, ...] = Field(min_length=1)
    protected_user_ids: tuple[UUID, ...] = Field(min_length=1)
    protected_group_ids: tuple[UUID, ...] = Field(min_length=1)
    allowed_sku_ids: tuple[UUID, ...] = Field(min_length=1)
    allowed_service_plan_ids: dict[UUID, tuple[UUID, ...]]

    @model_validator(mode="after")
    def validate_closed_lab_topology(self) -> IdentityLiveLabInventory:
        user_ids = tuple(self.core_users.model_dump().values())
        group_ids = tuple(self.core_groups.model_dump().values())
        if isinstance(self.extended, ExtendedLabProvisioned):
            user_ids += tuple(self.extended.users.model_dump().values())
            group_ids += tuple(self.extended.groups.model_dump().values())
        if len(set(user_ids)) != len(user_ids):
            raise ValueError("live-lab user fixtures must use distinct object IDs")
        if len(set(group_ids)) != len(group_ids):
            raise ValueError("live-lab group fixtures must use distinct object IDs")
        operator_ids = {
            profile.subject_id
            for profile in (
                self.operators.session,
                self.operators.account,
                self.operators.group,
                self.operators.license,
                self.operators.negative,
            )
        }
        if operator_ids & set(user_ids):
            raise ValueError("live-lab operators must be separate from target fixtures")
        if self.marker.group_id in set(group_ids):
            raise ValueError("lab marker must be separate from operation target groups")

        expected_users = set(user_ids) - {
            self.core_users.outside_allowlist_user_id
        }
        if set(self.allowlisted_user_ids) != expected_users:
            raise ValueError("live-lab user allowlist does not match fixture topology")
        expected_groups = set(group_ids) - {
            self.core_groups.outside_allowlist_group_id
        }
        if set(self.allowlisted_group_ids) != expected_groups:
            raise ValueError("live-lab group allowlist does not match fixture topology")
        expected_protected_users = {
            self.core_users.administrator_user_id,
            self.core_users.break_glass_user_id,
        }
        if isinstance(self.extended, ExtendedLabProvisioned):
            expected_protected_users.update(
                {
                    self.extended.users.pim_active_user_id,
                    self.extended.users.pim_eligible_user_id,
                }
            )
        if set(self.protected_user_ids) != expected_protected_users:
            raise ValueError("live-lab protected users must be exact")
        if set(self.protected_group_ids) != {
            self.core_groups.protected_static_group_id,
        }:
            raise ValueError("live-lab protected groups must be exact")
        if set(self.allowed_sku_ids) != {self.licenses.allowed_sku_id}:
            raise ValueError("live-lab SKU allowlist must contain only the allowed SKU")
        if self.licenses.disallowed_sku_id in set(self.allowed_sku_ids):
            raise ValueError("disallowed live-lab SKU cannot be allowlisted")
        if (
            self.licenses.disallowed_service_plan_id
            in set(self.licenses.allowed_service_plan_ids)
        ):
            raise ValueError("disallowed service plan cannot be allowlisted")
        if self.allowed_service_plan_ids != {
            self.licenses.allowed_sku_id: self.licenses.allowed_service_plan_ids
        }:
            raise ValueError("live-lab service-plan allowlist must be exact")

        relationship_users = {
            self.core_relationships.already_member_user_id,
            self.core_relationships.non_member_user_id,
        }
        relationship_groups = {
            self.core_relationships.already_member_group_id,
            self.core_relationships.non_member_group_id,
        }
        if not relationship_users <= expected_users:
            raise ValueError("membership fixtures must use allowlisted users")
        if not relationship_groups <= expected_groups:
            raise ValueError("relationship fixtures must use allowlisted groups")
        return self


class LiveLabGateResult(FrozenModel):
    status: Literal["ready"]
    profile: Literal["live-lab"]
    environment: Literal["dedicated-nonproduction"]
    operator_profile: LiveLabOperatorProfileName
    auth_flow: Literal["system-browser-pkce", "device-code-explicit"]
    core_gate: Literal["required"]
    extended_gate: Literal["not_provisioned", "provisioned"]
    candidate_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    effect_model_digest: str = Field(pattern=SHA256_PATTERN)
    resource_counts: dict[str, int]
    external_authority_present: bool


class PublicLiveLabCase(FrozenModel):
    lab_level: LiveLabLevel
    scenario: str = Field(pattern=r"^[a-z0-9_.-]{3,96}$")
    resource_type: Literal["user", "group", "license", "relationship", "session"]
    operation_id: Literal[
        "entra.user.sessions.revoke",
        "entra.user.account_state.set",
        "entra.group.user_membership.add",
        "entra.group.user_membership.remove",
        "entra.user.direct_license.set",
    ]
    expected_status: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    observed_status: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    approximate_duration: Literal[
        "under_1s",
        "1_to_5s",
        "5_to_30s",
        "30_to_120s",
        "over_120s",
    ]
    classification: Literal[
        "accepted",
        "verified",
        "uncertain",
        "blocked",
        "failed_confirmed",
    ]
    error_code: str | None = Field(
        default=None,
        pattern=r"^[A-Z][A-Z0-9_.-]{2,63}$",
    )
    contract_digest: str = Field(pattern=SHA256_PATTERN)
    execution_state: Literal["passed", "failed", "not_executed"]

    @model_validator(mode="after")
    def known_scenario(self) -> PublicLiveLabCase:
        expected = (
            CORE_REQUIRED_SCENARIOS
            if self.lab_level is LiveLabLevel.CORE
            else EXTENDED_REQUIRED_SCENARIOS
        )
        if self.scenario not in expected:
            raise ValueError("live-lab evidence contains an unknown scenario")
        if self.execution_state == "not_executed" and self.observed_status != "NOT_EXECUTED":
            raise ValueError("not-executed evidence requires NOT_EXECUTED status")
        return self


class PublicLiveLabEvidence(FrozenModel):
    schema_version: Literal["2.0"]
    evidence_kind: Literal["sanitized-identity-live-lab"]
    contains_customer_data: Literal[False]
    candidate_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    cases: tuple[PublicLiveLabCase, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def deterministic_cases(self) -> PublicLiveLabEvidence:
        scenarios = [item.scenario for item in self.cases]
        if scenarios != sorted(set(scenarios)):
            raise ValueError("live-lab evidence scenarios must be unique and sorted")
        if set(scenarios) != set(CORE_REQUIRED_SCENARIOS + EXTENDED_REQUIRED_SCENARIOS):
            raise ValueError("live-lab evidence coverage is incomplete")
        return self


class LiveLabEligibility(FrozenModel):
    preview_signing_eligible: bool
    stable_promotion_eligible: bool
    core_failed: tuple[str, ...]
    core_not_executed: tuple[str, ...]
    extended_failed: tuple[str, ...]
    extended_not_executed: tuple[str, ...]


class LiveLabTokenContext(FrozenModel):
    """Private token facts supplied by the reviewed lab runner."""

    tenant_id: UUID
    client_id: UUID
    subject_id: UUID
    operator_profile: LiveLabOperatorProfileName
    authority: str
    auth_flow: Literal["system-browser-pkce", "device-code-explicit"]
    keyring_service: str
    delegated_scopes: tuple[str, ...]
    directory_roles: tuple[str, ...]
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    approval_plan_digest: str = Field(pattern=SHA256_PATTERN)
    approval_tenant_id: UUID
    approval_subject_id: UUID
    approval_profile: Literal["selected-write"]
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    operation_id: str

    @model_validator(mode="after")
    def deterministic_sets(self) -> LiveLabTokenContext:
        if self.delegated_scopes != tuple(sorted(set(self.delegated_scopes))):
            raise ValueError("live-lab delegated scopes must be unique and sorted")
        if self.directory_roles != tuple(sorted(set(self.directory_roles))):
            raise ValueError("live-lab roles must be unique and sorted")
        return self


def _secure_private_json(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SecurityError("live-lab inventory is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SecurityError("live-lab inventory must be a regular non-symlink file")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise SecurityError("live-lab inventory must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SecurityError("live-lab inventory must use mode 0600")
    if metadata.st_size > MAX_INVENTORY_BYTES:
        raise SecurityError("live-lab inventory exceeds its size limit")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SecurityError("live-lab inventory could not be read") from exc


def load_live_lab_inventory(path: Path) -> IdentityLiveLabInventory:
    """Load one owner-only inventory without exposing its path or identifiers."""
    try:
        payload = json.loads(_secure_private_json(path))
        return IdentityLiveLabInventory.model_validate(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise SecurityError("live-lab inventory is invalid") from exc


def _current_candidate_digest(root: Path) -> str:
    return sha256_digest(load_identity_candidate(root))


def _validate_external_authority(
    inventory: IdentityLiveLabInventory,
    *,
    root: Path,
    environ: Mapping[str, str],
) -> None:
    """Verify one isolated operator profile without disclosing private values."""

    try:
        selected_profile = LiveLabOperatorProfileName(
            environ[LAB_OPERATOR_PROFILE_ENV]
        )
    except (KeyError, ValueError) as exc:
        raise SecurityError("identity live lab operator profile is invalid") from exc
    operator = inventory.operators.get(selected_profile)
    try:
        allowed_operator_ids = {
            UUID(item.strip())
            for item in environ["M365_ALLOWED_USER_OBJECT_IDS"].split(",")
            if item.strip()
        }
    except (KeyError, ValueError) as exc:
        raise SecurityError("identity live lab operator allowlist is invalid") from exc
    if allowed_operator_ids != {operator.subject_id}:
        raise SecurityError("identity live lab operator allowlist is not profile-exact")
    try:
        verified = load_verified_governance_policy(
            Path(environ["M365_GOVERNANCE_POLICY_PATH"]),
            Path(environ["M365_GOVERNANCE_PUBLIC_KEY_PATH"]),
        )
    except (KeyError, PrivateStateError, ValueError) as exc:
        raise SecurityError("identity live lab external authority is invalid") from exc
    policy = verified.bundle.policy
    candidate = load_identity_candidate(root)
    candidate_digest = sha256_digest(candidate)
    if (
        verified.policy_digest != operator.governance_policy_digest
        or policy.tenant_id != inventory.tenant_id
        or policy.active_profile is not GovernanceProfileName.SELECTED_WRITE
    ):
        raise SecurityError("identity live lab Governance binding does not match")
    if selected_profile is LiveLabOperatorProfileName.NEGATIVE:
        if not isinstance(policy, GovernancePolicy):
            raise SecurityError("negative live-lab operator requires signed deny policy")
        if policy.profiles[
            GovernanceProfileName.SELECTED_WRITE
        ].enabled_contracts:
            raise SecurityError("negative live-lab operator cannot enable writes")
        if environ.get("M365_APPROVAL_PUBLIC_KEY_PATH"):
            raise SecurityError("negative live-lab operator cannot load approval authority")
        return
    if not isinstance(policy, GovernancePolicyV3):
        raise SecurityError("effect live-lab operator requires signed Governance v3")
    if (
        policy.contract_manifest_digest != candidate_digest
        or policy.operations.contract_manifest_digest != candidate_digest
        or policy.operations.effect_model_digest != effect_model_digest()
    ):
        raise SecurityError("identity live lab Governance binding does not match")
    enabled_contracts = policy.profiles[
        GovernanceProfileName.SELECTED_WRITE
    ].enabled_contracts
    if tuple(enabled_contracts) != operator.allowed_operation_ids:
        raise SecurityError("identity live lab operation profile is not exact")
    resources = policy.resources
    policy_service_plans = {
        sku: tuple(plans)
        for sku, plans in resources.allowed_service_plan_ids.items()
    }
    if (
        set(resources.tenants) != {inventory.tenant_id}
        or set(resources.users) != set(inventory.allowlisted_user_ids)
        or set(resources.groups) != set(inventory.allowlisted_group_ids)
        or set(resources.protected_user_ids) != set(inventory.protected_user_ids)
        or set(resources.break_glass_user_ids)
        != {inventory.core_users.break_glass_user_id}
        or resources.emergency_access_user_ids
        or set(resources.protected_group_ids) != set(inventory.protected_group_ids)
        or set(resources.allowed_sku_ids) != set(inventory.allowed_sku_ids)
        or policy_service_plans != inventory.allowed_service_plan_ids
    ):
        raise SecurityError("identity live lab Governance resource fences differ")
    try:
        for contract in candidate.contracts:
            if contract.id not in operator.allowed_operation_ids:
                continue
            resolve_operation_governance(
                policy,
                contract,
                contract_manifest_digest=candidate_digest,
            )
    except (KeyError, SecurityError, ValueError) as exc:
        raise SecurityError(
            "identity live lab operation Governance is incomplete"
        ) from exc

    try:
        encoded = read_private_file(
            Path(environ["M365_APPROVAL_PUBLIC_KEY_PATH"]),
            max_bytes=4_096,
            label="live-lab approval public key",
        ).strip()
        raw = base64.b64decode(encoded, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (KeyError, PrivateStateError, TypeError, ValueError) as exc:
        raise SecurityError("identity live lab approval authority is invalid") from exc
    fingerprint = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if (
        fingerprint != operator.approval_public_key_sha256
        or fingerprint not in {
            item.public_key_sha256
            for item in policy.operations.approval_authorities
        }
    ):
        raise SecurityError("identity live lab approval authority is not governed")


def validate_live_lab_token_context(
    inventory: IdentityLiveLabInventory,
    context: LiveLabTokenContext,
) -> None:
    """Bind the selected token, plan and approval to one isolated lab profile."""

    operator = inventory.operators.get(context.operator_profile)
    expected_authority = f"{LAB_AUTHORITY_PREFIX}{inventory.tenant_id}"
    if context.operator_profile is LiveLabOperatorProfileName.NEGATIVE:
        raise SecurityError("negative live-lab operator has no effect authority")
    if (
        context.tenant_id != inventory.tenant_id
        or context.client_id != inventory.client_id
        or context.subject_id != operator.subject_id
        or context.authority != expected_authority
        or context.keyring_service != operator.keyring_service
        or context.policy_digest != operator.governance_policy_digest
        or context.operation_id not in operator.allowed_operation_ids
    ):
        raise SecurityError("live-lab token authority does not match operator profile")
    if set(context.delegated_scopes) != set(REQUIRED_DELEGATED_SCOPES):
        raise SecurityError("live-lab delegated scope evidence is incomplete")
    if set(context.directory_roles) != set(operator.required_roles):
        raise SecurityError("live-lab operator role evidence is incomplete")
    if (
        context.plan_digest != context.approval_plan_digest
        or context.approval_tenant_id != context.tenant_id
        or context.approval_subject_id != context.subject_id
        or context.approval_profile != "selected-write"
    ):
        raise SecurityError("live-lab plan and approval binding does not match")


def validate_live_lab_gate(
    inventory: IdentityLiveLabInventory,
    *,
    root: Path,
    environ: Mapping[str, str],
) -> LiveLabGateResult:
    """Validate the explicit, process-fixed boundary before any live write."""
    if environ.get(LAB_ENABLE_ENV) != "1":
        raise SecurityError("identity live lab is not explicitly enabled")
    if environ.get(LAB_PROFILE_ENV) != LAB_PROFILE:
        raise SecurityError("identity live lab requires the live-lab profile")
    if environ.get(LAB_WRITE_ACK_ENV) != LAB_WRITE_ACK:
        raise SecurityError("identity live lab write acknowledgement is missing")
    if any(environ.get(name) for name in FORBIDDEN_AUTH_ENV):
        raise SecurityError("identity live lab forbids confidential or ROPC credentials")
    try:
        environment_tenant = UUID(environ.get(LAB_TENANT_ENV, ""))
        runtime_tenant = UUID(environ.get("M365_TENANT_ID", ""))
        environment_client = UUID(environ.get("M365_CLIENT_ID", ""))
    except ValueError as exc:
        raise SecurityError("identity live lab binding is incomplete") from exc
    if (
        environment_tenant != inventory.tenant_id
        or runtime_tenant != inventory.tenant_id
        or environment_client != inventory.client_id
    ):
        raise SecurityError("identity live lab process binding does not match inventory")
    missing = [name for name in REQUIRED_EXTERNAL_ENV if not environ.get(name)]
    if missing:
        raise SecurityError("identity live lab external authority is incomplete")
    try:
        selected_profile = LiveLabOperatorProfileName(
            environ.get(LAB_OPERATOR_PROFILE_ENV, "")
        )
    except ValueError as exc:
        raise SecurityError("identity live lab operator profile is invalid") from exc
    operator = inventory.operators.get(selected_profile)
    if environ.get("M365_KEYRING_SERVICE") != operator.keyring_service:
        raise SecurityError("identity live lab token-cache boundary does not match")
    if environ.get("M365_TOKEN_CACHE_MODE") != "keyring":
        raise SecurityError("identity live lab requires owner-only external token cache")
    auth_flow = environ.get("M365_AUTH_FLOW", "interactive")
    if auth_flow == "interactive":
        projected_auth_flow: Literal[
            "system-browser-pkce", "device-code-explicit"
        ] = "system-browser-pkce"
    elif (
        auth_flow == "device_code"
        and environ.get("M365_ALLOW_DEVICE_CODE", "").lower() == "true"
    ):
        projected_auth_flow = "device-code-explicit"
    else:
        raise SecurityError("identity live lab authentication flow is prohibited")
    expected_candidate = _current_candidate_digest(root)
    if inventory.candidate_manifest_digest != expected_candidate:
        raise SecurityError("identity live lab candidate digest is stale")
    expected_effect = effect_model_digest()
    if inventory.effect_model_digest != expected_effect:
        raise SecurityError("identity live lab Effect Model digest is stale")
    _validate_external_authority(inventory, root=root, environ=environ)
    return LiveLabGateResult(
        status="ready",
        profile="live-lab",
        environment="dedicated-nonproduction",
        operator_profile=selected_profile,
        auth_flow=projected_auth_flow,
        core_gate="required",
        extended_gate=inventory.extended.state,
        candidate_manifest_digest=expected_candidate,
        effect_model_digest=expected_effect,
        resource_counts={
            "core_groups": len(CoreLiveLabGroups.model_fields),
            "core_users": len(CoreLiveLabUsers.model_fields),
            "extended_groups": (
                len(ExtendedLiveLabGroups.model_fields)
                if isinstance(inventory.extended, ExtendedLabProvisioned)
                else 0
            ),
            "extended_users": (
                len(ExtendedLiveLabUsers.model_fields)
                if isinstance(inventory.extended, ExtendedLabProvisioned)
                else 0
            ),
            "licenses": 2,
            "marker_groups": 1,
            "service_plans": len(inventory.licenses.allowed_service_plan_ids) + 1,
            "operator_profiles": 5,
        },
        external_authority_present=True,
    )


def load_gate_from_environment(
    *,
    root: Path,
    environ: Mapping[str, str] | None = None,
) -> LiveLabGateResult:
    environment = os.environ if environ is None else environ
    raw_path = environment.get(LAB_INVENTORY_ENV)
    if not raw_path:
        raise SecurityError("identity live lab inventory path is not configured")
    inventory = load_live_lab_inventory(Path(raw_path))
    return validate_live_lab_gate(inventory, root=root, environ=environment)


def public_requirements() -> dict[str, object]:
    """Return tenant-neutral provisioning requirements only."""
    return {
        "schema_version": "2.0",
        "environment": "dedicated-nonproduction",
        "profile": LAB_PROFILE,
        "operations": list(IDENTITY_OPERATIONS),
        "delegated_scopes": sorted(REQUIRED_DELEGATED_SCOPES),
        "operator_profiles": {
            profile.value: {
                "roles": list(requirements["roles"]),
                "operations": list(requirements["operations"]),
            }
            for profile, requirements in OPERATOR_PROFILE_REQUIREMENTS.items()
        },
        "authentication": {
            "application_type": "single-tenant-public-client",
            "primary_flow": "system-browser-pkce",
            "fallback_flow": "device-code-explicit",
            "redirect_uri": LAB_REDIRECT_URI,
            "token_cache": "os-keychain-owner-only",
            "tenant_authority": "exact-no-common",
            "client_secret": "prohibited",
            "ropc": "prohibited",
        },
        "resource_counts": {
            "core_users": 8,
            "core_groups": 3,
            "operator_profiles": 5,
            "independent_marker_groups": 1,
            "subscribed_skus": 2,
            "service_plan_classes": 2,
        },
        "core_required_scenarios": list(CORE_REQUIRED_SCENARIOS),
        "extended_required_scenarios": list(EXTENDED_REQUIRED_SCENARIOS),
        "external_material": [
            "dedicated public-client App Registration",
            "four signed Governance v3 effect policies",
            "one signed deny policy for the negative operator",
            "five external Governance verification keys",
            "four external approval verification keys",
            "five isolated OS-keychain token-cache namespaces",
        ],
        "automatic_provisioning": False,
        "contains_identifiers": False,
        "contains_credentials": False,
    }


def evaluate_live_lab_evidence(
    evidence: PublicLiveLabEvidence,
) -> LiveLabEligibility:
    """Compute preview/stable gates without treating missing execution as success."""

    core_failed = tuple(
        item.scenario
        for item in evidence.cases
        if item.lab_level is LiveLabLevel.CORE
        and item.execution_state == "failed"
    )
    core_not_executed = tuple(
        item.scenario
        for item in evidence.cases
        if item.lab_level is LiveLabLevel.CORE
        and item.execution_state == "not_executed"
    )
    extended_failed = tuple(
        item.scenario
        for item in evidence.cases
        if item.lab_level is LiveLabLevel.EXTENDED
        and item.execution_state == "failed"
    )
    extended_not_executed = tuple(
        item.scenario
        for item in evidence.cases
        if item.lab_level is LiveLabLevel.EXTENDED
        and item.execution_state == "not_executed"
    )
    preview = not core_failed and not core_not_executed
    stable = preview and not extended_failed and not extended_not_executed
    return LiveLabEligibility(
        preview_signing_eligible=preview,
        stable_promotion_eligible=stable,
        core_failed=core_failed,
        core_not_executed=core_not_executed,
        extended_failed=extended_failed,
        extended_not_executed=extended_not_executed,
    )


def scan_public_live_lab_evidence(payload: object) -> PublicLiveLabEvidence:
    """Reject identifiers, secrets and unbounded text before evidence is public."""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    lowered = serialized.lower()
    if _UUID_PATTERN.search(serialized):
        raise SecurityError("public live-lab evidence contains a raw identifier")
    if _EMAIL_PATTERN.search(serialized) or _IPV4_PATTERN.search(serialized):
        raise SecurityError("public live-lab evidence contains identifying content")
    if _JWT_PATTERN.search(serialized) or "begin private key" in lowered:
        raise SecurityError("public live-lab evidence contains secret material")

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            for raw_key, child in value.items():
                key = str(raw_key).lower().replace("-", "_")
                if key in _FORBIDDEN_PUBLIC_KEYS:
                    raise SecurityError(
                        "public live-lab evidence contains a forbidden field"
                    )
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    inspect(payload)
    try:
        return PublicLiveLabEvidence.model_validate(payload)
    except ValueError as exc:
        raise SecurityError("public live-lab evidence schema is invalid") from exc


def _safe_json(value: BaseModel | dict[str, object]) -> str:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(payload, sort_keys=True, indent=2)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="m365-identity-live-lab")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("requirements")
    inventory = subparsers.add_parser("validate-inventory")
    inventory.add_argument("--inventory", type=Path, required=True)
    subparsers.add_parser("gate")
    evidence = subparsers.add_parser("scan-evidence")
    evidence.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    try:
        if args.command == "requirements":
            print(_safe_json(public_requirements()))
        elif args.command == "validate-inventory":
            inventory = load_live_lab_inventory(args.inventory)
            print(
                _safe_json(
                    {
                        "status": "valid",
                        "environment": inventory.environment,
                        "profile": inventory.profile,
                        "candidate_manifest_digest": (
                            inventory.candidate_manifest_digest
                        ),
                        "effect_model_digest": inventory.effect_model_digest,
                        "contains_identifiers": False,
                    }
                )
            )
        elif args.command == "gate":
            print(_safe_json(load_gate_from_environment(root=root)))
        elif args.command == "scan-evidence":
            payload = json.loads(args.evidence.read_text())
            print(_safe_json(scan_public_live_lab_evidence(payload)))
        else:  # pragma: no cover - argparse owns the closed command set
            raise SecurityError("unsupported live-lab command")
    except (OSError, json.JSONDecodeError, SecurityError):
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason_code": "IDENTITY_LIVE_LAB_GATE_FAILED",
                    "operator_action": (
                        "review the external dedicated-lab inventory and authority"
                    ),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
