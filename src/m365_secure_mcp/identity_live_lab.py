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
from pathlib import Path
from typing import Literal
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .contract_compiler import load_identity_candidate
from .contract_manifest import effect_model_digest, sha256_digest
from .governance import (
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
LAB_WRITE_ACK_ENV = "M365_IDENTITY_LIVE_LAB_WRITE_ACK"
LAB_WRITE_ACK = "DEDICATED_NONPRODUCTION_IDENTITY_LAB"
LAB_PROFILE = "live-lab"
MAX_INVENTORY_BYTES = 64 * 1024
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"

REQUIRED_EXTERNAL_ENV = (
    "M365_CLIENT_ID",
    "M365_GOVERNANCE_POLICY_PATH",
    "M365_GOVERNANCE_PUBLIC_KEY_PATH",
    "M365_APPROVAL_PUBLIC_KEY_PATH",
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
PROJECT_REQUIRED_ROLES = (
    "Global Reader",
    "Groups Administrator",
    "Helpdesk Administrator",
    "License Administrator",
    "User Administrator",
)
IDENTITY_OPERATIONS = (
    "entra.group.user_membership.add",
    "entra.group.user_membership.remove",
    "entra.user.account_state.set",
    "entra.user.direct_license.set",
    "entra.user.sessions.revoke",
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


class LiveLabUsers(FrozenModel):
    normal_enabled_user_id: UUID
    normal_disabled_user_id: UUID
    direct_license_user_id: UUID
    inherited_license_user_id: UUID
    guest_user_id: UUID
    synchronized_user_id: UUID
    administrator_user_id: UUID
    break_glass_user_id: UUID
    no_usage_location_user_id: UUID
    outside_allowlist_user_id: UUID


class LiveLabGroups(FrozenModel):
    allowed_static_group_id: UUID
    protected_static_group_id: UUID
    dynamic_group_id: UUID
    role_assignable_group_id: UUID
    outside_allowlist_group_id: UUID


class LiveLabRelationships(FrozenModel):
    already_member_user_id: UUID
    already_member_group_id: UUID
    non_member_user_id: UUID
    non_member_group_id: UUID
    inherited_license_group_id: UUID


class LiveLabLicenses(FrozenModel):
    allowed_sku_id: UUID
    disallowed_sku_id: UUID
    allowed_service_plan_ids: tuple[UUID, ...] = Field(min_length=1)
    disallowed_service_plan_id: UUID


class IdentityLiveLabInventory(FrozenModel):
    """Private external inventory. It contains identifiers and is never committed."""

    schema_version: Literal["1.0"]
    environment: Literal["dedicated-nonproduction"]
    profile: Literal["live-lab"]
    tenant_id: UUID
    client_id: UUID
    operator_object_id: UUID
    candidate_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    effect_model_digest: str = Field(pattern=SHA256_PATTERN)
    governance_policy_digest: str = Field(pattern=SHA256_PATTERN)
    marker: LiveLabMarker
    users: LiveLabUsers
    groups: LiveLabGroups
    relationships: LiveLabRelationships
    licenses: LiveLabLicenses
    allowlisted_user_ids: tuple[UUID, ...] = Field(min_length=1)
    allowlisted_group_ids: tuple[UUID, ...] = Field(min_length=1)
    protected_user_ids: tuple[UUID, ...] = Field(min_length=1)
    protected_group_ids: tuple[UUID, ...] = Field(min_length=1)
    allowed_sku_ids: tuple[UUID, ...] = Field(min_length=1)
    allowed_service_plan_ids: dict[UUID, tuple[UUID, ...]]

    @model_validator(mode="after")
    def validate_closed_lab_topology(self) -> IdentityLiveLabInventory:
        user_ids = tuple(self.users.model_dump().values())
        group_ids = tuple(self.groups.model_dump().values())
        if len(set(user_ids)) != len(user_ids):
            raise ValueError("live-lab user fixtures must use distinct object IDs")
        if len(set(group_ids)) != len(group_ids):
            raise ValueError("live-lab group fixtures must use distinct object IDs")
        if self.operator_object_id in set(user_ids):
            raise ValueError("live-lab operator must be separate from target fixtures")
        if self.marker.group_id in set(group_ids):
            raise ValueError("lab marker must be separate from operation target groups")

        expected_users = set(user_ids) - {self.users.outside_allowlist_user_id}
        if set(self.allowlisted_user_ids) != expected_users:
            raise ValueError("live-lab user allowlist does not match fixture topology")
        expected_groups = set(group_ids) - {self.groups.outside_allowlist_group_id}
        if set(self.allowlisted_group_ids) != expected_groups:
            raise ValueError("live-lab group allowlist does not match fixture topology")
        if set(self.protected_user_ids) != {
            self.users.administrator_user_id,
            self.users.break_glass_user_id,
        }:
            raise ValueError("live-lab protected users must be exact")
        if set(self.protected_group_ids) != {
            self.groups.protected_static_group_id,
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
            self.relationships.already_member_user_id,
            self.relationships.non_member_user_id,
        }
        relationship_groups = {
            self.relationships.already_member_group_id,
            self.relationships.non_member_group_id,
            self.relationships.inherited_license_group_id,
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
    candidate_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    effect_model_digest: str = Field(pattern=SHA256_PATTERN)
    resource_counts: dict[str, int]
    external_authority_present: bool


class PublicLiveLabCase(FrozenModel):
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
    passed: bool


class PublicLiveLabEvidence(FrozenModel):
    schema_version: Literal["1.0"]
    evidence_kind: Literal["sanitized-identity-live-lab"]
    contains_customer_data: Literal[False]
    candidate_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    cases: tuple[PublicLiveLabCase, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def deterministic_cases(self) -> PublicLiveLabEvidence:
        scenarios = [item.scenario for item in self.cases]
        if scenarios != sorted(set(scenarios)):
            raise ValueError("live-lab evidence scenarios must be unique and sorted")
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
    """Verify private Governance and one approval verifier without disclosing them."""

    try:
        verified = load_verified_governance_policy(
            Path(environ["M365_GOVERNANCE_POLICY_PATH"]),
            Path(environ["M365_GOVERNANCE_PUBLIC_KEY_PATH"]),
        )
    except (KeyError, PrivateStateError, ValueError) as exc:
        raise SecurityError("identity live lab external authority is invalid") from exc
    policy = verified.bundle.policy
    if not isinstance(policy, GovernancePolicyV3):
        raise SecurityError("identity live lab requires signed Governance v3")
    candidate = load_identity_candidate(root)
    candidate_digest = sha256_digest(candidate)
    if (
        verified.policy_digest != inventory.governance_policy_digest
        or policy.tenant_id != inventory.tenant_id
        or policy.active_profile is not GovernanceProfileName.SELECTED_WRITE
        or policy.contract_manifest_digest != candidate_digest
        or policy.operations.contract_manifest_digest != candidate_digest
        or policy.operations.effect_model_digest != effect_model_digest()
    ):
        raise SecurityError("identity live lab Governance binding does not match")
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
        != {inventory.users.break_glass_user_id}
        or resources.emergency_access_user_ids
        or set(resources.protected_group_ids) != set(inventory.protected_group_ids)
        or set(resources.allowed_sku_ids) != set(inventory.allowed_sku_ids)
        or policy_service_plans != inventory.allowed_service_plan_ids
    ):
        raise SecurityError("identity live lab Governance resource fences differ")
    try:
        for contract in candidate.contracts:
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
    if fingerprint not in {
        item.public_key_sha256 for item in policy.operations.approval_authorities
    }:
        raise SecurityError("identity live lab approval authority is not governed")


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
    try:
        environment_tenant = UUID(environ.get(LAB_TENANT_ENV, ""))
        environment_client = UUID(environ.get("M365_CLIENT_ID", ""))
    except ValueError as exc:
        raise SecurityError("identity live lab binding is incomplete") from exc
    if (
        environment_tenant != inventory.tenant_id
        or environment_client != inventory.client_id
    ):
        raise SecurityError("identity live lab process binding does not match inventory")
    missing = [name for name in REQUIRED_EXTERNAL_ENV if not environ.get(name)]
    if missing:
        raise SecurityError("identity live lab external authority is incomplete")
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
        candidate_manifest_digest=expected_candidate,
        effect_model_digest=expected_effect,
        resource_counts={
            "groups": len(LiveLabGroups.model_fields),
            "licenses": 2,
            "marker_groups": 1,
            "service_plans": len(inventory.licenses.allowed_service_plan_ids) + 1,
            "users": len(LiveLabUsers.model_fields),
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
        "schema_version": "1.0",
        "environment": "dedicated-nonproduction",
        "profile": LAB_PROFILE,
        "operations": list(IDENTITY_OPERATIONS),
        "delegated_scopes": sorted(REQUIRED_DELEGATED_SCOPES),
        "project_required_roles": list(PROJECT_REQUIRED_ROLES),
        "resource_counts": {
            "users": 10,
            "groups": 5,
            "independent_marker_groups": 1,
            "subscribed_skus": 2,
            "service_plan_classes": 2,
        },
        "external_material": [
            "dedicated public-client App Registration",
            "signed Governance v3 live-lab policy",
            "external Governance verification key",
            "external approval verification key",
            "OS-keychain or memory-only delegated token cache",
        ],
        "automatic_provisioning": False,
        "contains_identifiers": False,
        "contains_credentials": False,
    }


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
