"""Read-only profile debt across scopes, contracts, evidence, and fences."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .assurance import AssuranceSnapshotStore
from .config import Settings
from .contract_manifest import ContractManifest, ContractSpec, sha256_digest
from .entra_permission_drift import (
    EntraPermissionGrantDriftService,
    PermissionGrantDriftReport,
    PermissionGrantTargetPosture,
)
from .governance import (
    GovernancePolicyError,
    ProfileDebtBaseline,
    ProfileDebtControl,
    ProfileDebtException,
    VerifiedGovernancePolicy,
)
from .operations import AlignmentStatus, Finding, ResponsibleParty
from .security import PrivateStateError, SecurityError, read_private_file

CONTRACT_ID = "entra.profile_debt.posture.snapshot"
TOOL_NAME = "m365_get_entra_profile_debt_posture"
MAX_AUDIT_BYTES = 16_000_000
MAX_AUDIT_RECORDS = 100_000
AMBIENT_TOKEN_SCOPES = frozenset(
    {"openid", "profile", "email", "offline_access"}
)
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ScopeClaimsSource(Protocol):
    async def delegated_scope_claims(self) -> frozenset[str]: ...


class ProfileDebtSnapshotDomain(StrEnum):
    TOKEN_SCOPES = "token_scopes"  # noqa: S105
    PERMISSION_GRANTS = "permission_grants"
    PROFILE_CONTRACTS = "profile_contracts"
    AUDIT_EVIDENCE = "audit_evidence"
    RESOURCE_FENCES = "resource_fences"
    POLICY_LIFECYCLE = "policy_lifecycle"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScopePosture(StrictModel):
    expected_scopes: list[str]
    token_scopes: list[str]
    missing_token_scopes: list[str]
    unexpected_token_scopes: list[str]
    expected_grant_scope_count: int = Field(ge=0)
    observed_delegated_grant_scope_count: int = Field(ge=0)
    observed_application_grant_count: int = Field(ge=0)
    grant_target_reference: str | None = Field(
        default=None,
        pattern=r"^sp:[0-9a-f]{24}$",
    )
    grant_workload_identity_reference: str | None = Field(
        default=None,
        pattern=r"^wi:[0-9a-f]{24}$",
    )
    grant_alignment: AlignmentStatus
    alignment: AlignmentStatus


class ContractPosture(StrictModel):
    contract_id: str
    tool_name: str
    profile_enabled: bool
    permission_baseline_enabled: bool
    recent_successes: int = Field(ge=0)
    recent_failures: int = Field(ge=0)
    evidence_alignment: AlignmentStatus
    alignment: AlignmentStatus


class ResourcePosture(StrictModel):
    resource_kind: Literal[
        "users",
        "groups",
        "applications",
        "service_principals",
    ]
    governance_count: int = Field(ge=0)
    runtime_count: int = Field(ge=0)
    consuming_contract_count: int = Field(ge=0)
    runtime_matches_governance: bool
    alignment: AlignmentStatus


class ProfileDebtReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["OBSERVED_COMPLETE", "OBSERVED_PARTIAL"]
    contract_id: Literal["entra.profile_debt.posture.snapshot"] = (
        "entra.profile_debt.posture.snapshot"
    )
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_mode: Literal["automatic_read"] = "automatic_read"
    authorization_basis: Literal["signed_policy"] = "signed_policy"
    active_profile: Literal["privileged-read"] = "privileged-read"
    snapshot_id: UUID
    snapshot_reference: str = Field(pattern=r"^snapshot:[0-9a-f-]{36}$")
    captured_at: datetime
    tenant_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")
    coverage_status: dict[
        Literal[
            "token_scopes",
            "permission_grants",
            "profile_contracts",
            "audit_evidence",
            "resource_fences",
            "policy_lifecycle",
        ],
        Literal["complete", "not_evaluated"],
    ]
    baseline_id: str
    baseline_version: int = Field(ge=1)
    policy_version: int = Field(ge=1)
    scope_posture: ScopePosture
    contract_posture: list[ContractPosture]
    resource_posture: list[ResourcePosture]
    findings: list[Finding]
    writes_performed: Literal[False] = False
    consent_changes_performed: Literal[False] = False
    policy_changes_performed: Literal[False] = False
    admin_consent_is_manual: Literal[True] = True


class AuditEvidence(StrictModel):
    available: bool
    successes: dict[str, int]
    failures: dict[str, int]
    reason: Literal["complete", "missing", "invalid", "oversized"]


RESOURCE_CONSUMERS: dict[str, frozenset[str]] = {
    "users": frozenset(
        {
            "entra.user.operational_profile.read",
            "entra.user.operational_profile.update",
        }
    ),
    "groups": frozenset(),
    "applications": frozenset(
        {"entra.app_credentials.posture.snapshot"}
    ),
    "service_principals": frozenset(
        {
            "entra.permission_grants.drift.snapshot",
            "entra.profile_debt.posture.snapshot",
        }
    ),
}


def _canonical_scopes(scopes: frozenset[str] | set[str]) -> dict[str, str]:
    canonical: dict[str, str] = {}
    for scope in scopes:
        name = scope.rsplit("/", 1)[-1]
        lowered = name.lower()
        if lowered not in AMBIENT_TOKEN_SCOPES:
            canonical[lowered] = name
    return canonical


def _read_audit_evidence(
    settings: Settings,
    *,
    contract_tools: frozenset[str],
    since: datetime,
) -> tuple[AuditEvidence, list[dict[str, Any]]]:
    """Read only the configured owner-only audit file and aggregate metadata."""

    path = settings.effective_audit_log_path
    if not path.exists():
        return (
            AuditEvidence(
                available=False,
                successes={},
                failures={},
                reason="missing",
            ),
            [],
        )
    try:
        payload = read_private_file(
            path,
            max_bytes=MAX_AUDIT_BYTES,
            label="profile debt audit evidence",
        )
    except PrivateStateError as exc:
        reason: Literal["invalid", "oversized"] = (
            "oversized" if "byte limit" in str(exc) else "invalid"
        )
        return (
            AuditEvidence(
                available=False,
                successes={},
                failures={},
                reason=reason,
            ),
            [],
        )

    successes = {tool: 0 for tool in sorted(contract_tools)}
    failures = {tool: 0 for tool in sorted(contract_tools)}
    normalized: list[dict[str, Any]] = []
    lines = payload.splitlines()
    if len(lines) > MAX_AUDIT_RECORDS:
        return (
            AuditEvidence(
                available=False,
                successes={},
                failures={},
                reason="oversized",
            ),
            [],
        )
    try:
        for line in lines:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError
            timestamp_text = record.get("timestamp")
            tool = record.get("tool")
            outcome = record.get("outcome")
            namespace = record.get("deployment_namespace")
            if (
                not isinstance(timestamp_text, str)
                or not isinstance(tool, str)
                or not isinstance(outcome, str)
                or not isinstance(namespace, str)
            ):
                raise ValueError
            timestamp = datetime.fromisoformat(
                timestamp_text.replace("Z", "+00:00")
            )
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError
            if (
                namespace != settings.deployment_namespace
                or timestamp < since
                or tool not in contract_tools
            ):
                continue
            if outcome == "success":
                successes[tool] += 1
            elif outcome.startswith("error:"):
                failures[tool] += 1
            normalized.append(
                {
                    "timestamp": timestamp.isoformat(),
                    "tool": tool,
                    "outcome_class": (
                        "success"
                        if outcome == "success"
                        else "failure"
                        if outcome.startswith("error:")
                        else "attempt"
                    ),
                }
            )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return (
            AuditEvidence(
                available=False,
                successes={},
                failures={},
                reason="invalid",
            ),
            [],
        )
    return (
        AuditEvidence(
            available=True,
            successes=successes,
            failures=failures,
            reason="complete",
        ),
        normalized,
    )


class EntraProfileDebtService:
    """Correlate signed profile intent with observed runtime evidence."""

    def __init__(
        self,
        *,
        scope_source: ScopeClaimsSource,
        settings: Settings,
        manifest: ContractManifest,
        governance: VerifiedGovernancePolicy,
        snapshots: AssuranceSnapshotStore,
        permission_drift: EntraPermissionGrantDriftService,
    ) -> None:
        self.scope_source = scope_source
        self.settings = settings
        self.manifest = manifest
        self.contract: ContractSpec = manifest.contract(CONTRACT_ID)
        self.governance = governance
        self.snapshots = snapshots
        self.permission_drift = permission_drift

    @staticmethod
    def _active_exceptions(
        baseline: ProfileDebtBaseline,
        *,
        now: datetime,
    ) -> dict[tuple[ProfileDebtControl, str], ProfileDebtException]:
        return {
            (item.control_id, item.subject): item
            for item in baseline.exceptions
            if item.expires_at > now
        }

    def _finding(
        self,
        *,
        baseline: ProfileDebtBaseline,
        exceptions: Mapping[
            tuple[ProfileDebtControl, str],
            ProfileDebtException,
        ],
        control: ProfileDebtControl,
        subject: str,
        summary: str,
        action: str,
        party: ResponsibleParty,
        evidence_reference: str,
        alignment: AlignmentStatus = AlignmentStatus.NOT_ALIGNED,
    ) -> Finding:
        exception = exceptions.get((control, subject))
        if exception is not None:
            alignment = AlignmentStatus.EXCEPTION_APPROVED
            action = (
                "Review the signed exception before its expiry; no runtime "
                "policy or grant was changed."
            )
            party = ResponsibleParty.GOVERNANCE_OWNER
        finding_reference = self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="finding",
            resource_id=f"{control.value}:{subject}",
        )
        return Finding(
            finding_id=f"profile-debt:{finding_reference}",
            control_id=control.value,
            status=alignment.value,
            severity=baseline.severities[control].value,
            summary=summary,
            evidence_reference=evidence_reference,
            alignment=alignment,
            operator_action=action,
            responsible_party=party,
            baseline_reference=f"{baseline.baseline_id}:v{baseline.version}",
        )

    @staticmethod
    def _current_target(
        report: PermissionGrantDriftReport,
        *,
        expected_workload_reference: str,
    ) -> PermissionGrantTargetPosture | None:
        matches = [
            item
            for item in report.targets
            if item.workload_identity_reference
            == expected_workload_reference
        ]
        if len(matches) > 1:
            raise SecurityError(
                "permission baseline contains duplicate workload identities"
            )
        return matches[0] if matches else None

    def _resource_sets(self) -> tuple[
        dict[str, frozenset[str]],
        dict[str, frozenset[str]],
    ]:
        resources = self.governance.policy.resources
        governance_sets = {
            "users": frozenset(str(item) for item in resources.users),
            "groups": frozenset(str(item) for item in resources.groups),
            "applications": frozenset(
                str(item) for item in resources.applications
            ),
            "service_principals": frozenset(
                str(item) for item in resources.service_principals
            ),
        }
        runtime_sets = {
            "users": self.settings.target_user_ids,
            "groups": self.settings.group_ids,
            "applications": self.settings.application_ids,
            "service_principals": self.settings.service_principal_ids,
        }
        return governance_sets, runtime_sets

    async def collect(self) -> ProfileDebtReport:
        decision, baseline = self.governance.authorize_profile_debt_read(
            self.contract,
            tenant_id=self.settings.tenant_id,
        )
        if decision.profile.value != "privileged-read":
            raise GovernancePolicyError(
                "profile debt analysis requires privileged-read",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )

        policy = self.governance.policy
        profile = policy.profiles[policy.active_profile]
        profile_contract_ids = frozenset(profile.enabled_contracts)
        profile_contracts = {
            contract_id: self.manifest.contract(contract_id)
            for contract_id in profile_contract_ids
        }
        expected_scope_map = _canonical_scopes(
            {
                "User.Read",
                *(
                    scope
                    for contract in profile_contracts.values()
                    for scope in contract.permissions.delegated_scopes
                ),
            }
        )
        token_scope_map = _canonical_scopes(
            set(await self.scope_source.delegated_scope_claims())
        )
        missing_scopes = sorted(
            expected_scope_map[key]
            for key in expected_scope_map.keys() - token_scope_map.keys()
        )
        unexpected_scopes = sorted(
            token_scope_map[key]
            for key in token_scope_map.keys() - expected_scope_map.keys()
        )

        permission_report = await self.permission_drift.collect()
        expected_workload_reference = self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="wi",
            resource_id=self.settings.client_id,
        )
        current_target = self._current_target(
            permission_report,
            expected_workload_reference=expected_workload_reference,
        )
        permission_contract_ids = frozenset(
            current_target.contract_ids if current_target is not None else []
        )

        now = datetime.now(UTC)
        evidence_since = now - timedelta(
            days=baseline.evidence_window_days
        )
        contract_tools = frozenset(
            contract.tool_name for contract in profile_contracts.values()
        )
        audit, audit_records = _read_audit_evidence(
            self.settings,
            contract_tools=contract_tools,
            since=evidence_since,
        )
        governance_sets, runtime_sets = self._resource_sets()
        all_enabled_contracts = frozenset(
            contract_id
            for item in policy.profiles.values()
            for contract_id in item.enabled_contracts
        )

        refreshed = self.governance.refresh()
        refreshed_decision, refreshed_baseline = (
            refreshed.authorize_profile_debt_read(
                self.contract,
                tenant_id=self.settings.tenant_id,
            )
        )
        if (
            refreshed_decision != decision
            or refreshed_baseline != baseline
            or refreshed.policy.profiles[refreshed.policy.active_profile]
            != profile
            or refreshed.policy.resources != policy.resources
        ):
            raise GovernancePolicyError(
                "governance authorization changed during profile debt collection",
                reason_code="POLICY_CHANGED",
            )

        snapshot_id = uuid4()
        snapshot_reference = self.snapshots.store(
            snapshot_id=snapshot_id,
            contract_id=CONTRACT_ID,
            tenant_id=self.settings.tenant_id,
            domains={
                ProfileDebtSnapshotDomain.TOKEN_SCOPES: [
                    {
                        "expected": sorted(expected_scope_map.values()),
                        "observed": sorted(token_scope_map.values()),
                    }
                ],
                ProfileDebtSnapshotDomain.PERMISSION_GRANTS: [
                    {
                        "permission_snapshot_reference": (
                            permission_report.snapshot_reference
                        ),
                        "current_target_observed": current_target is not None,
                        "baseline_contract_ids": sorted(
                            permission_contract_ids
                        ),
                    }
                ],
                ProfileDebtSnapshotDomain.PROFILE_CONTRACTS: [
                    {
                        "contract_id": contract_id,
                        "tool_name": profile_contracts[
                            contract_id
                        ].tool_name,
                    }
                    for contract_id in sorted(profile_contract_ids)
                ],
                ProfileDebtSnapshotDomain.AUDIT_EVIDENCE: audit_records,
                ProfileDebtSnapshotDomain.RESOURCE_FENCES: [
                    {
                        "resource_kind": kind,
                        "governance_ids": sorted(governance_sets[kind]),
                        "runtime_ids": sorted(runtime_sets[kind]),
                    }
                    for kind in sorted(RESOURCE_CONSUMERS)
                ],
                ProfileDebtSnapshotDomain.POLICY_LIFECYCLE: [
                    {
                        "policy_version": policy.policy_version,
                        "policy_issued_at": policy.issued_at.isoformat(),
                        "evidence_window_start": evidence_since.isoformat(),
                    }
                ],
            },
        )
        exceptions = self._active_exceptions(baseline, now=now)
        findings: list[Finding] = []

        if current_target is None:
            findings.append(
                self._finding(
                    baseline=baseline,
                    exceptions=exceptions,
                    control=ProfileDebtControl.CURRENT_APP_BASELINE_MISSING,
                    subject="current_app",
                    summary=(
                        "The current workload identity is not an exact target "
                        "in the signed permission baseline."
                    ),
                    action=(
                        "Add the current service principal and exact contract "
                        "closure to Governance, then re-sign the tenant policy."
                    ),
                    party=ResponsibleParty.GOVERNANCE_OWNER,
                    evidence_reference=snapshot_reference,
                    alignment=AlignmentStatus.NOT_EVALUATED,
                )
            )
        elif current_target.alignment is not AlignmentStatus.ALIGNED:
            findings.append(
                self._finding(
                    baseline=baseline,
                    exceptions=exceptions,
                    control=ProfileDebtControl.PERMISSION_GRANT_DRIFT,
                    subject="current_app",
                    summary=(
                        "The current workload identity grant posture is not "
                        "aligned with its signed contract-derived baseline."
                    ),
                    action=(
                        "Review the permission-grant drift evidence and have "
                        "the tenant administrator correct grants manually."
                    ),
                    party=(
                        ResponsibleParty.GOVERNANCE_OWNER
                        if current_target.alignment
                        is AlignmentStatus.EXCEPTION_APPROVED
                        else ResponsibleParty.TENANT_ADMIN
                    ),
                    evidence_reference=permission_report.snapshot_reference,
                    alignment=current_target.alignment,
                )
            )
        for scope in missing_scopes:
            findings.append(
                self._finding(
                    baseline=baseline,
                    exceptions=exceptions,
                    control=ProfileDebtControl.TOKEN_SCOPE_MISSING,
                    subject=scope,
                    summary=f"Validated token is missing required scope {scope}.",
                    action=(
                        "Have the tenant administrator grant and consent the "
                        "exact documented permission manually, then reauthenticate."
                    ),
                    party=ResponsibleParty.TENANT_ADMIN,
                    evidence_reference=snapshot_reference,
                )
            )
        for scope in unexpected_scopes:
            findings.append(
                self._finding(
                    baseline=baseline,
                    exceptions=exceptions,
                    control=ProfileDebtControl.TOKEN_SCOPE_UNEXPECTED,
                    subject=scope,
                    summary=(
                        f"Validated token contains scope {scope} outside the "
                        "active signed profile closure."
                    ),
                    action=(
                        "Review the dedicated App Registration and remove the "
                        "unneeded grant manually or isolate this profile."
                    ),
                    party=ResponsibleParty.TENANT_ADMIN,
                    evidence_reference=snapshot_reference,
                )
            )

        contract_posture: list[ContractPosture] = []
        contract_union = profile_contract_ids | permission_contract_ids
        fresh_evidence_contracts = frozenset(
            {"entra.permission_grants.drift.snapshot"}
        )
        for contract_id in sorted(contract_union):
            contract = self.manifest.contract(contract_id)
            profile_enabled = contract_id in profile_contract_ids
            baseline_enabled = contract_id in permission_contract_ids
            successes = max(
                audit.successes.get(contract.tool_name, 0),
                1 if contract_id in fresh_evidence_contracts else 0,
            )
            failures = audit.failures.get(contract.tool_name, 0)
            if contract_id == CONTRACT_ID:
                evidence_alignment = AlignmentStatus.NOT_APPLICABLE
            elif contract_id in fresh_evidence_contracts:
                evidence_alignment = AlignmentStatus.ALIGNED
            elif not audit.available:
                evidence_alignment = AlignmentStatus.NOT_EVALUATED
            elif successes == 0:
                evidence_alignment = AlignmentStatus.NOT_ALIGNED
            elif failures >= baseline.persistent_failure_threshold:
                evidence_alignment = AlignmentStatus.NOT_ALIGNED
            else:
                evidence_alignment = AlignmentStatus.ALIGNED
            baseline_alignment = (
                AlignmentStatus.ALIGNED
                if profile_enabled == baseline_enabled
                else AlignmentStatus.NOT_ALIGNED
            )
            alignment = (
                baseline_alignment
                if baseline_alignment is AlignmentStatus.NOT_ALIGNED
                else evidence_alignment
            )
            contract_posture.append(
                ContractPosture(
                    contract_id=contract_id,
                    tool_name=contract.tool_name,
                    profile_enabled=profile_enabled,
                    permission_baseline_enabled=baseline_enabled,
                    recent_successes=successes,
                    recent_failures=failures,
                    evidence_alignment=evidence_alignment,
                    alignment=alignment,
                )
            )
            if baseline_alignment is AlignmentStatus.NOT_ALIGNED:
                findings.append(
                    self._finding(
                        baseline=baseline,
                        exceptions=exceptions,
                        control=(
                            ProfileDebtControl.CONTRACT_BASELINE_MISMATCH
                        ),
                        subject=contract_id,
                        summary=(
                            "Contract selection differs between the active "
                            "profile and the current-app permission baseline."
                        ),
                        action=(
                            "Align the exact contract IDs in the private "
                            "Governance profile and permission baseline, then re-sign."
                        ),
                        party=ResponsibleParty.GOVERNANCE_OWNER,
                        evidence_reference=snapshot_reference,
                    )
                )
            if (
                contract_id != CONTRACT_ID
                and evidence_alignment
                in {
                    AlignmentStatus.NOT_ALIGNED,
                    AlignmentStatus.NOT_EVALUATED,
                }
                and successes == 0
            ):
                findings.append(
                    self._finding(
                        baseline=baseline,
                        exceptions=exceptions,
                        control=(
                            ProfileDebtControl.CONTRACT_NO_RECENT_EVIDENCE
                        ),
                        subject=contract_id,
                        summary=(
                            "No successful execution evidence was observed for "
                            f"{contract_id} in the signed evidence window."
                        ),
                        action=(
                            "Run the governed read when operationally needed, "
                            "or remove the unused contract in the next signed policy."
                        ),
                        party=ResponsibleParty.OPERATOR,
                        evidence_reference=snapshot_reference,
                        alignment=evidence_alignment,
                    )
                )
            if failures >= baseline.persistent_failure_threshold:
                findings.append(
                    self._finding(
                        baseline=baseline,
                        exceptions=exceptions,
                        control=(
                            ProfileDebtControl.CONTRACT_PERSISTENT_FAILURE
                        ),
                        subject=contract_id,
                        summary=(
                            f"{contract_id} reached the signed persistent-failure "
                            "threshold in the evidence window."
                        ),
                        action=(
                            "Inspect the metadata-only audit trail and resolve "
                            "the deterministic precondition before retrying."
                        ),
                        party=ResponsibleParty.OPERATOR,
                        evidence_reference=snapshot_reference,
                    )
                )

        policy_age = now - policy.issued_at.astimezone(UTC)
        if policy.policy_version < baseline.minimum_policy_version:
            findings.append(
                self._finding(
                    baseline=baseline,
                    exceptions=exceptions,
                    control=ProfileDebtControl.POLICY_VERSION_STALE,
                    subject="policy",
                    summary=(
                        "The signed Governance policy version is below the "
                        "customer-approved minimum."
                    ),
                    action=(
                        "Review and issue a newer private Governance policy; "
                        "runtime will not update or sign it."
                    ),
                    party=ResponsibleParty.GOVERNANCE_OWNER,
                    evidence_reference=snapshot_reference,
                )
            )
        if policy_age > timedelta(days=baseline.maximum_policy_age_days):
            findings.append(
                self._finding(
                    baseline=baseline,
                    exceptions=exceptions,
                    control=ProfileDebtControl.POLICY_AGE_STALE,
                    subject="policy",
                    summary=(
                        "The signed Governance policy is older than the "
                        "customer-approved review interval."
                    ),
                    action=(
                        "Review tenant intent and reissue the policy through "
                        "the external Governance signing workflow."
                    ),
                    party=ResponsibleParty.GOVERNANCE_OWNER,
                    evidence_reference=snapshot_reference,
                )
            )

        resource_posture: list[ResourcePosture] = []
        for kind in sorted(RESOURCE_CONSUMERS):
            governance_set = governance_sets[kind]
            runtime_set = runtime_sets[kind]
            consumers = RESOURCE_CONSUMERS[kind] & all_enabled_contracts
            matches = governance_set == runtime_set
            if not governance_set and not runtime_set:
                alignment = AlignmentStatus.NOT_APPLICABLE
            elif not matches:
                alignment = AlignmentStatus.NOT_ALIGNED
            elif not consumers:
                alignment = AlignmentStatus.NOT_ALIGNED
            else:
                alignment = AlignmentStatus.ALIGNED
            resource_posture.append(
                ResourcePosture(
                    resource_kind=kind,  # type: ignore[arg-type]
                    governance_count=len(governance_set),
                    runtime_count=len(runtime_set),
                    consuming_contract_count=len(consumers),
                    runtime_matches_governance=matches,
                    alignment=alignment,
                )
            )
            if not matches:
                findings.append(
                    self._finding(
                        baseline=baseline,
                        exceptions=exceptions,
                        control=ProfileDebtControl.RESOURCE_FENCE_MISMATCH,
                        subject=kind,
                        summary=(
                            f"The private Governance and local runtime {kind} "
                            "fences do not contain the same exact IDs."
                        ),
                        action=(
                            "Align the local allowlist and signed private policy "
                            "through their owner-controlled configuration paths."
                        ),
                        party=ResponsibleParty.GOVERNANCE_OWNER,
                        evidence_reference=snapshot_reference,
                    )
                )
            elif governance_set and not consumers:
                findings.append(
                    self._finding(
                        baseline=baseline,
                        exceptions=exceptions,
                        control=(
                            ProfileDebtControl.RESOURCE_ALLOWLIST_UNUSED
                        ),
                        subject=kind,
                        summary=(
                            f"The {kind} allowlist has entries but no enabled "
                            "compiled contract consumes that resource class."
                        ),
                        action=(
                            "Remove the unused fence in the next signed policy "
                            "and local configuration review."
                        ),
                        party=ResponsibleParty.GOVERNANCE_OWNER,
                        evidence_reference=snapshot_reference,
                    )
                )

        token_debt_exceptions_complete = bool(
            missing_scopes or unexpected_scopes
        ) and all(
            (
                control,
                scope,
            )
            in exceptions
            for control, scopes in (
                (ProfileDebtControl.TOKEN_SCOPE_MISSING, missing_scopes),
                (
                    ProfileDebtControl.TOKEN_SCOPE_UNEXPECTED,
                    unexpected_scopes,
                ),
            )
            for scope in scopes
        )
        scope_alignment = (
            AlignmentStatus.NOT_EVALUATED
            if current_target is None
            else AlignmentStatus.NOT_ALIGNED
            if (
                current_target.alignment is AlignmentStatus.NOT_ALIGNED
                or profile_contract_ids != permission_contract_ids
                or (
                    (missing_scopes or unexpected_scopes)
                    and not token_debt_exceptions_complete
                )
            )
            else AlignmentStatus.EXCEPTION_APPROVED
            if (
                token_debt_exceptions_complete
                or current_target.alignment
                is AlignmentStatus.EXCEPTION_APPROVED
            )
            else AlignmentStatus.ALIGNED
        )
        coverage: dict[str, Literal["complete", "not_evaluated"]] = {
            "token_scopes": "complete",
            "permission_grants": (
                "complete"
                if current_target is not None
                else "not_evaluated"
            ),
            "profile_contracts": "complete",
            "audit_evidence": (
                "complete" if audit.available else "not_evaluated"
            ),
            "resource_fences": "complete",
            "policy_lifecycle": "complete",
        }
        findings.sort(
            key=lambda item: (
                SEVERITY_ORDER[item.severity],
                item.control_id,
                item.finding_id,
            )
        )
        return ProfileDebtReport(
            status=(
                "OBSERVED_COMPLETE"
                if all(value == "complete" for value in coverage.values())
                else "OBSERVED_PARTIAL"
            ),
            contract_digest=sha256_digest(self.contract),
            contract_manifest_digest=sha256_digest(self.manifest),
            policy_digest=refreshed.policy_digest,
            snapshot_id=snapshot_id,
            snapshot_reference=snapshot_reference,
            captured_at=now,
            tenant_namespace=self.settings.deployment_namespace,
            coverage_status=coverage,  # type: ignore[arg-type]
            baseline_id=baseline.baseline_id,
            baseline_version=baseline.version,
            policy_version=policy.policy_version,
            scope_posture=ScopePosture(
                expected_scopes=sorted(expected_scope_map.values()),
                token_scopes=sorted(token_scope_map.values()),
                missing_token_scopes=missing_scopes,
                unexpected_token_scopes=unexpected_scopes,
                expected_grant_scope_count=(
                    current_target.expected_delegated_permissions
                    if current_target is not None
                    else 0
                ),
                observed_delegated_grant_scope_count=(
                    current_target.observed_delegated_permissions
                    if current_target is not None
                    else 0
                ),
                observed_application_grant_count=(
                    current_target.observed_application_permissions
                    if current_target is not None
                    else 0
                ),
                grant_target_reference=(
                    current_target.target_reference
                    if current_target is not None
                    else None
                ),
                grant_workload_identity_reference=(
                    current_target.workload_identity_reference
                    if current_target is not None
                    else None
                ),
                grant_alignment=(
                    current_target.alignment
                    if current_target is not None
                    else AlignmentStatus.NOT_EVALUATED
                ),
                alignment=scope_alignment,
            ),
            contract_posture=contract_posture,
            resource_posture=resource_posture,
            findings=findings,
        )
