"""Read-only Entra Identity Governance posture and signed-baseline drift."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .assurance import AssuranceSnapshotStore
from .config import Settings
from .contract_manifest import ContractManifest, ContractSpec, sha256_digest
from .governance import (
    AssuranceDomainName,
    AssuranceException,
    DriftSeverity,
    GovernancePolicyError,
    IdentityGovernanceBaseline,
    VerifiedGovernancePolicy,
)
from .graph import GraphClient
from .operations import (
    AlignmentStatus,
    Finding,
    ResponsibleParty,
)
from .security import SecurityError

CONTRACT_ID = "entra.identity_governance.posture.snapshot"
TOOL_NAME = "m365_get_entra_identity_governance_posture"

CONDITIONAL_ACCESS_ENDPOINT = "/identity/conditionalAccess/policies"
PERMANENT_ROLE_ENDPOINT = "/roleManagement/directory/roleAssignments"
ACTIVE_ROLE_ENDPOINT = (
    "/roleManagement/directory/roleAssignmentScheduleInstances"
)
ELIGIBLE_ROLE_ENDPOINT = (
    "/roleManagement/directory/roleEligibilityScheduleInstances"
)

DOMAIN_ENDPOINTS: dict[AssuranceDomainName, tuple[str, str]] = {
    AssuranceDomainName.CONDITIONAL_ACCESS: (
        CONDITIONAL_ACCESS_ENDPOINT,
        "id,state,conditions,grantControls,sessionControls",
    ),
    AssuranceDomainName.PERMANENT_ROLE_ASSIGNMENTS: (
        PERMANENT_ROLE_ENDPOINT,
        "id,principalId,roleDefinitionId,directoryScopeId,appScopeId",
    ),
    AssuranceDomainName.ACTIVE_ROLE_ASSIGNMENTS: (
        ACTIVE_ROLE_ENDPOINT,
        (
            "id,principalId,roleDefinitionId,directoryScopeId,appScopeId,"
            "assignmentType,memberType,startDateTime,endDateTime"
        ),
    ),
    AssuranceDomainName.ELIGIBLE_ROLE_ASSIGNMENTS: (
        ELIGIBLE_ROLE_ENDPOINT,
        (
            "id,principalId,roleDefinitionId,directoryScopeId,appScopeId,"
            "memberType,startDateTime,endDateTime"
        ),
    ),
}

CA_STATES = frozenset(
    {"enabled", "disabled", "enabledForReportingButNotEnforced"}
)
MAX_NORMALIZED_DEPTH = 12
MAX_NORMALIZED_LIST_ITEMS = 2_000
MAX_NORMALIZED_OBJECT_KEYS = 100
MAX_NORMALIZED_STRING = 2_048
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BaselineSummary(StrictModel):
    configured: bool
    baseline_id: str | None = None
    version: int | None = None
    captured_at: datetime | None = None


class DomainPosture(StrictModel):
    domain: AssuranceDomainName
    digest: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    item_count: int = Field(ge=0)
    pages_read: int = Field(ge=1)
    metrics: dict[str, int]
    alignment: AlignmentStatus
    drift_severity: DriftSeverity | None = None


class IdentityGovernancePostureReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["OBSERVED_COMPLETE"] = "OBSERVED_COMPLETE"
    contract_id: Literal["entra.identity_governance.posture.snapshot"] = (
        "entra.identity_governance.posture.snapshot"
    )
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_mode: Literal["automatic_read"] = "automatic_read"
    authorization_basis: Literal["signed_policy"] = "signed_policy"
    active_profile: Literal["routine-read", "privileged-read"]
    snapshot_id: UUID
    snapshot_reference: str = Field(pattern=r"^snapshot:[0-9a-f-]{36}$")
    captured_at: datetime
    tenant_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")
    coverage_status: Literal["complete"] = "complete"
    baseline: BaselineSummary
    domains: list[DomainPosture] = Field(min_length=4, max_length=4)
    findings: list[Finding]
    writes_performed: Literal[False] = False
    admin_consent_is_manual: Literal[True] = True


def _safe_scalar(
    value: Any,
    *,
    field: str,
    required: bool = False,
) -> str | None:
    if value is None:
        if required:
            raise SecurityError(f"Microsoft Graph omitted {field}")
        return None
    if not isinstance(value, str):
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    if (
        not value
        or len(value) > MAX_NORMALIZED_STRING
        or any(ord(character) < 32 for character in value)
    ):
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    return value


def _normalize_json(value: Any, *, depth: int = 0) -> Any:
    """Bound nested Graph policy data without trusting its content."""

    if depth > MAX_NORMALIZED_DEPTH:
        raise SecurityError("Conditional Access policy nesting exceeds the contract")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > MAX_NORMALIZED_STRING:
            raise SecurityError("Conditional Access policy text exceeds the contract")
        if any(ord(character) < 32 for character in value):
            raise SecurityError("Conditional Access policy contains control characters")
        return value
    if isinstance(value, list):
        if len(value) > MAX_NORMALIZED_LIST_ITEMS:
            raise SecurityError("Conditional Access list exceeds the contract")
        return [
            _normalize_json(item, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, dict):
        keys = [
            key
            for key in value
            if isinstance(key, str) and not key.startswith("@odata.")
        ]
        if len(keys) != len(
            [key for key in value if not str(key).startswith("@odata.")]
        ):
            raise SecurityError("Conditional Access policy has invalid object keys")
        if any(
            len(key) > 128 or any(ord(character) < 32 for character in key)
            for key in keys
        ):
            raise SecurityError("Conditional Access policy has unsafe object keys")
        if len(keys) > MAX_NORMALIZED_OBJECT_KEYS:
            raise SecurityError("Conditional Access object exceeds the contract")
        return {
            key: _normalize_json(value[key], depth=depth + 1)
            for key in sorted(keys)
        }
    raise SecurityError("Conditional Access policy contains an unsupported value")


def _normalize_conditional_access(record: dict[str, Any]) -> dict[str, Any]:
    policy_id = _safe_scalar(
        record.get("id"),
        field="Conditional Access ID",
        required=True,
    )
    state = _safe_scalar(
        record.get("state"),
        field="Conditional Access state",
        required=True,
    )
    if state not in CA_STATES:
        raise SecurityError("Microsoft Graph returned an unknown Conditional Access state")
    if not isinstance(record.get("conditions"), dict):
        raise SecurityError("Microsoft Graph omitted Conditional Access conditions")
    return {
        "id": policy_id,
        "state": state,
        "conditions": _normalize_json(record.get("conditions")),
        "grantControls": _normalize_json(record.get("grantControls")),
        "sessionControls": _normalize_json(record.get("sessionControls")),
    }


def _normalize_role_assignment(
    record: dict[str, Any],
    *,
    scheduled: bool,
) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "id": _safe_scalar(
            record.get("id"),
            field="role assignment ID",
            required=True,
        ),
        "principalId": _safe_scalar(
            record.get("principalId"),
            field="role assignment principal ID",
            required=True,
        ),
        "roleDefinitionId": _safe_scalar(
            record.get("roleDefinitionId"),
            field="role definition ID",
            required=True,
        ),
        "directoryScopeId": _safe_scalar(
            record.get("directoryScopeId"),
            field="directory scope ID",
        ),
        "appScopeId": _safe_scalar(
            record.get("appScopeId"),
            field="application scope ID",
        ),
    }
    if (
        normalized["directoryScopeId"] is None
        and normalized["appScopeId"] is None
    ):
        raise SecurityError("Microsoft Graph omitted the role assignment scope")
    if scheduled:
        normalized.update(
            {
                "assignmentType": _safe_scalar(
                    record.get("assignmentType"),
                    field="role assignment type",
                ),
                "memberType": _safe_scalar(
                    record.get("memberType"),
                    field="role member type",
                ),
                "startDateTime": _safe_scalar(
                    record.get("startDateTime"),
                    field="role assignment start time",
                ),
                "endDateTime": _safe_scalar(
                    record.get("endDateTime"),
                    field="role assignment end time",
                ),
            }
        )
    return normalized


def _normalized_record(
    domain: AssuranceDomainName,
    record: dict[str, Any],
) -> dict[str, Any]:
    if domain is AssuranceDomainName.CONDITIONAL_ACCESS:
        return _normalize_conditional_access(record)
    return _normalize_role_assignment(
        record,
        scheduled=domain
        in {
            AssuranceDomainName.ACTIVE_ROLE_ASSIGNMENTS,
            AssuranceDomainName.ELIGIBLE_ROLE_ASSIGNMENTS,
        },
    )


def _record_sort_key(record: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(record.get(field) or "")
        for field in (
            "id",
            "principalId",
            "roleDefinitionId",
            "directoryScopeId",
            "appScopeId",
        )
    )


def _metrics(
    domain: AssuranceDomainName,
    records: list[dict[str, Any]],
) -> dict[str, int]:
    if domain is AssuranceDomainName.CONDITIONAL_ACCESS:
        states = [record["state"] for record in records]
        return {
            "total": len(records),
            "enabled": states.count("enabled"),
            "report_only": states.count(
                "enabledForReportingButNotEnforced"
            ),
            "disabled": states.count("disabled"),
        }
    if domain is AssuranceDomainName.ACTIVE_ROLE_ASSIGNMENTS:
        return {
            "total": len(records),
            "activated": sum(
                record.get("assignmentType") == "Activated"
                for record in records
            ),
            "assigned": sum(
                record.get("assignmentType") == "Assigned"
                for record in records
            ),
        }
    return {"total": len(records)}


class EntraIdentityGovernancePostureService:
    """Collect complete read-only posture, compare signed digests, emit evidence."""

    def __init__(
        self,
        *,
        graph: GraphClient,
        settings: Settings,
        manifest: ContractManifest,
        governance: VerifiedGovernancePolicy,
        snapshots: AssuranceSnapshotStore,
    ) -> None:
        self.graph = graph
        self.settings = settings
        self.manifest = manifest
        self.contract: ContractSpec = manifest.contract(CONTRACT_ID)
        self.governance = governance
        self.snapshots = snapshots

    async def _collect_domain(
        self,
        domain: AssuranceDomainName,
    ) -> tuple[list[dict[str, Any]], int]:
        endpoint, select = DOMAIN_ENDPOINTS[domain]
        data = await self.graph.request_json(
            "GET",
            endpoint,
            params={"$select": select},
        )
        records: list[dict[str, Any]] = []
        pages = 0
        seen_next_links: set[str] = set()
        while True:
            pages += 1
            if pages > self.settings.assurance_max_pages_per_domain:
                raise SecurityError(
                    "Assurance pagination exceeded the signed runtime bound"
                )
            raw_items = data.get("value")
            if not isinstance(raw_items, list):
                raise SecurityError(
                    "Microsoft Graph returned an invalid posture collection"
                )
            for raw_item in raw_items:
                if not isinstance(raw_item, dict):
                    raise SecurityError(
                        "Microsoft Graph returned an invalid posture record"
                    )
                records.append(_normalized_record(domain, raw_item))
                if (
                    len(records)
                    > self.settings.assurance_max_records_per_domain
                ):
                    raise SecurityError(
                        "Assurance collection exceeded the signed runtime bound"
                    )
            next_link = data.get("@odata.nextLink")
            if next_link is None:
                break
            if (
                not isinstance(next_link, str)
                or next_link in seen_next_links
                or pages >= self.settings.assurance_max_pages_per_domain
            ):
                raise SecurityError(
                    "Assurance pagination could not prove a complete snapshot"
                )
            seen_next_links.add(next_link)
            data = await self.graph.request_cursor(next_link)
        records.sort(key=_record_sort_key)
        return records, pages

    def _active_exceptions(
        self,
        baseline: IdentityGovernanceBaseline | None,
        *,
        now: datetime,
    ) -> dict[tuple[AssuranceDomainName, str], AssuranceException]:
        if baseline is None:
            return {}
        return {
            (item.domain, item.control_id): item
            for item in baseline.exceptions
            if item.expires_at > now
        }

    def _finding(
        self,
        *,
        snapshot_id: UUID,
        snapshot_reference: str,
        domain: AssuranceDomainName,
        control_id: str,
        severity: str,
        summary: str,
        operator_action: str,
        alignment: AlignmentStatus,
        baseline_reference: str | None,
        active_exceptions: dict[
            tuple[AssuranceDomainName, str],
            AssuranceException,
        ],
    ) -> Finding:
        exception = active_exceptions.get((domain, control_id))
        if exception is not None:
            alignment = AlignmentStatus.EXCEPTION_APPROVED
            operator_action = (
                "No remediation while the signed exception remains valid; "
                "the Governance owner must review it before expiry."
            )
        return Finding(
            finding_id=f"{control_id}:{snapshot_id}",
            control_id=control_id,
            status=alignment.value,
            severity=severity,
            summary=summary,
            evidence_reference=snapshot_reference,
            alignment=alignment,
            operator_action=operator_action,
            responsible_party=(
                ResponsibleParty.GOVERNANCE_OWNER
                if exception is not None
                else ResponsibleParty.TENANT_ADMIN
            ),
            baseline_reference=baseline_reference,
        )

    def _posture_findings(
        self,
        *,
        snapshot_id: UUID,
        snapshot_reference: str,
        domains: dict[AssuranceDomainName, list[dict[str, Any]]],
        baseline: IdentityGovernanceBaseline | None,
        active_exceptions: dict[
            tuple[AssuranceDomainName, str],
            AssuranceException,
        ],
    ) -> list[Finding]:
        baseline_reference = (
            f"{baseline.baseline_id}:v{baseline.version}"
            if baseline is not None
            else None
        )
        findings: list[Finding] = []
        ca_metrics = _metrics(
            AssuranceDomainName.CONDITIONAL_ACCESS,
            domains[AssuranceDomainName.CONDITIONAL_ACCESS],
        )
        if ca_metrics["total"] == 0:
            findings.append(
                self._finding(
                    snapshot_id=snapshot_id,
                    snapshot_reference=snapshot_reference,
                    domain=AssuranceDomainName.CONDITIONAL_ACCESS,
                    control_id="CA.NO_POLICIES",
                    severity="critical",
                    summary="No Conditional Access policies were observed.",
                    operator_action=(
                        "Have the tenant administrator review the tenant's "
                        "Conditional Access design; this read-only tool will not remediate it."
                    ),
                    alignment=AlignmentStatus.NOT_ALIGNED,
                    baseline_reference=baseline_reference,
                    active_exceptions=active_exceptions,
                )
            )
        elif ca_metrics["enabled"] == 0:
            findings.append(
                self._finding(
                    snapshot_id=snapshot_id,
                    snapshot_reference=snapshot_reference,
                    domain=AssuranceDomainName.CONDITIONAL_ACCESS,
                    control_id="CA.NO_ENABLED_POLICIES",
                    severity="critical",
                    summary="Conditional Access policies exist but none are enabled.",
                    operator_action=(
                        "Have the tenant administrator review policy state; "
                        "no write is available from this Assurance contract."
                    ),
                    alignment=AlignmentStatus.NOT_ALIGNED,
                    baseline_reference=baseline_reference,
                    active_exceptions=active_exceptions,
                )
            )
        if ca_metrics["report_only"] > 0:
            findings.append(
                self._finding(
                    snapshot_id=snapshot_id,
                    snapshot_reference=snapshot_reference,
                    domain=AssuranceDomainName.CONDITIONAL_ACCESS,
                    control_id="CA.REPORT_ONLY_OBSERVED",
                    severity="info",
                    summary="One or more Conditional Access policies are report-only.",
                    operator_action=(
                        "Review report-only evaluation results in Entra before "
                        "considering any separately governed change."
                    ),
                    alignment=AlignmentStatus.NOT_EVALUATED,
                    baseline_reference=baseline_reference,
                    active_exceptions=active_exceptions,
                )
            )
        permanent_count = len(
            domains[AssuranceDomainName.PERMANENT_ROLE_ASSIGNMENTS]
        )
        if permanent_count:
            findings.append(
                self._finding(
                    snapshot_id=snapshot_id,
                    snapshot_reference=snapshot_reference,
                    domain=AssuranceDomainName.PERMANENT_ROLE_ASSIGNMENTS,
                    control_id="ROLE.PERMANENT_ASSIGNMENTS_OBSERVED",
                    severity="info",
                    summary="Permanent directory role assignments were observed.",
                    operator_action=(
                        "Review necessity and PIM eligibility in the tenant; "
                        "presence alone is not classified as non-compliance."
                    ),
                    alignment=AlignmentStatus.NOT_EVALUATED,
                    baseline_reference=baseline_reference,
                    active_exceptions=active_exceptions,
                )
            )
        return findings

    async def collect(self) -> IdentityGovernancePostureReport:
        decision = self.governance.authorize_read(
            self.contract,
            tenant_id=self.settings.tenant_id,
        )
        domains: dict[AssuranceDomainName, list[dict[str, Any]]] = {}
        pages_by_domain: dict[AssuranceDomainName, int] = {}
        for domain in AssuranceDomainName:
            records, pages = await self._collect_domain(domain)
            domains[domain] = records
            pages_by_domain[domain] = pages

        refreshed = self.governance.refresh()
        refreshed_decision = refreshed.authorize_read(
            self.contract,
            tenant_id=self.settings.tenant_id,
        )
        if refreshed_decision != decision:
            raise GovernancePolicyError(
                "governance authorization changed during posture collection",
                reason_code="POLICY_CHANGED",
            )

        snapshot_id = uuid4()
        snapshot_reference = self.snapshots.store(
            snapshot_id=snapshot_id,
            contract_id=CONTRACT_ID,
            tenant_id=self.settings.tenant_id,
            domains=domains,
        )
        captured_at = datetime.now(UTC)
        baseline = refreshed.policy.identity_governance_baseline
        now = datetime.now(UTC)
        active_exceptions = self._active_exceptions(baseline, now=now)

        domain_results: list[DomainPosture] = []
        drift_findings: list[Finding] = []
        baseline_reference = (
            f"{baseline.baseline_id}:v{baseline.version}"
            if baseline is not None
            else None
        )
        for domain in AssuranceDomainName:
            records = domains[domain]
            digest = self.snapshots.domain_digest(
                tenant_id=self.settings.tenant_id,
                contract_id=CONTRACT_ID,
                domain=domain,
                records=records,
            )
            expectation = (
                baseline.domains[domain]
                if baseline is not None
                else None
            )
            if expectation is None:
                alignment = AlignmentStatus.NOT_EVALUATED
                severity = None
            elif expectation.expected_digest == digest:
                alignment = AlignmentStatus.ALIGNED
                severity = expectation.drift_severity
            else:
                alignment = AlignmentStatus.NOT_ALIGNED
                severity = expectation.drift_severity
                control_id = f"DRIFT.{domain.value.upper()}"
                drift_findings.append(
                    self._finding(
                        snapshot_id=snapshot_id,
                        snapshot_reference=snapshot_reference,
                        domain=domain,
                        control_id=control_id,
                        severity=expectation.drift_severity.value,
                        summary=(
                            f"The complete {domain.value} snapshot differs "
                            "from the signed tenant baseline."
                        ),
                        operator_action=(
                            "Review the encrypted tenant-local snapshot and "
                            "either investigate the drift or sign a new baseline."
                        ),
                        alignment=alignment,
                        baseline_reference=baseline_reference,
                        active_exceptions=active_exceptions,
                    )
                )
                if drift_findings[-1].alignment is AlignmentStatus.EXCEPTION_APPROVED:
                    alignment = AlignmentStatus.EXCEPTION_APPROVED
            domain_results.append(
                DomainPosture(
                    domain=domain,
                    digest=digest,
                    item_count=len(records),
                    pages_read=pages_by_domain[domain],
                    metrics=_metrics(domain, records),
                    alignment=alignment,
                    drift_severity=severity,
                )
            )

        findings = self._posture_findings(
            snapshot_id=snapshot_id,
            snapshot_reference=snapshot_reference,
            domains=domains,
            baseline=baseline,
            active_exceptions=active_exceptions,
        )
        findings.extend(drift_findings)
        if baseline is None:
            findings.append(
                Finding(
                    finding_id=f"ASSURANCE.BASELINE.NOT_CONFIGURED:{snapshot_id}",
                    control_id="ASSURANCE.BASELINE.NOT_CONFIGURED",
                    status=AlignmentStatus.NOT_EVALUATED.value,
                    severity="info",
                    summary=(
                        "No signed Identity Governance baseline is configured."
                    ),
                    evidence_reference=snapshot_reference,
                    alignment=AlignmentStatus.NOT_EVALUATED,
                    operator_action=(
                        "Copy the four returned domain digests into the private "
                        "Governance policy, review it, and sign a new policy version."
                    ),
                    responsible_party=ResponsibleParty.GOVERNANCE_OWNER,
                )
            )
        findings.sort(
            key=lambda item: (
                SEVERITY_ORDER[item.severity],
                item.control_id,
            )
        )

        active_profile: Literal["routine-read", "privileged-read"] = (
            "routine-read"
            if refreshed_decision.profile.value == "routine-read"
            else "privileged-read"
        )
        return IdentityGovernancePostureReport(
            contract_digest=sha256_digest(self.contract),
            contract_manifest_digest=sha256_digest(self.manifest),
            policy_digest=refreshed.policy_digest,
            active_profile=active_profile,
            snapshot_id=snapshot_id,
            snapshot_reference=snapshot_reference,
            captured_at=captured_at,
            tenant_namespace=self.settings.deployment_namespace,
            baseline=BaselineSummary(
                configured=baseline is not None,
                baseline_id=baseline.baseline_id if baseline else None,
                version=baseline.version if baseline else None,
                captured_at=baseline.captured_at if baseline else None,
            ),
            domains=domain_results,
            findings=findings,
        )
