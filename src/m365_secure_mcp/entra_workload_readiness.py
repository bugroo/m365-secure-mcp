"""Signed T0 playbook for Entra workload-identity readiness."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .assurance import AssuranceSnapshotStore
from .config import Settings
from .contract_manifest import ContractManifest, sha256_digest
from .entra_app_credentials import (
    CONTRACT_ID as APPLICATION_CREDENTIAL_CONTRACT_ID,
)
from .entra_app_credentials import (
    ApplicationCredentialPostureReport,
    EntraApplicationCredentialPostureService,
)
from .entra_permission_drift import (
    CONTRACT_ID as PERMISSION_DRIFT_CONTRACT_ID,
)
from .entra_permission_drift import (
    EntraPermissionGrantDriftService,
    PermissionGrantDriftReport,
)
from .governance import GovernancePolicyError, VerifiedGovernancePolicy
from .graph import GraphError
from .operations import (
    AlignmentStatus,
    Finding,
    PlaybookStatus,
    ResponsibleParty,
)
from .playbook_manifest import PlaybookManifest, PlaybookSpec
from .security import SecurityError

PLAYBOOK_ID = "entra.workload_identity.readiness.playbook"
TOOL_NAME = "m365_get_entra_workload_identity_readiness"
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PlaybookNodeResult(StrictModel):
    node_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    status: Literal["COMPLETED_VERIFIED", "NOT_EVALUATED"]
    evidence_reference: str | None = Field(default=None, max_length=128)
    reason_code: str | None = Field(default=None, max_length=128)
    finding_count: int = Field(default=0, ge=0, le=10_000)
    target_count: int = Field(default=0, ge=0, le=100)


class WorkloadIdentityTargetReadiness(StrictModel):
    workload_identity_reference: str = Field(pattern=r"^wi:[0-9a-f]{24}$")
    service_principal_reference: str | None = Field(
        default=None,
        pattern=r"^sp:[0-9a-f]{24}$",
    )
    application_reference: str | None = Field(
        default=None,
        pattern=r"^app:[0-9a-f]{24}$",
    )
    alignment: AlignmentStatus
    permission_alignment: AlignmentStatus
    credential_alignment: AlignmentStatus
    expected_delegated_permissions: int = Field(ge=0)
    observed_delegated_permissions: int = Field(ge=0)
    observed_application_permissions: int = Field(ge=0)
    missing_permissions: int = Field(ge=0)
    unexpected_permissions: int = Field(ge=0)
    owner_count: int | None = Field(default=None, ge=0, le=100)
    expiring_credentials: int | None = Field(default=None, ge=0, le=200)
    expired_credentials: int | None = Field(default=None, ge=0, le=200)
    approved_exceptions: int = Field(ge=0, le=1_000)


class WorkloadIdentityReadinessReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    status: PlaybookStatus
    playbook_id: Literal["entra.workload_identity.readiness.playbook"] = (
        "entra.workload_identity.readiness.playbook"
    )
    playbook_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_mode: Literal["automatic_read"] = "automatic_read"
    authorization_basis: Literal["signed_policy"] = "signed_policy"
    active_profile: Literal["privileged-read"] = "privileged-read"
    run_id: UUID
    captured_at: datetime
    tenant_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")
    coverage_status: Literal[
        "complete_for_signed_targets",
        "not_evaluated",
    ]
    nodes: list[PlaybookNodeResult] = Field(min_length=1, max_length=20)
    targets: list[WorkloadIdentityTargetReadiness] = Field(
        default_factory=list,
        max_length=100,
    )
    findings: list[Finding] = Field(default_factory=list, max_length=10_000)
    operator_action: str = Field(min_length=3, max_length=500)
    writes_performed: Literal[False] = False
    admin_consent_is_manual: Literal[True] = True


NodeReport = PermissionGrantDriftReport | ApplicationCredentialPostureReport
NodeHandler = Callable[[], Awaitable[NodeReport]]


def _combined_alignment(
    permission: AlignmentStatus,
    credential: AlignmentStatus,
) -> AlignmentStatus:
    values = {permission, credential}
    if AlignmentStatus.NOT_EVALUATED in values:
        return AlignmentStatus.NOT_EVALUATED
    if AlignmentStatus.NOT_ALIGNED in values:
        return AlignmentStatus.NOT_ALIGNED
    if AlignmentStatus.EXCEPTION_APPROVED in values:
        return AlignmentStatus.EXCEPTION_APPROVED
    if values == {AlignmentStatus.ALIGNED}:
        return AlignmentStatus.ALIGNED
    return AlignmentStatus.NOT_EVALUATED


class EntraWorkloadIdentityReadinessService:
    """Execute one fixed read-only DAG and correlate only opaque evidence."""

    def __init__(
        self,
        *,
        settings: Settings,
        contract_manifest: ContractManifest,
        playbook_manifest: PlaybookManifest,
        governance: VerifiedGovernancePolicy,
        snapshots: AssuranceSnapshotStore,
        permission_drift: EntraPermissionGrantDriftService,
        application_credentials: EntraApplicationCredentialPostureService,
    ) -> None:
        self.settings = settings
        self.contract_manifest = contract_manifest
        self.playbook_manifest = playbook_manifest
        self.playbook: PlaybookSpec = playbook_manifest.playbook(PLAYBOOK_ID)
        self.governance = governance
        self.snapshots = snapshots
        self._handlers: dict[str, NodeHandler] = {
            PERMISSION_DRIFT_CONTRACT_ID: permission_drift.collect,
            APPLICATION_CREDENTIAL_CONTRACT_ID: application_credentials.collect,
        }
        node_contracts = {node.contract_id for node in self.playbook.nodes}
        if node_contracts != set(self._handlers):
            raise RuntimeError(
                "workload readiness playbook has an unsupported contract closure"
            )

    def _playbook_finding(
        self,
        *,
        run_reference: str,
        workload_reference: str,
        control_id: str,
        severity: Literal["info", "low", "medium", "high", "critical"],
        summary: str,
        operator_action: str,
        responsible_party: ResponsibleParty,
        alignment: AlignmentStatus,
    ) -> Finding:
        finding_id = self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="finding",
            resource_id=(
                f"{PLAYBOOK_ID}:{workload_reference}:{control_id}"
            ),
        )
        return Finding(
            finding_id=finding_id,
            control_id=control_id,
            status=alignment.value,
            severity=severity,
            summary=summary,
            evidence_reference=run_reference,
            alignment=alignment,
            operator_action=operator_action,
            responsible_party=responsible_party,
        )

    def _halted_report(
        self,
        *,
        run_id: UUID,
        decision_policy_digest: str,
        completed: list[PlaybookNodeResult],
        failed_node_id: str,
        failed_contract_id: str,
        reason_code: str,
        remaining_nodes: list[tuple[str, str]],
    ) -> WorkloadIdentityReadinessReport:
        run_reference = f"playbook:{run_id}"
        failed_contract = self.contract_manifest.contract(failed_contract_id)
        nodes = [
            *completed,
            PlaybookNodeResult(
                node_id=failed_node_id,
                contract_id=failed_contract_id,
                contract_digest=sha256_digest(failed_contract),
                status="NOT_EVALUATED",
                reason_code=reason_code,
            ),
        ]
        findings = [
            self._playbook_finding(
                run_reference=run_reference,
                workload_reference=failed_node_id,
                control_id="PLAYBOOK_NODE_NOT_EVALUATED",
                severity="high",
                summary=(
                    f"Playbook node {failed_node_id} could not establish "
                    "complete evidence."
                ),
                operator_action=(
                    "Resolve the reported policy, scope, fence, or evidence "
                    "failure and run a new read-only playbook."
                ),
                responsible_party=(
                    ResponsibleParty.GOVERNANCE_OWNER
                    if reason_code.startswith(("POLICY_", "DENIED_", "BASELINE_"))
                    else ResponsibleParty.OPERATOR
                ),
                alignment=AlignmentStatus.NOT_EVALUATED,
            )
        ]
        for node_id, contract_id in remaining_nodes:
            nodes.append(
                PlaybookNodeResult(
                    node_id=node_id,
                    contract_id=contract_id,
                    contract_digest=sha256_digest(
                        self.contract_manifest.contract(contract_id)
                    ),
                    status="NOT_EVALUATED",
                    reason_code="UPSTREAM_NODE_HALTED",
                )
            )
            findings.append(
                self._playbook_finding(
                    run_reference=run_reference,
                    workload_reference=node_id,
                    control_id="PLAYBOOK_NODE_NOT_EVALUATED",
                    severity="medium",
                    summary=(
                        f"Playbook node {node_id} was not run after an "
                        "earlier node halted."
                    ),
                    operator_action=(
                        "Do not infer alignment from missing evidence; rerun "
                        "only after the failed prerequisite is resolved."
                    ),
                    responsible_party=ResponsibleParty.OPERATOR,
                    alignment=AlignmentStatus.NOT_EVALUATED,
                )
            )
        return WorkloadIdentityReadinessReport(
            status=PlaybookStatus.PLAYBOOK_HALTED,
            playbook_digest=sha256_digest(self.playbook),
            playbook_manifest_digest=sha256_digest(self.playbook_manifest),
            contract_manifest_digest=sha256_digest(self.contract_manifest),
            policy_digest=decision_policy_digest,
            run_id=run_id,
            captured_at=datetime.now(UTC),
            tenant_namespace=self.settings.deployment_namespace,
            coverage_status="not_evaluated",
            nodes=nodes,
            findings=findings,
            operator_action=(
                "Resolve the named failure and start a new playbook run; "
                "this result is not complete posture evidence."
            ),
        )

    def _correlate(
        self,
        *,
        run_reference: str,
        permission_report: PermissionGrantDriftReport,
        credential_report: ApplicationCredentialPostureReport,
    ) -> tuple[list[WorkloadIdentityTargetReadiness], list[Finding]]:
        permissions = {
            target.workload_identity_reference: target
            for target in permission_report.targets
        }
        credentials = {
            target.workload_identity_reference: target
            for target in credential_report.targets
        }
        if len(permissions) != len(permission_report.targets):
            raise SecurityError(
                "permission evidence contains duplicate workload identities"
            )
        if len(credentials) != len(credential_report.targets):
            raise SecurityError(
                "credential evidence contains duplicate workload identities"
            )

        findings = [
            *permission_report.findings,
            *credential_report.findings,
        ]
        targets: list[WorkloadIdentityTargetReadiness] = []
        for reference in sorted(set(permissions) | set(credentials)):
            permission = permissions.get(reference)
            credential = credentials.get(reference)
            permission_alignment = (
                permission.alignment
                if permission is not None
                else AlignmentStatus.NOT_EVALUATED
            )
            credential_alignment = (
                credential.alignment
                if credential is not None
                else AlignmentStatus.NOT_EVALUATED
            )
            alignment = _combined_alignment(
                permission_alignment,
                credential_alignment,
            )
            if permission is None or credential is None:
                findings.append(
                    self._playbook_finding(
                        run_reference=run_reference,
                        workload_reference=reference,
                        control_id="WORKLOAD_IDENTITY_MAPPING_INCOMPLETE",
                        severity="high",
                        summary=(
                            f"{reference}: signed application and service-"
                            "principal evidence could not be correlated."
                        ),
                        operator_action=(
                            "Add the matching application object and service "
                            "principal to both private signed baselines, then rerun."
                        ),
                        responsible_party=ResponsibleParty.GOVERNANCE_OWNER,
                        alignment=AlignmentStatus.NOT_EVALUATED,
                    )
                )
            elif (
                permission.alignment is AlignmentStatus.NOT_ALIGNED
                and credential.alignment is AlignmentStatus.NOT_ALIGNED
            ):
                findings.append(
                    self._playbook_finding(
                        run_reference=run_reference,
                        workload_reference=reference,
                        control_id="WORKLOAD_IDENTITY_COMBINED_RISK",
                        severity="critical",
                        summary=(
                            f"{reference}: permission and credential/ownership "
                            "controls are simultaneously not aligned."
                        ),
                        operator_action=(
                            "Prioritize a tenant-admin review of this workload "
                            "identity; no remediation was performed."
                        ),
                        responsible_party=ResponsibleParty.TENANT_ADMIN,
                        alignment=AlignmentStatus.NOT_ALIGNED,
                    )
                )

            targets.append(
                WorkloadIdentityTargetReadiness(
                    workload_identity_reference=reference,
                    service_principal_reference=(
                        permission.target_reference
                        if permission is not None
                        else None
                    ),
                    application_reference=(
                        credential.target_reference
                        if credential is not None
                        else None
                    ),
                    alignment=alignment,
                    permission_alignment=permission_alignment,
                    credential_alignment=credential_alignment,
                    expected_delegated_permissions=(
                        permission.expected_delegated_permissions
                        if permission is not None
                        else 0
                    ),
                    observed_delegated_permissions=(
                        permission.observed_delegated_permissions
                        if permission is not None
                        else 0
                    ),
                    observed_application_permissions=(
                        permission.observed_application_permissions
                        if permission is not None
                        else 0
                    ),
                    missing_permissions=(
                        permission.missing_permissions
                        if permission is not None
                        else 0
                    ),
                    unexpected_permissions=(
                        permission.unexpected_permissions
                        if permission is not None
                        else 0
                    ),
                    owner_count=(
                        credential.owner_count
                        if credential is not None
                        else None
                    ),
                    expiring_credentials=(
                        credential.expiring_credentials
                        if credential is not None
                        else None
                    ),
                    expired_credentials=(
                        credential.expired_credentials
                        if credential is not None
                        else None
                    ),
                    approved_exceptions=(
                        (
                            permission.approved_exceptions
                            if permission is not None
                            else 0
                        )
                        + (
                            credential.approved_exceptions
                            if credential is not None
                            else 0
                        )
                    ),
                )
            )
        findings.sort(
            key=lambda item: (
                SEVERITY_ORDER[item.severity],
                item.control_id,
                item.finding_id,
            )
        )
        return targets, findings

    async def collect(self) -> WorkloadIdentityReadinessReport:
        decision = self.governance.authorize_playbook_read(
            self.playbook,
            contract_manifest=self.contract_manifest,
            tenant_id=self.settings.tenant_id,
        )
        run_id = uuid4()
        run_reference = f"playbook:{run_id}"
        node_results: list[PlaybookNodeResult] = []
        reports: dict[str, NodeReport] = {}
        ordered = self.playbook.ordered_nodes()
        for index, node in enumerate(ordered):
            try:
                report = await self._handlers[node.contract_id]()
            except GovernancePolicyError as exc:
                return self._halted_report(
                    run_id=run_id,
                    decision_policy_digest=decision.policy_digest,
                    completed=node_results,
                    failed_node_id=node.id,
                    failed_contract_id=node.contract_id,
                    reason_code=exc.reason_code,
                    remaining_nodes=[
                        (item.id, item.contract_id)
                        for item in ordered[index + 1 :]
                    ],
                )
            except (GraphError, SecurityError):
                return self._halted_report(
                    run_id=run_id,
                    decision_policy_digest=decision.policy_digest,
                    completed=node_results,
                    failed_node_id=node.id,
                    failed_contract_id=node.contract_id,
                    reason_code="EVIDENCE_VALIDATION_FAILED",
                    remaining_nodes=[
                        (item.id, item.contract_id)
                        for item in ordered[index + 1 :]
                    ],
                )
            reports[node.contract_id] = report
            node_results.append(
                PlaybookNodeResult(
                    node_id=node.id,
                    contract_id=node.contract_id,
                    contract_digest=report.contract_digest,
                    status="COMPLETED_VERIFIED",
                    evidence_reference=report.snapshot_reference,
                    finding_count=len(report.findings),
                    target_count=len(report.targets),
                )
            )

        try:
            refreshed = self.governance.refresh()
            refreshed_decision = refreshed.authorize_playbook_read(
                self.playbook,
                contract_manifest=self.contract_manifest,
                tenant_id=self.settings.tenant_id,
            )
            if refreshed_decision != decision:
                raise GovernancePolicyError(
                    "governance authorization changed during the playbook",
                    reason_code="POLICY_CHANGED",
                )
        except GovernancePolicyError as exc:
            final_node = ordered[-1]
            completed_before_final = node_results[:-1]
            return self._halted_report(
                run_id=run_id,
                decision_policy_digest=decision.policy_digest,
                completed=completed_before_final,
                failed_node_id=final_node.id,
                failed_contract_id=final_node.contract_id,
                reason_code=exc.reason_code,
                remaining_nodes=[],
            )

        permission_report = reports[PERMISSION_DRIFT_CONTRACT_ID]
        credential_report = reports[APPLICATION_CREDENTIAL_CONTRACT_ID]
        if not isinstance(permission_report, PermissionGrantDriftReport):
            raise RuntimeError("permission node returned an invalid report")
        if not isinstance(
            credential_report,
            ApplicationCredentialPostureReport,
        ):
            raise RuntimeError("credential node returned an invalid report")
        targets, findings = self._correlate(
            run_reference=run_reference,
            permission_report=permission_report,
            credential_report=credential_report,
        )
        return WorkloadIdentityReadinessReport(
            status=PlaybookStatus.PLAYBOOK_COMPLETED_VERIFIED,
            playbook_digest=sha256_digest(self.playbook),
            playbook_manifest_digest=sha256_digest(self.playbook_manifest),
            contract_manifest_digest=sha256_digest(self.contract_manifest),
            policy_digest=refreshed.policy_digest,
            run_id=run_id,
            captured_at=datetime.now(UTC),
            tenant_namespace=self.settings.deployment_namespace,
            coverage_status="complete_for_signed_targets",
            nodes=node_results,
            targets=targets,
            findings=findings,
            operator_action=(
                "Review non-aligned findings; any change must use a separate "
                "governed write contract."
                if findings
                else "Retain this evidence and continue scheduled posture review."
            ),
        )
