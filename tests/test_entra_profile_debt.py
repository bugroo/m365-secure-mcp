from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from m365_secure_mcp.assurance import AssuranceSnapshotStore
from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    RiskTier,
    load_global_manifest,
)
from m365_secure_mcp.entra_permission_drift import (
    PermissionGrantDriftReport,
    PermissionGrantTargetPosture,
)
from m365_secure_mcp.entra_profile_debt import (
    CONTRACT_ID,
    TOOL_NAME,
    EntraProfileDebtService,
)
from m365_secure_mcp.governance import (
    DriftSeverity,
    GovernancePolicyError,
    GovernanceProfileName,
    PermissionGrantBaseline,
    PermissionGrantTarget,
    ProfileDebtBaseline,
    ProfileDebtControl,
    ProfileDebtException,
    load_verified_governance_policy,
)
from m365_secure_mcp.operations import AlignmentStatus
from m365_secure_mcp.security import AuditLogger

from .conftest import CLIENT_ID, TENANT_ID, USER_ID
from .governance_helpers import write_signed_governance

SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"
PRIVILEGED_CONTRACTS = [
    "entra.app_credentials.posture.snapshot",
    "entra.conditional_access.policies.read",
    "entra.identity_governance.posture.snapshot",
    "entra.permission_grants.drift.snapshot",
    "entra.profile_debt.posture.snapshot",
    "entra.role_assignments.read",
]


class FakeScopeSource:
    def __init__(self, scopes: frozenset[str]) -> None:
        self.scopes = scopes

    async def delegated_scope_claims(self) -> frozenset[str]:
        return self.scopes


class FakePermissionDrift:
    def __init__(
        self,
        *,
        settings: Settings,
        snapshots: AssuranceSnapshotStore,
        include_current_app: bool = True,
        contract_ids: list[str] | None = None,
    ) -> None:
        self.settings = settings
        self.snapshots = snapshots
        self.include_current_app = include_current_app
        self.contract_ids = contract_ids or PRIVILEGED_CONTRACTS

    async def collect(self) -> PermissionGrantDriftReport:
        application_id = (
            CLIENT_ID
            if self.include_current_app
            else "66666666-6666-4666-8666-666666666666"
        )
        target_reference = self.snapshots.resource_reference(
            tenant_id=TENANT_ID,
            category="sp",
            resource_id=SERVICE_PRINCIPAL_ID,
        )
        workload_reference = self.snapshots.resource_reference(
            tenant_id=TENANT_ID,
            category="wi",
            resource_id=application_id,
        )
        return PermissionGrantDriftReport(
            contract_digest="sha256:" + ("1" * 64),
            contract_manifest_digest="sha256:" + ("2" * 64),
            policy_digest="sha256:" + ("3" * 64),
            snapshot_id=uuid4(),
            snapshot_reference=f"snapshot:{uuid4()}",
            captured_at=datetime.now(UTC),
            tenant_namespace=self.settings.deployment_namespace,
            baseline_id="profile-permissions",
            baseline_version=1,
            targets=[
                PermissionGrantTargetPosture(
                    target_reference=target_reference,
                    workload_identity_reference=workload_reference,
                    baseline_reference="profile-permissions:v1",
                    contract_ids=self.contract_ids,
                    digest="hmac-sha256:" + ("4" * 64),
                    alignment=AlignmentStatus.ALIGNED,
                    expected_delegated_permissions=5,
                    observed_delegated_permissions=5,
                    observed_application_permissions=0,
                    missing_permissions=0,
                    unexpected_permissions=0,
                    approved_exceptions=0,
                )
            ],
            findings=[],
        )


def _profile_baseline(
    *,
    minimum_policy_version: int = 2,
) -> ProfileDebtBaseline:
    return ProfileDebtBaseline(
        baseline_id="msp-profile-debt",
        version=1,
        minimum_policy_version=minimum_policy_version,
        maximum_policy_age_days=30,
        evidence_window_days=7,
        persistent_failure_threshold=3,
        severities={
            control: DriftSeverity.MEDIUM
            for control in ProfileDebtControl
        },
    )


def _permission_baseline() -> PermissionGrantBaseline:
    return PermissionGrantBaseline(
        baseline_id="profile-permissions",
        version=1,
        targets=[
            PermissionGrantTarget(
                service_principal_id=UUID(SERVICE_PRINCIPAL_ID),
                contract_ids=PRIVILEGED_CONTRACTS,
            )
        ],
    )


def _service(
    tmp_path: Path,
    *,
    scopes: frozenset[str] | None = None,
    include_current_app: bool = True,
    write_audit: bool = True,
    minimum_policy_version: int = 2,
    profile_baseline: ProfileDebtBaseline | None = None,
) -> tuple[EntraProfileDebtService, Settings]:
    policy_path, verifier_path = write_signed_governance(
        tmp_path / "policy",
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        active_profile=GovernanceProfileName.PRIVILEGED_READ,
        permission_grant_baseline=_permission_baseline(),
        service_principal_id=SERVICE_PRINCIPAL_ID,
        profile_debt_baseline=profile_baseline
        or _profile_baseline(
            minimum_policy_version=minimum_policy_version
        ),
        enable_profile_debt=True,
        policy_version=2,
    )
    settings = Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        modules="profile,assurance",
        privileged_modules_enabled=True,
        enabled_tools=f"{TOOL_NAME},m365_get_entra_permission_grant_drift",
        allowed_user_object_ids=USER_ID,
        allowed_target_user_ids=USER_ID,
        allowed_upn_domains="example.com",
        allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
        governance_policy_path=policy_path,
        governance_public_key_path=verifier_path,
        assurance_snapshot_path=tmp_path / "runtime" / "assurance.jsonl",
        audit_log_path=tmp_path / "runtime" / "audit.jsonl",
    )
    snapshots = AssuranceSnapshotStore(settings)
    if write_audit:
        audit = AuditLogger(
            settings.effective_audit_log_path,
            deployment_namespace=settings.deployment_namespace,
        )
        manifest = load_global_manifest()
        for contract_id in PRIVILEGED_CONTRACTS:
            if contract_id == CONTRACT_ID:
                continue
            audit.record(
                tool=manifest.contract(contract_id).tool_name,
                outcome="success",
            )
    expected_scopes = scopes or frozenset(
        {
            "Application.Read.All",
            "Directory.Read.All",
            "Policy.Read.All",
            "RoleManagement.Read.Directory",
            "User.Read",
        }
    )
    return (
        EntraProfileDebtService(
            scope_source=FakeScopeSource(expected_scopes),
            settings=settings,
            manifest=load_global_manifest(),
            governance=load_verified_governance_policy(
                policy_path,
                verifier_path,
            ),
            snapshots=snapshots,
            permission_drift=FakePermissionDrift(
                settings=settings,
                snapshots=snapshots,
                include_current_app=include_current_app,
            ),  # type: ignore[arg-type]
        ),
        settings,
    )


def test_profile_debt_contract_is_fixed_t0_and_read_only() -> None:
    contract = load_global_manifest().contract(CONTRACT_ID)

    assert contract.tool_name == TOOL_NAME
    assert contract.graph.method == "GET"
    assert contract.graph.endpoint == "/oauth2PermissionGrants"
    assert contract.input_schema["properties"] == {}
    assert contract.permissions.delegated_scopes == ["Directory.Read.All"]
    assert contract.risk_tier is RiskTier.T0
    assert contract.authorization_mode is AuthorizationMode.AUTOMATIC_READ
    assert "no_consent_or_policy_change" in contract.postconditions
    assert "no_automatic_remediation" in contract.postconditions


@pytest.mark.asyncio
async def test_profile_debt_aligned_report_is_complete_and_private(
    tmp_path: Path,
) -> None:
    service, settings = _service(tmp_path)

    report = await service.collect()

    assert report.status == "OBSERVED_COMPLETE"
    assert set(report.coverage_status.values()) == {"complete"}
    assert report.scope_posture.alignment is AlignmentStatus.ALIGNED
    assert report.scope_posture.missing_token_scopes == []
    assert report.scope_posture.unexpected_token_scopes == []
    assert report.findings == []
    assert report.writes_performed is False
    assert report.consent_changes_performed is False
    assert report.policy_changes_performed is False
    assert report.admin_consent_is_manual is True
    assert all(
        item.alignment
        in {AlignmentStatus.ALIGNED, AlignmentStatus.NOT_APPLICABLE}
        for item in report.resource_posture
    )

    public_result = report.model_dump_json()
    for private_value in (
        TENANT_ID,
        CLIENT_ID,
        SERVICE_PRINCIPAL_ID,
        USER_ID,
    ):
        assert private_value not in public_result
    snapshot_payload = settings.effective_assurance_snapshot_path.read_text()
    assert '"ciphertext":' in snapshot_payload
    assert SERVICE_PRINCIPAL_ID not in snapshot_payload
    assert USER_ID not in snapshot_payload
    assert (
        stat.S_IMODE(
            settings.effective_assurance_snapshot_path.stat().st_mode
        )
        == 0o600
    )


@pytest.mark.asyncio
async def test_missing_current_app_never_claims_complete_grant_coverage(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path, include_current_app=False)

    report = await service.collect()

    assert report.status == "OBSERVED_PARTIAL"
    assert report.coverage_status["permission_grants"] == "not_evaluated"
    assert report.scope_posture.grant_alignment is AlignmentStatus.NOT_EVALUATED
    finding = next(
        item
        for item in report.findings
        if item.control_id == "PROFILE_CURRENT_APP_BASELINE_MISSING"
    )
    assert finding.alignment is AlignmentStatus.NOT_EVALUATED
    assert finding.responsible_party.value == "GOVERNANCE_OWNER"


@pytest.mark.asyncio
async def test_missing_audit_is_partial_and_token_debt_is_explicit(
    tmp_path: Path,
) -> None:
    service, _ = _service(
        tmp_path,
        scopes=frozenset(
            {
                "Application.Read.All",
                "Directory.Read.All",
                "Policy.Read.All",
                "User.Read",
                "Mail.Read",
            }
        ),
        write_audit=False,
    )

    report = await service.collect()

    assert report.status == "OBSERVED_PARTIAL"
    assert report.coverage_status["audit_evidence"] == "not_evaluated"
    assert report.scope_posture.missing_token_scopes == [
        "RoleManagement.Read.Directory"
    ]
    assert report.scope_posture.unexpected_token_scopes == ["Mail.Read"]
    controls = {item.control_id for item in report.findings}
    assert "PROFILE_TOKEN_SCOPE_MISSING" in controls
    assert "PROFILE_TOKEN_SCOPE_UNEXPECTED" in controls
    assert "PROFILE_CONTRACT_NO_RECENT_EVIDENCE" in controls


@pytest.mark.asyncio
async def test_exact_signed_scope_exception_is_visible(
    tmp_path: Path,
) -> None:
    baseline = _profile_baseline()
    baseline = baseline.model_copy(
        update={
            "exceptions": [
                ProfileDebtException(
                    exception_id="mail-read-temporary",
                    control_id=(
                        ProfileDebtControl.TOKEN_SCOPE_UNEXPECTED
                    ),
                    subject="Mail.Read",
                    rationale="Temporary migration dependency.",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                )
            ]
        }
    )
    service, _ = _service(
        tmp_path,
        scopes=frozenset(
            {
                "Application.Read.All",
                "Directory.Read.All",
                "Policy.Read.All",
                "RoleManagement.Read.Directory",
                "User.Read",
                "Mail.Read",
            }
        ),
        profile_baseline=baseline,
    )

    report = await service.collect()

    finding = next(
        item
        for item in report.findings
        if item.control_id == "PROFILE_TOKEN_SCOPE_UNEXPECTED"
    )
    assert finding.alignment is AlignmentStatus.EXCEPTION_APPROVED
    assert report.scope_posture.alignment is AlignmentStatus.EXCEPTION_APPROVED


def test_profile_debt_baseline_requires_customer_severity_for_every_control() -> None:
    document = _profile_baseline().model_dump(mode="json")
    document["severities"].pop("PROFILE_TOKEN_SCOPE_UNEXPECTED")

    with pytest.raises(ValueError, match="every control"):
        ProfileDebtBaseline.model_validate(document)


def test_profile_debt_contract_requires_both_signed_baselines(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        GovernancePolicyError,
        match="both signed customer baselines",
    ):
        write_signed_governance(
            tmp_path,
            tenant_id=TENANT_ID,
            user_id=USER_ID,
            active_profile=GovernanceProfileName.PRIVILEGED_READ,
            service_principal_id=SERVICE_PRINCIPAL_ID,
            enable_profile_debt=True,
        )


def test_profile_debt_policy_version_is_signed_policy_material(
    tmp_path: Path,
) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        policy_version=2,
    )
    document = json.loads(policy_path.read_text())
    document["policy"]["policy_version"] = 3
    policy_path.write_text(json.dumps(document))
    policy_path.chmod(0o600)

    with pytest.raises(Exception, match="digest mismatch"):
        load_verified_governance_policy(policy_path, verifier_path)


def test_profile_debt_exception_must_expire_and_select_exact_subject() -> None:
    baseline = _profile_baseline()
    document = baseline.model_dump(mode="json")
    document["exceptions"] = [
        {
            "exception_id": "mail-read-temporary",
            "control_id": "PROFILE_TOKEN_SCOPE_UNEXPECTED",
            "subject": "Mail.Read",
            "rationale": "Temporary migration dependency.",
            "expires_at": (
                datetime.now(UTC) + timedelta(days=1)
            ).isoformat(),
        }
    ]

    parsed = ProfileDebtBaseline.model_validate(document)

    assert parsed.exceptions[0].subject == "Mail.Read"
