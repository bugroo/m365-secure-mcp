from __future__ import annotations

import json
import stat
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from m365_secure_mcp.assurance import AssuranceSnapshotStore
from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_manifest import load_global_manifest
from m365_secure_mcp.entra_posture import (
    ACTIVE_ROLE_ENDPOINT,
    CONDITIONAL_ACCESS_ENDPOINT,
    CONTRACT_ID,
    ELIGIBLE_ROLE_ENDPOINT,
    PERMANENT_ROLE_ENDPOINT,
    EntraIdentityGovernancePostureService,
)
from m365_secure_mcp.governance import (
    AssuranceDomainBaseline,
    AssuranceDomainName,
    AssuranceException,
    DriftSeverity,
    GovernancePolicyError,
    GovernanceProfileName,
    IdentityGovernanceBaseline,
    load_verified_governance_policy,
)
from m365_secure_mcp.operations import AlignmentStatus
from m365_secure_mcp.security import PrivateStateError, SecurityError

from .conftest import CLIENT_ID, TENANT_ID, USER_ID
from .governance_helpers import write_signed_governance

TARGET_ID = "77777777-7777-4777-8777-777777777777"
CA_POLICY_ID = "88888888-8888-4888-8888-888888888888"
CA_GROUP_ID = "99999999-9999-4999-8999-999999999999"
ROLE_ASSIGNMENT_ID = "role-assignment-private-id"
ROLE_PRINCIPAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ROLE_DEFINITION_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def test_posture_handler_endpoints_match_the_signed_contract() -> None:
    contract = load_global_manifest().contract(CONTRACT_ID)
    assert contract.graph.endpoint == CONDITIONAL_ACCESS_ENDPOINT
    assert {
        call.endpoint for call in contract.preflight_graph_calls
    } == {
        PERMANENT_ROLE_ENDPOINT,
        ACTIVE_ROLE_ENDPOINT,
        ELIGIBLE_ROLE_ENDPOINT,
    }


class FakePostureGraph:
    def __init__(
        self,
        *,
        ca_state: str = "enabled",
        paginate_ca: bool = False,
    ) -> None:
        self.ca_state = ca_state
        self.paginate_ca = paginate_ca
        self.calls: list[tuple[str, str]] = []

    def _ca_page(self, *, final: bool) -> dict[str, Any]:
        record = {
            "id": (
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                if final
                else CA_POLICY_ID
            ),
            "state": (
                "enabledForReportingButNotEnforced"
                if final
                else self.ca_state
            ),
            "conditions": {
                "users": {
                    "includeUsers": ["All"],
                    "excludeGroups": [CA_GROUP_ID],
                },
                "clientAppTypes": ["all"],
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"],
            },
            "sessionControls": None,
        }
        result: dict[str, Any] = {"value": [record]}
        if self.paginate_ca and not final:
            result["@odata.nextLink"] = (
                "https://graph.microsoft.com/v1.0/"
                "identity/conditionalAccess/policies?$skiptoken=opaque"
            )
        return result

    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        del params, json_body, headers
        self.calls.append((method, endpoint))
        assert method == "GET"
        if endpoint == CONDITIONAL_ACCESS_ENDPOINT:
            return self._ca_page(final=False)
        role_record = {
            "id": ROLE_ASSIGNMENT_ID,
            "principalId": ROLE_PRINCIPAL_ID,
            "roleDefinitionId": ROLE_DEFINITION_ID,
            "directoryScopeId": "/",
            "appScopeId": None,
        }
        if endpoint == PERMANENT_ROLE_ENDPOINT:
            return {"value": [role_record]}
        if endpoint == ACTIVE_ROLE_ENDPOINT:
            return {
                "value": [
                    {
                        **role_record,
                        "id": "active-role-private-id",
                        "assignmentType": "Activated",
                        "memberType": "Direct",
                        "startDateTime": "2026-07-26T10:00:00Z",
                        "endDateTime": "2026-07-26T11:00:00Z",
                    }
                ]
            }
        if endpoint == ELIGIBLE_ROLE_ENDPOINT:
            return {
                "value": [
                    {
                        **role_record,
                        "id": "eligible-role-private-id",
                        "memberType": "Direct",
                        "startDateTime": "2026-01-01T00:00:00Z",
                        "endDateTime": None,
                    }
                ]
            }
        raise AssertionError(f"unexpected Graph endpoint: {endpoint}")

    async def request_cursor(self, url: str) -> dict[str, Any]:
        self.calls.append(("GET_CURSOR", url))
        assert "$skiptoken=opaque" in url
        return self._ca_page(final=True)


def _settings(
    tmp_path: Path,
    *,
    policy_path: Path,
    verifier_path: Path,
    **overrides: object,
) -> Settings:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
        "modules": "profile,assurance",
        "privileged_modules_enabled": True,
        "enabled_tools": "m365_get_entra_identity_governance_posture",
        "allowed_user_object_ids": USER_ID,
        "allowed_upn_domains": "example.com",
        "governance_policy_path": policy_path,
        "governance_public_key_path": verifier_path,
        "assurance_snapshot_path": (
            tmp_path / "private-runtime" / "assurance.jsonl"
        ),
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _service(
    tmp_path: Path,
    graph: FakePostureGraph,
    *,
    baseline: IdentityGovernanceBaseline | None = None,
    snapshots: AssuranceSnapshotStore | None = None,
    policy_root: str = "policy",
    **settings_overrides: object,
) -> tuple[
    EntraIdentityGovernancePostureService,
    AssuranceSnapshotStore,
    Settings,
]:
    policy_path, verifier_path = write_signed_governance(
        tmp_path / policy_root,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        active_profile=GovernanceProfileName.PRIVILEGED_READ,
        identity_governance_baseline=baseline,
    )
    settings = _settings(
        tmp_path,
        policy_path=policy_path,
        verifier_path=verifier_path,
        **settings_overrides,
    )
    snapshot_store = snapshots or AssuranceSnapshotStore(settings)
    return (
        EntraIdentityGovernancePostureService(
            graph=graph,  # type: ignore[arg-type]
            settings=settings,
            manifest=load_global_manifest(),
            governance=load_verified_governance_policy(
                policy_path,
                verifier_path,
            ),
            snapshots=snapshot_store,
        ),
        snapshot_store,
        settings,
    )


def _baseline_from_report(
    report: Any,
    *,
    exception: AssuranceException | None = None,
) -> IdentityGovernanceBaseline:
    return IdentityGovernanceBaseline(
        baseline_id="entra-governance-production",
        version=1,
        captured_at=report.captured_at,
        source_snapshot_reference=report.snapshot_reference,
        domains={
            item.domain: AssuranceDomainBaseline(
                expected_digest=item.digest,
                drift_severity=DriftSeverity.HIGH,
            )
            for item in report.domains
        },
        exceptions=[exception] if exception is not None else [],
    )


@pytest.mark.asyncio
async def test_posture_snapshot_is_complete_minimized_and_read_only(
    tmp_path: Path,
) -> None:
    graph = FakePostureGraph(paginate_ca=True)
    service, _, settings = _service(tmp_path, graph)

    report = await service.collect()

    assert report.status == "OBSERVED_COMPLETE"
    assert report.coverage_status == "complete"
    assert report.authorization_mode == "automatic_read"
    assert report.authorization_basis == "signed_policy"
    assert report.active_profile == "privileged-read"
    assert report.writes_performed is False
    assert len(report.domains) == 4
    ca = next(
        item
        for item in report.domains
        if item.domain is AssuranceDomainName.CONDITIONAL_ACCESS
    )
    assert ca.pages_read == 2
    assert ca.item_count == 2
    assert ca.metrics == {
        "total": 2,
        "enabled": 1,
        "report_only": 1,
        "disabled": 0,
    }
    assert ca.digest.startswith("hmac-sha256:")
    assert all(method in {"GET", "GET_CURSOR"} for method, _ in graph.calls)

    public_result = report.model_dump_json()
    for private_value in (
        TENANT_ID,
        CA_POLICY_ID,
        CA_GROUP_ID,
        ROLE_ASSIGNMENT_ID,
        ROLE_PRINCIPAL_ID,
        ROLE_DEFINITION_ID,
    ):
        assert private_value not in public_result
    snapshot_payload = settings.effective_assurance_snapshot_path.read_text()
    assert '"ciphertext":' in snapshot_payload
    assert CA_GROUP_ID not in snapshot_payload
    assert ROLE_PRINCIPAL_ID not in snapshot_payload
    assert (
        stat.S_IMODE(
            settings.effective_assurance_snapshot_path.stat().st_mode
        )
        == 0o600
    )
    assert (
        stat.S_IMODE(
            settings.effective_assurance_snapshot_path.parent.stat().st_mode
        )
        == 0o700
    )


@pytest.mark.asyncio
async def test_signed_baseline_aligns_without_per_call_approval(
    tmp_path: Path,
) -> None:
    first_service, snapshots, _ = _service(
        tmp_path,
        FakePostureGraph(),
        policy_root="initial",
    )
    first = await first_service.collect()
    baseline = _baseline_from_report(first)
    second_service, _, _ = _service(
        tmp_path,
        FakePostureGraph(),
        baseline=baseline,
        snapshots=snapshots,
        policy_root="baseline",
    )

    second = await second_service.collect()

    assert second.baseline.configured is True
    assert second.baseline.baseline_id == baseline.baseline_id
    assert {
        item.alignment for item in second.domains
    } == {AlignmentStatus.ALIGNED}
    assert not any(
        finding.control_id.startswith("DRIFT.")
        for finding in second.findings
    )


@pytest.mark.asyncio
async def test_drift_uses_signed_severity_and_expiring_exception(
    tmp_path: Path,
) -> None:
    first_service, snapshots, _ = _service(
        tmp_path,
        FakePostureGraph(),
        policy_root="initial",
    )
    first = await first_service.collect()
    exception = AssuranceException(
        exception_id="approved-ca-change",
        control_id="DRIFT.CONDITIONAL_ACCESS",
        domain=AssuranceDomainName.CONDITIONAL_ACCESS,
        rationale="Approved temporary Conditional Access evaluation.",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    baseline = _baseline_from_report(first, exception=exception)
    drift_service, _, _ = _service(
        tmp_path,
        FakePostureGraph(ca_state="disabled"),
        baseline=baseline,
        snapshots=snapshots,
        policy_root="drift",
    )

    report = await drift_service.collect()

    ca = next(
        item
        for item in report.domains
        if item.domain is AssuranceDomainName.CONDITIONAL_ACCESS
    )
    assert ca.alignment is AlignmentStatus.EXCEPTION_APPROVED
    drift = next(
        item
        for item in report.findings
        if item.control_id == "DRIFT.CONDITIONAL_ACCESS"
    )
    assert drift.severity == "high"
    assert drift.alignment is AlignmentStatus.EXCEPTION_APPROVED
    assert drift.responsible_party.value == "GOVERNANCE_OWNER"


@pytest.mark.asyncio
async def test_expired_exception_does_not_suppress_drift(
    tmp_path: Path,
) -> None:
    first_service, snapshots, _ = _service(
        tmp_path,
        FakePostureGraph(),
        policy_root="initial",
    )
    first = await first_service.collect()
    expired = AssuranceException(
        exception_id="expired-ca-change",
        control_id="DRIFT.CONDITIONAL_ACCESS",
        domain=AssuranceDomainName.CONDITIONAL_ACCESS,
        rationale="Expired temporary Conditional Access evaluation.",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    baseline = _baseline_from_report(first, exception=expired)
    drift_service, _, _ = _service(
        tmp_path,
        FakePostureGraph(ca_state="disabled"),
        baseline=baseline,
        snapshots=snapshots,
        policy_root="drift",
    )

    report = await drift_service.collect()

    drift = next(
        item
        for item in report.findings
        if item.control_id == "DRIFT.CONDITIONAL_ACCESS"
    )
    assert drift.alignment is AlignmentStatus.NOT_ALIGNED
    assert drift.responsible_party.value == "TENANT_ADMIN"


@pytest.mark.asyncio
async def test_pagination_bound_fails_without_partial_snapshot(
    tmp_path: Path,
) -> None:
    service, _, settings = _service(
        tmp_path,
        FakePostureGraph(paginate_ca=True),
        assurance_max_pages_per_domain=1,
    )

    with pytest.raises(SecurityError, match="complete snapshot"):
        await service.collect()

    assert not settings.effective_assurance_snapshot_path.exists()


def test_baseline_digest_tampering_invalidates_governance_signature(
    tmp_path: Path,
) -> None:
    baseline = IdentityGovernanceBaseline(
        baseline_id="signed-baseline",
        version=1,
        captured_at=datetime.now(UTC),
        source_snapshot_reference=(
            "snapshot:dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        ),
        domains={
            domain: AssuranceDomainBaseline(
                expected_digest="hmac-sha256:" + ("a" * 64),
                drift_severity=DriftSeverity.HIGH,
            )
            for domain in AssuranceDomainName
        },
    )
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        active_profile=GovernanceProfileName.PRIVILEGED_READ,
        identity_governance_baseline=baseline,
    )
    document = json.loads(policy_path.read_text())
    document["policy"]["identity_governance_baseline"]["domains"][
        "conditional_access"
    ]["expected_digest"] = "hmac-sha256:" + ("b" * 64)
    policy_path.write_text(json.dumps(document), encoding="utf-8")
    policy_path.chmod(0o600)

    with pytest.raises(GovernancePolicyError, match="digest mismatch"):
        load_verified_governance_policy(policy_path, verifier_path)


def test_encrypted_snapshot_byte_bound_fails_before_file_creation(
    tmp_path: Path,
) -> None:
    _, snapshots, settings = _service(
        tmp_path,
        FakePostureGraph(),
        assurance_max_snapshot_bytes=1_000_000,
    )
    domains = {domain: [] for domain in AssuranceDomainName}
    domains[AssuranceDomainName.CONDITIONAL_ACCESS] = [
        {"bounded_test_value": "x" * 1_000_000}
    ]

    with pytest.raises(PrivateStateError, match="storage bound"):
        snapshots.store(
            snapshot_id=uuid4(),
            contract_id="entra.identity_governance.posture.snapshot",
            tenant_id=TENANT_ID,
            domains=domains,
        )

    assert not settings.effective_assurance_snapshot_path.exists()
