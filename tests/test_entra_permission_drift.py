from __future__ import annotations

import json
import stat
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from m365_secure_mcp.assurance import AssuranceSnapshotStore
from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    RiskTier,
    load_global_manifest,
)
from m365_secure_mcp.entra_permission_drift import (
    APP_ROLE_ASSIGNMENTS_ENDPOINT,
    CONTRACT_ID,
    MICROSOFT_GRAPH_APP_ID,
    OAUTH2_GRANTS_ENDPOINT,
    EntraPermissionGrantDriftService,
)
from m365_secure_mcp.governance import (
    GovernancePolicyError,
    GovernanceProfileName,
    PermissionGrantBaseline,
    PermissionGrantException,
    PermissionGrantKind,
    PermissionGrantTarget,
    load_verified_governance_policy,
)
from m365_secure_mcp.operations import AlignmentStatus
from m365_secure_mcp.security import SecurityError

from .conftest import CLIENT_ID, TENANT_ID
from .governance_helpers import write_signed_governance

TARGET_SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"
TARGET_APPLICATION_ID = "66666666-6666-4666-8666-666666666666"
GRAPH_SERVICE_PRINCIPAL_ID = "77777777-7777-4777-8777-777777777777"
DELEGATED_GRANT_ID = "opaque-delegated-grant-id"
APP_ROLE_ASSIGNMENT_ID = "opaque-app-role-assignment-id"
APPLICATION_READWRITE_ROLE_ID = "88888888-8888-4888-8888-888888888888"


def _baseline(
    *,
    exception: PermissionGrantException | None = None,
) -> PermissionGrantBaseline:
    return PermissionGrantBaseline(
        baseline_id="msp-runtime-apps",
        version=1,
        targets=[
            PermissionGrantTarget(
                service_principal_id=UUID(TARGET_SERVICE_PRINCIPAL_ID),
                contract_ids=[CONTRACT_ID],
            )
        ],
        exceptions=[exception] if exception is not None else [],
    )


class FakePermissionGraph:
    def __init__(
        self,
        *,
        extra_delegated: bool = False,
        application_permission: bool = False,
        paginate_forever: bool = False,
    ) -> None:
        self.extra_delegated = extra_delegated
        self.application_permission = application_permission
        self.paginate_forever = paginate_forever
        self.calls: list[tuple[str, str]] = []

    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        del json_body, headers
        self.calls.append((method, endpoint))
        assert method == "GET"
        if endpoint == f"/servicePrincipals/{TARGET_SERVICE_PRINCIPAL_ID}":
            return {
                "id": TARGET_SERVICE_PRINCIPAL_ID,
                "appId": TARGET_APPLICATION_ID,
                "servicePrincipalType": "Application",
                "accountEnabled": True,
            }
        if endpoint == OAUTH2_GRANTS_ENDPOINT:
            assert params is not None
            assert params["$filter"] == (
                f"clientId eq '{TARGET_SERVICE_PRINCIPAL_ID}'"
            )
            scope = "Directory.Read.All User.Read"
            if self.extra_delegated:
                scope += " Application.Read.All"
            result: dict[str, Any] = {
                "value": [
                    {
                        "id": DELEGATED_GRANT_ID,
                        "clientId": TARGET_SERVICE_PRINCIPAL_ID,
                        "consentType": "AllPrincipals",
                        "principalId": None,
                        "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
                        "scope": scope,
                    }
                ]
            }
            if self.paginate_forever:
                result["@odata.nextLink"] = (
                    "https://graph.microsoft.com/v1.0/"
                    "oauth2PermissionGrants?$skiptoken=opaque"
                )
            return result
        if endpoint == (
            f"/servicePrincipals/{TARGET_SERVICE_PRINCIPAL_ID}"
            "/appRoleAssignments"
        ):
            assignments = []
            if self.application_permission:
                assignments.append(
                    {
                        "id": APP_ROLE_ASSIGNMENT_ID,
                        "principalId": TARGET_SERVICE_PRINCIPAL_ID,
                        "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
                        "appRoleId": APPLICATION_READWRITE_ROLE_ID,
                        "createdDateTime": "2026-07-26T12:00:00Z",
                    }
                )
            return {"value": assignments}
        if endpoint == f"/servicePrincipals/{GRAPH_SERVICE_PRINCIPAL_ID}":
            return {
                "id": GRAPH_SERVICE_PRINCIPAL_ID,
                "appId": str(MICROSOFT_GRAPH_APP_ID),
                "appRoles": [
                    {
                        "id": APPLICATION_READWRITE_ROLE_ID,
                        "value": "Application.ReadWrite.All",
                    }
                ],
            }
        raise AssertionError(f"unexpected Graph endpoint: {endpoint}")

    async def request_cursor(self, url: str) -> dict[str, Any]:
        self.calls.append(("GET_CURSOR", url))
        return {
            "value": [],
            "@odata.nextLink": url,
        }


def _service(
    tmp_path: Path,
    graph: FakePermissionGraph,
    *,
    baseline: PermissionGrantBaseline | None = None,
    local_target: str = TARGET_SERVICE_PRINCIPAL_ID,
    **overrides: object,
) -> tuple[
    EntraPermissionGrantDriftService,
    AssuranceSnapshotStore,
    Settings,
    Path,
]:
    policy_path, verifier_path = write_signed_governance(
        tmp_path / "policy",
        tenant_id=TENANT_ID,
        user_id="99999999-9999-4999-8999-999999999999",
        active_profile=GovernanceProfileName.PRIVILEGED_READ,
        permission_grant_baseline=baseline or _baseline(),
        service_principal_id=TARGET_SERVICE_PRINCIPAL_ID,
    )
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
        "modules": "profile,assurance",
        "privileged_modules_enabled": True,
        "enabled_tools": "m365_get_entra_permission_grant_drift",
        "allowed_user_object_ids": (
            "99999999-9999-4999-8999-999999999999"
        ),
        "allowed_upn_domains": "example.com",
        "allowed_service_principal_ids": local_target,
        "governance_policy_path": policy_path,
        "governance_public_key_path": verifier_path,
        "assurance_snapshot_path": (
            tmp_path / "runtime" / "permission-grants.jsonl"
        ),
    }
    values.update(overrides)
    settings = Settings(**values)  # type: ignore[arg-type]
    snapshots = AssuranceSnapshotStore(settings)
    return (
        EntraPermissionGrantDriftService(
            graph=graph,  # type: ignore[arg-type]
            settings=settings,
            manifest=load_global_manifest(),
            governance=load_verified_governance_policy(
                policy_path,
                verifier_path,
            ),
            snapshots=snapshots,
        ),
        snapshots,
        settings,
        policy_path,
    )


def test_permission_drift_contract_is_fixed_t0_and_least_privileged() -> None:
    contract = load_global_manifest().contract(CONTRACT_ID)
    assert contract.graph.method == "GET"
    assert contract.graph.endpoint == OAUTH2_GRANTS_ENDPOINT
    assert contract.input_schema["properties"] == {}
    assert contract.permissions.delegated_scopes == ["Directory.Read.All"]
    assert contract.permissions.operator_roles == [
        "Directory Readers",
        "Global Reader",
    ]
    assert contract.risk_tier is RiskTier.T0
    assert contract.authorization_mode is AuthorizationMode.AUTOMATIC_READ
    assert {
        call.endpoint for call in contract.preflight_graph_calls
    } == {
        "/servicePrincipals/{service_principal_id}",
        APP_ROLE_ASSIGNMENTS_ENDPOINT,
        "/servicePrincipals/{resource_service_principal_id}",
    }


@pytest.mark.asyncio
async def test_complete_contract_derived_snapshot_is_aligned_and_private(
    tmp_path: Path,
) -> None:
    graph = FakePermissionGraph()
    service, _, settings, _ = _service(tmp_path, graph)

    report = await service.collect()

    assert report.status == "OBSERVED_COMPLETE"
    assert report.coverage_status == "complete_for_signed_targets"
    assert report.authorization_mode == "automatic_read"
    assert report.active_profile == "privileged-read"
    assert report.writes_performed is False
    assert report.admin_consent_is_manual is True
    assert len(report.targets) == 1
    target = report.targets[0]
    assert target.alignment is AlignmentStatus.ALIGNED
    assert target.expected_delegated_permissions == 2
    assert target.observed_delegated_permissions == 2
    assert target.observed_application_permissions == 0
    assert report.findings == []
    assert all(method in {"GET", "GET_CURSOR"} for method, _ in graph.calls)

    public_result = report.model_dump_json()
    for private_value in (
        TENANT_ID,
        TARGET_SERVICE_PRINCIPAL_ID,
        TARGET_APPLICATION_ID,
        GRAPH_SERVICE_PRINCIPAL_ID,
        DELEGATED_GRANT_ID,
    ):
        assert private_value not in public_result
    snapshot_payload = settings.effective_assurance_snapshot_path.read_text()
    assert '"ciphertext":' in snapshot_payload
    assert TARGET_SERVICE_PRINCIPAL_ID not in snapshot_payload
    assert GRAPH_SERVICE_PRINCIPAL_ID not in snapshot_payload
    assert (
        stat.S_IMODE(
            settings.effective_assurance_snapshot_path.stat().st_mode
        )
        == 0o600
    )


@pytest.mark.asyncio
async def test_unexpected_application_permission_is_critical(
    tmp_path: Path,
) -> None:
    service, _, _, _ = _service(
        tmp_path,
        FakePermissionGraph(application_permission=True),
    )

    report = await service.collect()

    target = report.targets[0]
    assert target.alignment is AlignmentStatus.NOT_ALIGNED
    assert target.observed_application_permissions == 1
    finding = next(
        item
        for item in report.findings
        if item.control_id == "PERMISSION_APPLICATION_UNEXPECTED"
    )
    assert finding.severity == "critical"
    assert finding.responsible_party.value == "TENANT_ADMIN"
    assert "Application.ReadWrite.All" in finding.summary


@pytest.mark.asyncio
async def test_exact_expiring_exception_is_visible_not_silent(
    tmp_path: Path,
) -> None:
    exception = PermissionGrantException(
        exception_id="temporary-app-read",
        service_principal_id=UUID(TARGET_SERVICE_PRINCIPAL_ID),
        kind=PermissionGrantKind.DELEGATED,
        resource_app_id=MICROSOFT_GRAPH_APP_ID,
        permission_value="Application.Read.All",
        consent_type="AllPrincipals",
        rationale="Approved while a legacy workflow is migrated.",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    service, _, _, _ = _service(
        tmp_path,
        FakePermissionGraph(extra_delegated=True),
        baseline=_baseline(exception=exception),
    )

    report = await service.collect()

    assert report.targets[0].alignment is AlignmentStatus.EXCEPTION_APPROVED
    finding = next(
        item
        for item in report.findings
        if item.control_id == "PERMISSION_DELEGATED_UNEXPECTED"
    )
    assert finding.alignment is AlignmentStatus.EXCEPTION_APPROVED
    assert finding.responsible_party.value == "GOVERNANCE_OWNER"


@pytest.mark.asyncio
async def test_local_target_fence_mismatch_blocks_before_graph(
    tmp_path: Path,
) -> None:
    graph = FakePermissionGraph()
    service, _, _, _ = _service(
        tmp_path,
        graph,
        local_target="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )

    with pytest.raises(
        GovernancePolicyError,
        match="allowlisted by runtime",
    ):
        await service.collect()

    assert graph.calls == []


@pytest.mark.asyncio
async def test_incomplete_pagination_fails_without_snapshot(
    tmp_path: Path,
) -> None:
    service, _, settings, _ = _service(
        tmp_path,
        FakePermissionGraph(paginate_forever=True),
        assurance_max_pages_per_domain=1,
    )

    with pytest.raises(SecurityError, match="prove completeness"):
        await service.collect()

    assert not settings.effective_assurance_snapshot_path.exists()


def test_permission_baseline_tampering_invalidates_signature(
    tmp_path: Path,
) -> None:
    _, _, _, policy_path = _service(tmp_path, FakePermissionGraph())
    document = json.loads(policy_path.read_text())
    document["policy"]["permission_grant_baseline"]["targets"][0][
        "contract_ids"
    ] = ["entra.organization.summary.read"]
    policy_path.write_text(json.dumps(document), encoding="utf-8")
    policy_path.chmod(0o600)

    with pytest.raises(GovernancePolicyError, match="digest mismatch"):
        load_verified_governance_policy(
            policy_path,
            tmp_path / "policy" / "governance" / "governance.pub",
        )
