from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from m365_secure_mcp.assurance import AssuranceSnapshotStore
from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_manifest import load_global_manifest
from m365_secure_mcp.entra_app_credentials import (
    EntraApplicationCredentialPostureService,
)
from m365_secure_mcp.entra_permission_drift import (
    MICROSOFT_GRAPH_APP_ID,
    EntraPermissionGrantDriftService,
)
from m365_secure_mcp.entra_workload_readiness import (
    PLAYBOOK_ID,
    EntraWorkloadIdentityReadinessService,
)
from m365_secure_mcp.governance import (
    ApplicationCredentialBaseline,
    ApplicationCredentialTarget,
    GovernancePolicyError,
    GovernanceProfileName,
    PermissionGrantBaseline,
    PermissionGrantTarget,
    load_verified_governance_policy,
)
from m365_secure_mcp.operations import AlignmentStatus, PlaybookStatus
from m365_secure_mcp.playbook_manifest import load_global_playbook_manifest

from .conftest import CLIENT_ID, TENANT_ID
from .governance_helpers import write_signed_governance

SERVICE_PRINCIPAL_ID = "44444444-4444-4444-8444-444444444444"
CLIENT_APPLICATION_ID = "55555555-5555-4555-8555-555555555555"
APPLICATION_OBJECT_ID = "66666666-6666-4666-8666-666666666666"
OWNER_ID = "77777777-7777-4777-8777-777777777777"
GRAPH_SERVICE_PRINCIPAL_ID = "88888888-8888-4888-8888-888888888888"
CERTIFICATE_KEY_ID = "99999999-9999-4999-8999-999999999999"
APPLICATION_ROLE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _timestamp(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def _permission_baseline() -> PermissionGrantBaseline:
    return PermissionGrantBaseline(
        baseline_id="readiness-permissions",
        version=1,
        targets=[
            PermissionGrantTarget(
                service_principal_id=UUID(SERVICE_PRINCIPAL_ID),
                contract_ids=["entra.permission_grants.drift.snapshot"],
            )
        ],
    )


def _credential_baseline() -> ApplicationCredentialBaseline:
    return ApplicationCredentialBaseline(
        baseline_id="readiness-credentials",
        version=1,
        targets=[
            ApplicationCredentialTarget(
                application_id=UUID(APPLICATION_OBJECT_ID),
                minimum_owner_count=1,
                maximum_active_key_credentials=2,
            )
        ],
    )


class FakeReadinessGraph:
    def __init__(
        self,
        *,
        client_application_id: str = CLIENT_APPLICATION_ID,
        application_permission: bool = False,
        owners: list[str] | None = None,
        paginate_owners_forever: bool = False,
    ) -> None:
        self.client_application_id = client_application_id
        self.application_permission = application_permission
        self.owners = [OWNER_ID] if owners is None else owners
        self.paginate_owners_forever = paginate_owners_forever
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
        if endpoint == f"/applications/{APPLICATION_OBJECT_ID}":
            assert params is None
            return {
                "id": APPLICATION_OBJECT_ID,
                "appId": self.client_application_id,
                "signInAudience": "AzureADMyOrg",
                "isFallbackPublicClient": False,
                "passwordCredentials": [],
                "keyCredentials": [
                    {
                        "keyId": CERTIFICATE_KEY_ID,
                        "startDateTime": _timestamp(-30),
                        "endDateTime": _timestamp(180),
                        "key": None,
                        "type": "AsymmetricX509Cert",
                        "usage": "Verify",
                    }
                ],
            }
        if endpoint == f"/applications/{APPLICATION_OBJECT_ID}/owners":
            result: dict[str, Any] = {
                "value": [{"id": owner_id} for owner_id in self.owners]
            }
            if self.paginate_owners_forever:
                result["@odata.nextLink"] = (
                    "https://graph.microsoft.com/v1.0/applications/"
                    f"{APPLICATION_OBJECT_ID}/owners?$skiptoken=opaque"
                )
            return result
        if endpoint == f"/servicePrincipals/{SERVICE_PRINCIPAL_ID}":
            return {
                "id": SERVICE_PRINCIPAL_ID,
                "appId": CLIENT_APPLICATION_ID,
                "servicePrincipalType": "Application",
                "accountEnabled": True,
            }
        if endpoint == "/oauth2PermissionGrants":
            return {
                "value": [
                    {
                        "id": "opaque-delegated-grant",
                        "clientId": SERVICE_PRINCIPAL_ID,
                        "consentType": "AllPrincipals",
                        "principalId": None,
                        "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
                        "scope": "Directory.Read.All User.Read",
                    }
                ]
            }
        if endpoint == (
            f"/servicePrincipals/{SERVICE_PRINCIPAL_ID}/appRoleAssignments"
        ):
            assignments = []
            if self.application_permission:
                assignments.append(
                    {
                        "id": "opaque-role-assignment",
                        "principalId": SERVICE_PRINCIPAL_ID,
                        "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
                        "appRoleId": APPLICATION_ROLE_ID,
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
                        "id": APPLICATION_ROLE_ID,
                        "value": "Application.ReadWrite.All",
                    }
                ],
            }
        raise AssertionError(f"unexpected Graph endpoint: {endpoint}")

    async def request_cursor(self, url: str) -> dict[str, Any]:
        self.calls.append(("GET_CURSOR", url))
        return {"value": [], "@odata.nextLink": url}


def _service(
    tmp_path: Path,
    graph: FakeReadinessGraph,
    *,
    enable_playbook: bool = True,
    **settings_overrides: object,
) -> tuple[EntraWorkloadIdentityReadinessService, Settings]:
    policy_path, verifier_path = write_signed_governance(
        tmp_path / "policy",
        tenant_id=TENANT_ID,
        user_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        active_profile=GovernanceProfileName.PRIVILEGED_READ,
        permission_grant_baseline=_permission_baseline(),
        service_principal_id=SERVICE_PRINCIPAL_ID,
        application_credential_baseline=_credential_baseline(),
        application_id=APPLICATION_OBJECT_ID,
        enable_workload_identity_readiness=enable_playbook,
    )
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
        "modules": "profile,assurance",
        "privileged_modules_enabled": True,
        "enabled_tools": "m365_get_entra_workload_identity_readiness",
        "allowed_user_object_ids": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "allowed_upn_domains": "example.com",
        "allowed_service_principal_ids": SERVICE_PRINCIPAL_ID,
        "allowed_application_ids": APPLICATION_OBJECT_ID,
        "governance_policy_path": policy_path,
        "governance_public_key_path": verifier_path,
        "assurance_snapshot_path": tmp_path / "runtime" / "readiness.jsonl",
    }
    values.update(settings_overrides)
    settings = Settings(**values)  # type: ignore[arg-type]
    contracts = load_global_manifest()
    playbooks = load_global_playbook_manifest(contracts)
    governance = load_verified_governance_policy(
        policy_path,
        verifier_path,
    )
    snapshots = AssuranceSnapshotStore(settings)
    permission_drift = EntraPermissionGrantDriftService(
        graph=graph,  # type: ignore[arg-type]
        settings=settings,
        manifest=contracts,
        governance=governance,
        snapshots=snapshots,
    )
    application_credentials = EntraApplicationCredentialPostureService(
        graph=graph,  # type: ignore[arg-type]
        settings=settings,
        manifest=contracts,
        governance=governance,
        snapshots=snapshots,
    )
    return (
        EntraWorkloadIdentityReadinessService(
            settings=settings,
            contract_manifest=contracts,
            playbook_manifest=playbooks,
            governance=governance,
            snapshots=snapshots,
            permission_drift=permission_drift,
            application_credentials=application_credentials,
        ),
        settings,
    )


@pytest.mark.asyncio
async def test_readiness_correlates_complete_private_read_only_evidence(
    tmp_path: Path,
) -> None:
    graph = FakeReadinessGraph()
    service, settings = _service(tmp_path, graph)

    report = await service.collect()

    assert report.playbook_id == PLAYBOOK_ID
    assert report.status is PlaybookStatus.PLAYBOOK_COMPLETED_VERIFIED
    assert report.coverage_status == "complete_for_signed_targets"
    assert report.authorization_mode == "automatic_read"
    assert report.writes_performed is False
    assert report.admin_consent_is_manual is True
    assert len(report.nodes) == 2
    assert {node.status for node in report.nodes} == {"COMPLETED_VERIFIED"}
    assert len(report.targets) == 1
    target = report.targets[0]
    assert target.alignment is AlignmentStatus.ALIGNED
    assert target.permission_alignment is AlignmentStatus.ALIGNED
    assert target.credential_alignment is AlignmentStatus.ALIGNED
    assert target.owner_count == 1
    assert report.findings == []
    assert all(method in {"GET", "GET_CURSOR"} for method, _ in graph.calls)

    public_result = report.model_dump_json()
    snapshot_payload = settings.effective_assurance_snapshot_path.read_text()
    for private_value in (
        TENANT_ID,
        SERVICE_PRINCIPAL_ID,
        CLIENT_APPLICATION_ID,
        APPLICATION_OBJECT_ID,
        OWNER_ID,
        GRAPH_SERVICE_PRINCIPAL_ID,
        CERTIFICATE_KEY_ID,
    ):
        assert private_value not in public_result
        assert private_value not in snapshot_payload
    assert snapshot_payload.count('"ciphertext":') == 2


@pytest.mark.asyncio
async def test_readiness_elevates_combined_permission_and_ownership_risk(
    tmp_path: Path,
) -> None:
    service, _ = _service(
        tmp_path,
        FakeReadinessGraph(
            application_permission=True,
            owners=[],
        ),
    )

    report = await service.collect()

    assert report.targets[0].alignment is AlignmentStatus.NOT_ALIGNED
    combined = next(
        finding
        for finding in report.findings
        if finding.control_id == "WORKLOAD_IDENTITY_COMBINED_RISK"
    )
    assert combined.severity == "critical"
    assert combined.responsible_party.value == "TENANT_ADMIN"


@pytest.mark.asyncio
async def test_readiness_marks_unmatched_application_evidence_not_evaluated(
    tmp_path: Path,
) -> None:
    service, _ = _service(
        tmp_path,
        FakeReadinessGraph(
            client_application_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        ),
    )

    report = await service.collect()

    assert len(report.targets) == 2
    assert {
        target.alignment for target in report.targets
    } == {AlignmentStatus.NOT_EVALUATED}
    assert sum(
        finding.control_id == "WORKLOAD_IDENTITY_MAPPING_INCOMPLETE"
        for finding in report.findings
    ) == 2


@pytest.mark.asyncio
async def test_disabled_playbook_is_denied_before_graph(
    tmp_path: Path,
) -> None:
    graph = FakeReadinessGraph()
    service, _ = _service(
        tmp_path,
        graph,
        enable_playbook=False,
    )

    with pytest.raises(GovernancePolicyError, match="not enabled"):
        await service.collect()

    assert graph.calls == []


@pytest.mark.asyncio
async def test_incomplete_node_halts_without_claiming_coverage(
    tmp_path: Path,
) -> None:
    graph = FakeReadinessGraph(paginate_owners_forever=True)
    service, _ = _service(
        tmp_path,
        graph,
        assurance_max_pages_per_domain=1,
    )

    report = await service.collect()

    assert report.status is PlaybookStatus.PLAYBOOK_HALTED
    assert report.coverage_status == "not_evaluated"
    assert report.targets == []
    assert {node.status for node in report.nodes} == {"NOT_EVALUATED"}
    assert all(
        finding.alignment is AlignmentStatus.NOT_EVALUATED
        for finding in report.findings
    )
    assert not any(
        endpoint == "/oauth2PermissionGrants"
        for _, endpoint in graph.calls
    )
