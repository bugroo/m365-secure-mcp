from __future__ import annotations

import stat
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from m365_secure_mcp.assurance import AssuranceSnapshotStore
from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    RiskTier,
    load_global_manifest,
)
from m365_secure_mcp.entra_app_credentials import (
    APPLICATION_ENDPOINT,
    APPLICATION_OWNERS_ENDPOINT,
    CONTRACT_ID,
    EntraApplicationCredentialPostureService,
)
from m365_secure_mcp.governance import (
    ApplicationCredentialBaseline,
    ApplicationCredentialException,
    ApplicationCredentialKind,
    ApplicationCredentialTarget,
    GovernancePolicyError,
    GovernanceProfileName,
    load_verified_governance_policy,
)
from m365_secure_mcp.operations import AlignmentStatus
from m365_secure_mcp.security import SecurityError

from .conftest import CLIENT_ID, TENANT_ID
from .governance_helpers import write_signed_governance

APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
CLIENT_APPLICATION_ID = "55555555-5555-4555-8555-555555555555"
OWNER_ID = "66666666-6666-4666-8666-666666666666"
PASSWORD_KEY_ID = "77777777-7777-4777-8777-777777777777"  # noqa: S105
CERTIFICATE_KEY_ID = "88888888-8888-4888-8888-888888888888"


def _timestamp(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def _baseline(
    *,
    minimum_owner_count: int = 1,
    password_credentials_allowed: bool = False,
    maximum_active_password_credentials: int = 0,
    maximum_active_key_credentials: int = 2,
    exception: ApplicationCredentialException | None = None,
) -> ApplicationCredentialBaseline:
    return ApplicationCredentialBaseline(
        baseline_id="msp-application-posture",
        version=1,
        targets=[
            ApplicationCredentialTarget(
                application_id=UUID(APPLICATION_ID),
                minimum_owner_count=minimum_owner_count,
                expiry_warning_days=30,
                password_credentials_allowed=password_credentials_allowed,
                maximum_active_password_credentials=(
                    maximum_active_password_credentials
                ),
                maximum_active_key_credentials=maximum_active_key_credentials,
            )
        ],
        exceptions=[exception] if exception is not None else [],
    )


class FakeApplicationGraph:
    def __init__(
        self,
        *,
        password_credentials: list[dict[str, Any]] | None = None,
        key_credentials: list[dict[str, Any]] | None = None,
        owners: list[str] | None = None,
        paginate_forever: bool = False,
    ) -> None:
        self.password_credentials = password_credentials or []
        self.key_credentials = (
            key_credentials
            if key_credentials is not None
            else [
                {
                    "keyId": CERTIFICATE_KEY_ID,
                    "startDateTime": _timestamp(-30),
                    "endDateTime": _timestamp(180),
                    "displayName": "production certificate",
                    "customKeyIdentifier": "thumbprint-must-not-persist",
                    "key": None,
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                }
            ]
        )
        self.owners = owners if owners is not None else [OWNER_ID]
        self.paginate_forever = paginate_forever
        self.calls: list[tuple[str, str, Mapping[str, str | int] | None]] = []

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
        self.calls.append((method, endpoint, params))
        assert method == "GET"
        if endpoint == APPLICATION_ENDPOINT.format(application_id=APPLICATION_ID):
            assert params is None
            return {
                "id": APPLICATION_ID,
                "appId": CLIENT_APPLICATION_ID,
                "signInAudience": "AzureADMyOrg",
                "isFallbackPublicClient": False,
                "displayName": "must not persist",
                "passwordCredentials": self.password_credentials,
                "keyCredentials": self.key_credentials,
            }
        if endpoint == APPLICATION_OWNERS_ENDPOINT.format(
            application_id=APPLICATION_ID
        ):
            assert params == {"$select": "id", "$top": 100}
            result: dict[str, Any] = {
                "value": [{"id": owner_id} for owner_id in self.owners]
            }
            if self.paginate_forever:
                result["@odata.nextLink"] = (
                    "https://graph.microsoft.com/v1.0/applications/"
                    f"{APPLICATION_ID}/owners?$skiptoken=opaque"
                )
            return result
        raise AssertionError(f"unexpected Graph endpoint: {endpoint}")

    async def request_cursor(self, url: str) -> dict[str, Any]:
        self.calls.append(("GET_CURSOR", url, None))
        return {"value": [], "@odata.nextLink": url}


def _service(
    tmp_path: Path,
    graph: FakeApplicationGraph,
    *,
    baseline: ApplicationCredentialBaseline | None = None,
    local_application_id: str = APPLICATION_ID,
    **overrides: object,
) -> tuple[
    EntraApplicationCredentialPostureService,
    Settings,
    Path,
]:
    policy_path, verifier_path = write_signed_governance(
        tmp_path / "policy",
        tenant_id=TENANT_ID,
        user_id="99999999-9999-4999-8999-999999999999",
        active_profile=GovernanceProfileName.PRIVILEGED_READ,
        application_credential_baseline=baseline or _baseline(),
        application_id=APPLICATION_ID,
    )
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
        "modules": "profile,assurance",
        "privileged_modules_enabled": True,
        "enabled_tools": "m365_get_entra_app_credential_posture",
        "allowed_user_object_ids": (
            "99999999-9999-4999-8999-999999999999"
        ),
        "allowed_upn_domains": "example.com",
        "allowed_application_ids": local_application_id,
        "governance_policy_path": policy_path,
        "governance_public_key_path": verifier_path,
        "assurance_snapshot_path": (
            tmp_path / "runtime" / "application-posture.jsonl"
        ),
    }
    values.update(overrides)
    settings = Settings(**values)  # type: ignore[arg-type]
    return (
        EntraApplicationCredentialPostureService(
            graph=graph,  # type: ignore[arg-type]
            settings=settings,
            manifest=load_global_manifest(),
            governance=load_verified_governance_policy(
                policy_path,
                verifier_path,
            ),
            snapshots=AssuranceSnapshotStore(settings),
        ),
        settings,
        policy_path,
    )


def test_application_credential_contract_is_fixed_t0_and_least_privileged() -> None:
    contract = load_global_manifest().contract(CONTRACT_ID)
    assert contract.graph.method == "GET"
    assert contract.graph.endpoint == APPLICATION_ENDPOINT
    assert contract.input_schema["properties"] == {}
    assert contract.permissions.delegated_scopes == ["Application.Read.All"]
    assert contract.permissions.operator_roles == [
        "Directory Readers",
        "Global Reader",
    ]
    assert contract.risk_tier is RiskTier.T0
    assert contract.authorization_mode is AuthorizationMode.AUTOMATIC_READ
    assert {
        call.endpoint for call in contract.preflight_graph_calls
    } == {APPLICATION_OWNERS_ENDPOINT}


def test_credential_exception_requires_exact_known_selector() -> None:
    with pytest.raises(ValidationError, match="exact credential selector"):
        ApplicationCredentialException(
            exception_id="unsafe-broad-exception",
            application_id=UUID(APPLICATION_ID),
            control_id="APP_CREDENTIAL_EXPIRING",
            rationale="This broad credential exception must not be accepted.",
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )


@pytest.mark.asyncio
async def test_healthy_snapshot_is_aligned_encrypted_and_material_free(
    tmp_path: Path,
) -> None:
    graph = FakeApplicationGraph()
    service, settings, _ = _service(tmp_path, graph)

    report = await service.collect()

    assert report.status == "OBSERVED_COMPLETE"
    assert report.coverage_status == "complete_for_signed_targets"
    assert report.authorization_mode == "automatic_read"
    assert report.active_profile == "privileged-read"
    assert report.writes_performed is False
    assert report.admin_consent_is_manual is True
    assert report.credential_material_returned is False
    assert report.findings == []
    target = report.targets[0]
    assert target.alignment is AlignmentStatus.ALIGNED
    assert target.owner_count == 1
    assert target.key_credentials == 1
    assert target.password_credentials == 0
    assert all(method in {"GET", "GET_CURSOR"} for method, _, _ in graph.calls)

    public_result = report.model_dump_json()
    snapshot_payload = settings.effective_assurance_snapshot_path.read_text()
    for private_value in (
        TENANT_ID,
        APPLICATION_ID,
        CLIENT_APPLICATION_ID,
        OWNER_ID,
        CERTIFICATE_KEY_ID,
        "production certificate",
        "thumbprint-must-not-persist",
        "must not persist",
    ):
        assert private_value not in public_result
        assert private_value not in snapshot_payload
    assert '"ciphertext":' in snapshot_payload
    assert (
        stat.S_IMODE(
            settings.effective_assurance_snapshot_path.stat().st_mode
        )
        == 0o600
    )


@pytest.mark.asyncio
async def test_owner_secret_expiry_and_redundancy_findings_are_deterministic(
    tmp_path: Path,
) -> None:
    graph = FakeApplicationGraph(
        owners=[],
        password_credentials=[
            {
                "keyId": PASSWORD_KEY_ID,
                "startDateTime": _timestamp(-90),
                "endDateTime": _timestamp(-1),
                    "hint": "sensitive-hint-do-not-return-7f91",
                "secretText": None,
            }
        ],
        key_credentials=[
            {
                "keyId": CERTIFICATE_KEY_ID,
                "startDateTime": _timestamp(-30),
                "endDateTime": _timestamp(5),
                "customKeyIdentifier": "discarded-thumbprint",
                "key": None,
                "type": "AsymmetricX509Cert",
                "usage": "Verify",
            }
        ],
    )
    service, settings, _ = _service(
        tmp_path,
        graph,
        baseline=_baseline(maximum_active_key_credentials=0),
    )

    report = await service.collect()

    control_ids = {finding.control_id for finding in report.findings}
    assert control_ids == {
        "APP_ACTIVE_KEY_CREDENTIALS_EXCEED_MAXIMUM",
        "APP_CREDENTIAL_EXPIRED",
        "APP_CREDENTIAL_EXPIRING",
        "APP_OWNER_COUNT_BELOW_MINIMUM",
        "APP_PASSWORD_CREDENTIAL_PROHIBITED",
    }
    assert report.targets[0].alignment is AlignmentStatus.NOT_ALIGNED
    assert report.targets[0].expired_credentials == 1
    assert report.targets[0].expiring_credentials == 1
    public_result = report.model_dump_json()
    snapshot_payload = settings.effective_assurance_snapshot_path.read_text()
    for excluded in (
        PASSWORD_KEY_ID,
        CERTIFICATE_KEY_ID,
            "sensitive-hint-do-not-return-7f91",
        "discarded-thumbprint",
    ):
        assert excluded not in public_result
        assert excluded not in snapshot_payload


@pytest.mark.asyncio
async def test_exact_expiring_exception_changes_alignment_not_policy(
    tmp_path: Path,
) -> None:
    exception = ApplicationCredentialException(
        exception_id="temporary-secret-migration",
        application_id=UUID(APPLICATION_ID),
        control_id="APP_PASSWORD_CREDENTIAL_PROHIBITED",
        credential_kind=ApplicationCredentialKind.PASSWORD,
        credential_key_id=UUID(PASSWORD_KEY_ID),
        rationale="Migration to workload identity is approved and scheduled.",
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    graph = FakeApplicationGraph(
        password_credentials=[
            {
                "keyId": PASSWORD_KEY_ID,
                "startDateTime": _timestamp(-1),
                "endDateTime": _timestamp(180),
                "hint": "abc",
                "secretText": None,
            }
        ]
    )
    service, _, _ = _service(
        tmp_path,
        graph,
        baseline=_baseline(exception=exception),
    )

    report = await service.collect()

    assert len(report.findings) == 1
    assert report.findings[0].alignment is AlignmentStatus.EXCEPTION_APPROVED
    assert report.targets[0].alignment is AlignmentStatus.EXCEPTION_APPROVED
    assert report.targets[0].approved_exceptions == 1


@pytest.mark.asyncio
async def test_local_application_fence_blocks_before_graph(
    tmp_path: Path,
) -> None:
    graph = FakeApplicationGraph()
    service, _, _ = _service(
        tmp_path,
        graph,
        local_application_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )

    with pytest.raises(GovernancePolicyError, match="allowlisted"):
        await service.collect()

    assert graph.calls == []


@pytest.mark.asyncio
async def test_graph_key_material_fails_closed_and_is_never_persisted(
    tmp_path: Path,
) -> None:
    graph = FakeApplicationGraph(
        key_credentials=[
            {
                "keyId": CERTIFICATE_KEY_ID,
                "startDateTime": _timestamp(-1),
                "endDateTime": _timestamp(180),
                "key": "public-key-material",
                "type": "AsymmetricX509Cert",
                "usage": "Verify",
            }
        ]
    )
    service, settings, _ = _service(tmp_path, graph)

    with pytest.raises(SecurityError, match="key material"):
        await service.collect()

    assert not settings.effective_assurance_snapshot_path.exists()


@pytest.mark.asyncio
async def test_incomplete_owner_pagination_fails_closed(
    tmp_path: Path,
) -> None:
    graph = FakeApplicationGraph(paginate_forever=True)
    service, settings, _ = _service(
        tmp_path,
        graph,
        assurance_max_pages_per_domain=2,
    )

    with pytest.raises(SecurityError, match="pagination"):
        await service.collect()

    assert not settings.effective_assurance_snapshot_path.exists()
