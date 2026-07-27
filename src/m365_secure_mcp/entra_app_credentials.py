"""Read-only posture for allowlisted Entra application credentials."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .assurance import AssuranceSnapshotStore
from .config import Settings
from .contract_manifest import ContractManifest, ContractSpec, sha256_digest
from .governance import (
    ApplicationCredentialException,
    ApplicationCredentialKind,
    ApplicationCredentialTarget,
    GovernancePolicyError,
    VerifiedGovernancePolicy,
)
from .graph import GraphClient
from .operations import AlignmentStatus, Finding, ResponsibleParty
from .security import SecurityError, path_segment

CONTRACT_ID = "entra.app_credentials.posture.snapshot"
TOOL_NAME = "m365_get_entra_app_credential_posture"
APPLICATION_ENDPOINT = "/applications/{application_id}"
APPLICATION_OWNERS_ENDPOINT = "/applications/{application_id}/owners"

MAX_CREDENTIALS_PER_APPLICATION = 100
MAX_OWNERS_PER_APPLICATION = 100
MAX_GRAPH_DATETIME_LENGTH = 64
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ApplicationCredentialSnapshotDomain(StrEnum):
    APPLICATIONS = "applications"
    OWNERS = "owners"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ApplicationCredentialTargetPosture(StrictModel):
    target_reference: str = Field(pattern=r"^app:[0-9a-f]{24}$")
    workload_identity_reference: str = Field(pattern=r"^wi:[0-9a-f]{24}$")
    baseline_reference: str = Field(min_length=3, max_length=128)
    digest: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    alignment: AlignmentStatus
    owner_count: int = Field(ge=0, le=MAX_OWNERS_PER_APPLICATION)
    minimum_owner_count: int = Field(ge=1, le=20)
    password_credentials: int = Field(ge=0, le=MAX_CREDENTIALS_PER_APPLICATION)
    key_credentials: int = Field(ge=0, le=MAX_CREDENTIALS_PER_APPLICATION)
    active_password_credentials: int = Field(
        ge=0,
        le=MAX_CREDENTIALS_PER_APPLICATION,
    )
    active_key_credentials: int = Field(
        ge=0,
        le=MAX_CREDENTIALS_PER_APPLICATION,
    )
    expiring_credentials: int = Field(
        ge=0,
        le=MAX_CREDENTIALS_PER_APPLICATION * 2,
    )
    expired_credentials: int = Field(
        ge=0,
        le=MAX_CREDENTIALS_PER_APPLICATION * 2,
    )
    approved_exceptions: int = Field(ge=0, le=500)


class ApplicationCredentialPostureReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["OBSERVED_COMPLETE"] = "OBSERVED_COMPLETE"
    contract_id: Literal["entra.app_credentials.posture.snapshot"] = (
        "entra.app_credentials.posture.snapshot"
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
    coverage_status: Literal["complete_for_signed_targets"] = (
        "complete_for_signed_targets"
    )
    baseline_id: str
    baseline_version: int = Field(ge=1)
    targets: list[ApplicationCredentialTargetPosture] = Field(
        min_length=1,
        max_length=100,
    )
    findings: list[Finding]
    writes_performed: Literal[False] = False
    admin_consent_is_manual: Literal[True] = True
    credential_material_returned: Literal[False] = False


def _uuid_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise SecurityError(
            f"Microsoft Graph returned an invalid {field}"
        ) from exc
    if parsed.int == 0:
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    return str(parsed)


def _graph_datetime(value: Any, *, field: str) -> datetime | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_GRAPH_DATETIME_LENGTH
        or any(ord(character) < 32 for character in value)
    ):
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SecurityError(
            f"Microsoft Graph returned an invalid {field}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SecurityError(f"Microsoft Graph returned a timezone-free {field}")
    return parsed.astimezone(UTC)


def _optional_bounded_string(
    value: Any,
    *,
    field: str,
    allowed: frozenset[str] | None = None,
) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 100
        or any(ord(character) < 32 for character in value)
        or (allowed is not None and value not in allowed)
    ):
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    return value


def _normalize_credential(
    raw: Any,
    *,
    kind: ApplicationCredentialKind,
) -> dict[str, str | None]:
    if not isinstance(raw, dict):
        raise SecurityError("Microsoft Graph returned an invalid credential")
    if kind is ApplicationCredentialKind.PASSWORD:
        if raw.get("secretText") not in (None, ""):
            raise SecurityError(
                "Microsoft Graph unexpectedly returned password material"
            )
    elif raw.get("key") not in (None, ""):
        # The request deliberately avoids `$select=keyCredentials`, which is
        # the Graph switch that can include the public key value.
        raise SecurityError("Microsoft Graph unexpectedly returned key material")

    key_id = _uuid_text(raw.get("keyId"), field=f"{kind.value} credential ID")
    start = _graph_datetime(
        raw.get("startDateTime"),
        field=f"{kind.value} credential start time",
    )
    end = _graph_datetime(
        raw.get("endDateTime"),
        field=f"{kind.value} credential end time",
    )
    normalized: dict[str, str | None] = {
        "keyId": key_id,
        "startDateTime": start.isoformat() if start is not None else None,
        "endDateTime": end.isoformat() if end is not None else None,
    }
    if kind is ApplicationCredentialKind.KEY:
        normalized["type"] = _optional_bounded_string(
            raw.get("type"),
            field="key credential type",
        )
        normalized["usage"] = _optional_bounded_string(
            raw.get("usage"),
            field="key credential usage",
            allowed=frozenset({"Sign", "Verify"}),
        )
    # displayName, hint, customKeyIdentifier/thumbprint, secretText and key
    # are intentionally neither normalized nor persisted.
    return normalized


def _credential_times(
    credential: Mapping[str, str | None],
) -> tuple[datetime | None, datetime | None]:
    return (
        _graph_datetime(
            credential["startDateTime"],
            field="normalized credential start time",
        ),
        _graph_datetime(
            credential["endDateTime"],
            field="normalized credential end time",
        ),
    )


class EntraApplicationCredentialPostureService:
    """Evaluate signed app posture without listing a tenant or writing Graph."""

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

    async def _get_application(self, application_id: str) -> dict[str, Any]:
        safe_id = path_segment(application_id)
        # Do not add `$select=keyCredentials`: Microsoft documents that as the
        # opt-in that returns public key values. We minimize the default
        # response immediately and retain no names, hints or key material.
        data = await self.graph.request_json(
            "GET",
            f"/applications/{safe_id}",
        )
        resolved_id = _uuid_text(data.get("id"), field="application object ID")
        if resolved_id != application_id:
            raise SecurityError("Microsoft Graph returned a different application")
        raw_passwords = data.get("passwordCredentials")
        raw_keys = data.get("keyCredentials")
        if (
            not isinstance(raw_passwords, list)
            or len(raw_passwords) > MAX_CREDENTIALS_PER_APPLICATION
            or not isinstance(raw_keys, list)
            or len(raw_keys) > MAX_CREDENTIALS_PER_APPLICATION
        ):
            raise SecurityError(
                "Microsoft Graph returned an invalid credential collection"
            )
        public_client = data.get("isFallbackPublicClient")
        if public_client is not None and not isinstance(public_client, bool):
            raise SecurityError(
                "Microsoft Graph returned an invalid public-client state"
            )
        return {
            "id": resolved_id,
            "appId": _uuid_text(data.get("appId"), field="application client ID"),
            "signInAudience": _optional_bounded_string(
                data.get("signInAudience"),
                field="application sign-in audience",
                allowed=frozenset(
                    {
                        "AzureADMyOrg",
                        "AzureADMultipleOrgs",
                        "AzureADandPersonalMicrosoftAccount",
                        "PersonalMicrosoftAccount",
                    }
                ),
            ),
            "isFallbackPublicClient": public_client,
            "passwordCredentials": sorted(
                (
                    _normalize_credential(
                        item,
                        kind=ApplicationCredentialKind.PASSWORD,
                    )
                    for item in raw_passwords
                ),
                key=lambda item: str(item["keyId"]),
            ),
            "keyCredentials": sorted(
                (
                    _normalize_credential(
                        item,
                        kind=ApplicationCredentialKind.KEY,
                    )
                    for item in raw_keys
                ),
                key=lambda item: str(item["keyId"]),
            ),
        }

    async def _get_owners(
        self,
        application_id: str,
    ) -> tuple[list[dict[str, str]], int]:
        safe_id = path_segment(application_id)
        data = await self.graph.request_json(
            "GET",
            f"/applications/{safe_id}/owners",
            params={"$select": "id", "$top": 100},
        )
        owners: list[dict[str, str]] = []
        pages = 0
        seen_next_links: set[str] = set()
        while True:
            pages += 1
            if pages > self.settings.assurance_max_pages_per_domain:
                raise SecurityError(
                    "application-owner pagination exceeded the runtime bound"
                )
            raw_items = data.get("value")
            if not isinstance(raw_items, list):
                raise SecurityError(
                    "Microsoft Graph returned an invalid owner collection"
                )
            for raw in raw_items:
                if not isinstance(raw, dict):
                    raise SecurityError(
                        "Microsoft Graph returned an invalid owner record"
                    )
                owners.append(
                    {
                        "applicationId": application_id,
                        "ownerId": _uuid_text(
                            raw.get("id"),
                            field="application owner ID",
                        ),
                    }
                )
                if len(owners) > MAX_OWNERS_PER_APPLICATION:
                    raise SecurityError(
                        "application owner collection exceeded the contract bound"
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
                    "application-owner pagination could not prove completeness"
                )
            seen_next_links.add(next_link)
            data = await self.graph.request_cursor(next_link)

        owner_ids = [item["ownerId"] for item in owners]
        if owner_ids != sorted(set(owner_ids)):
            owners.sort(key=lambda item: item["ownerId"])
            if [item["ownerId"] for item in owners] != sorted(set(owner_ids)):
                raise SecurityError(
                    "Microsoft Graph returned duplicate application owners"
                )
        return owners, pages

    @staticmethod
    def _active_exception(
        exceptions: list[ApplicationCredentialException],
        *,
        target_id: str,
        control_id: str,
        kind: ApplicationCredentialKind | None,
        credential_key_id: str | None,
        now: datetime,
    ) -> bool:
        for item in exceptions:
            if (
                item.expires_at <= now
                or str(item.application_id) != target_id
                or item.control_id != control_id
            ):
                continue
            if item.credential_kind is None:
                return True
            if (
                kind is item.credential_kind
                and credential_key_id is not None
                and str(item.credential_key_id) == credential_key_id
            ):
                return True
        return False

    def _finding(
        self,
        *,
        snapshot_reference: str,
        baseline_reference: str,
        target_reference: str,
        target_id: str,
        control_id: str,
        severity: str,
        operator_action: str,
        exceptions: list[ApplicationCredentialException],
        now: datetime,
        kind: ApplicationCredentialKind | None = None,
        credential_key_id: str | None = None,
    ) -> Finding:
        excepted = self._active_exception(
            exceptions,
            target_id=target_id,
            control_id=control_id,
            kind=kind,
            credential_key_id=credential_key_id,
            now=now,
        )
        alignment = (
            AlignmentStatus.EXCEPTION_APPROVED
            if excepted
            else AlignmentStatus.NOT_ALIGNED
        )
        selector = credential_key_id or "application"
        finding_reference = self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="finding",
            resource_id=f"{target_id}:{control_id}:{kind}:{selector}",
        )
        return Finding(
            finding_id=finding_reference,
            control_id=control_id,
            status=alignment.value,
            severity=severity,
            summary=(
                f"{target_reference}: "
                f"{control_id.lower().replace('_', ' ')}."
            ),
            evidence_reference=snapshot_reference,
            alignment=alignment,
            operator_action=operator_action,
            responsible_party=(
                ResponsibleParty.GOVERNANCE_OWNER
                if excepted
                else ResponsibleParty.TENANT_ADMIN
            ),
            baseline_reference=baseline_reference,
        )

    def _credential_findings(
        self,
        *,
        target: ApplicationCredentialTarget,
        kind: ApplicationCredentialKind,
        credential: Mapping[str, str | None],
        target_reference: str,
        snapshot_reference: str,
        baseline_reference: str,
        exceptions: list[ApplicationCredentialException],
        now: datetime,
    ) -> tuple[list[Finding], bool, bool, bool]:
        target_id = str(target.application_id)
        key_id = str(credential["keyId"])
        start, end = _credential_times(credential)
        findings: list[Finding] = []
        active = (start is None or start <= now) and (end is None or end > now)
        expired = end is not None and end <= now
        expiring = (
            active
            and end is not None
            and end <= now + timedelta(days=target.expiry_warning_days)
        )
        if start is not None and end is not None and end <= start:
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    target_id=target_id,
                    control_id="APP_CREDENTIAL_INVALID_WINDOW",
                    severity="critical",
                    operator_action=(
                        "Review and replace this credential manually; its signed "
                        "validity window is invalid."
                    ),
                    exceptions=exceptions,
                    now=now,
                    kind=kind,
                    credential_key_id=key_id,
                )
            )
        if end is None:
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    target_id=target_id,
                    control_id="APP_CREDENTIAL_NO_EXPIRY",
                    severity="critical",
                    operator_action=(
                        "Replace this credential manually with a bounded lifetime "
                        "or use workload identity federation."
                    ),
                    exceptions=exceptions,
                    now=now,
                    kind=kind,
                    credential_key_id=key_id,
                )
            )
        elif expired:
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    target_id=target_id,
                    control_id="APP_CREDENTIAL_EXPIRED",
                    severity="critical",
                    operator_action=(
                        "Confirm application continuity, then remove or replace "
                        "the expired credential through an approved admin workflow."
                    ),
                    exceptions=exceptions,
                    now=now,
                    kind=kind,
                    credential_key_id=key_id,
                )
            )
        elif expiring:
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    target_id=target_id,
                    control_id="APP_CREDENTIAL_EXPIRING",
                    severity="high",
                    operator_action=(
                        "Schedule a reviewed credential rollover before expiry; "
                        "this Assurance tool performs no rotation."
                    ),
                    exceptions=exceptions,
                    now=now,
                    kind=kind,
                    credential_key_id=key_id,
                )
            )
        if (
            kind is ApplicationCredentialKind.PASSWORD
            and not target.password_credentials_allowed
        ):
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    target_id=target_id,
                    control_id="APP_PASSWORD_CREDENTIAL_PROHIBITED",
                    severity="high",
                    operator_action=(
                        "Migrate to workload identity federation, managed identity, "
                        "or a certificate, then remove the secret manually."
                    ),
                    exceptions=exceptions,
                    now=now,
                    kind=kind,
                    credential_key_id=key_id,
                )
            )
        return findings, active, expiring, expired

    def _classify_target(
        self,
        *,
        target: ApplicationCredentialTarget,
        application: dict[str, Any],
        owners: list[dict[str, str]],
        snapshot_reference: str,
        baseline_reference: str,
        exceptions: list[ApplicationCredentialException],
        now: datetime,
    ) -> tuple[ApplicationCredentialTargetPosture, list[Finding]]:
        target_id = str(target.application_id)
        target_reference = self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="app",
            resource_id=target_id,
        )
        workload_identity_reference = self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="wi",
            resource_id=str(application["appId"]),
        )
        findings: list[Finding] = []
        owner_count = len(owners)
        if owner_count < target.minimum_owner_count:
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    target_id=target_id,
                    control_id="APP_OWNER_COUNT_BELOW_MINIMUM",
                    severity="critical" if owner_count == 0 else "high",
                    operator_action=(
                        "Assign and review the minimum number of accountable "
                        "application owners in Entra."
                    ),
                    exceptions=exceptions,
                    now=now,
                )
            )

        active_passwords = 0
        active_keys = 0
        expiring = 0
        expired = 0
        for kind, field in (
            (ApplicationCredentialKind.PASSWORD, "passwordCredentials"),
            (ApplicationCredentialKind.KEY, "keyCredentials"),
        ):
            credentials = application[field]
            for credential in credentials:
                credential_findings, is_active, is_expiring, is_expired = (
                    self._credential_findings(
                        target=target,
                        kind=kind,
                        credential=credential,
                        target_reference=target_reference,
                        snapshot_reference=snapshot_reference,
                        baseline_reference=baseline_reference,
                        exceptions=exceptions,
                        now=now,
                    )
                )
                findings.extend(credential_findings)
                if is_active and kind is ApplicationCredentialKind.PASSWORD:
                    active_passwords += 1
                if is_active and kind is ApplicationCredentialKind.KEY:
                    active_keys += 1
                expiring += int(is_expiring)
                expired += int(is_expired)

        for control_id, actual, maximum, kind in (
            (
                "APP_ACTIVE_PASSWORD_CREDENTIALS_EXCEED_MAXIMUM",
                active_passwords,
                target.maximum_active_password_credentials,
                ApplicationCredentialKind.PASSWORD,
            ),
            (
                "APP_ACTIVE_KEY_CREDENTIALS_EXCEED_MAXIMUM",
                active_keys,
                target.maximum_active_key_credentials,
                ApplicationCredentialKind.KEY,
            ),
        ):
            if (
                kind is ApplicationCredentialKind.PASSWORD
                and not target.password_credentials_allowed
            ):
                continue
            if actual > maximum:
                findings.append(
                    self._finding(
                        snapshot_reference=snapshot_reference,
                        baseline_reference=baseline_reference,
                        target_reference=target_reference,
                        target_id=target_id,
                        control_id=control_id,
                        severity="high",
                        operator_action=(
                            "Review credential use and remove redundant active "
                            "credentials through an approved admin workflow."
                        ),
                        exceptions=exceptions,
                        now=now,
                        kind=kind,
                    )
                )

        unexcepted = [
            item
            for item in findings
            if item.alignment is AlignmentStatus.NOT_ALIGNED
        ]
        exception_count = sum(
            item.alignment is AlignmentStatus.EXCEPTION_APPROVED
            for item in findings
        )
        if unexcepted:
            alignment = AlignmentStatus.NOT_ALIGNED
        elif exception_count:
            alignment = AlignmentStatus.EXCEPTION_APPROVED
        else:
            alignment = AlignmentStatus.ALIGNED

        digest = self.snapshots.domain_digest(
            tenant_id=self.settings.tenant_id,
            contract_id=CONTRACT_ID,
            domain=ApplicationCredentialSnapshotDomain.APPLICATIONS,
            records=[application, *owners],
        )
        return (
            ApplicationCredentialTargetPosture(
                target_reference=target_reference,
                workload_identity_reference=workload_identity_reference,
                baseline_reference=baseline_reference,
                digest=digest,
                alignment=alignment,
                owner_count=owner_count,
                minimum_owner_count=target.minimum_owner_count,
                password_credentials=len(application["passwordCredentials"]),
                key_credentials=len(application["keyCredentials"]),
                active_password_credentials=active_passwords,
                active_key_credentials=active_keys,
                expiring_credentials=expiring,
                expired_credentials=expired,
                approved_exceptions=exception_count,
            ),
            findings,
        )

    async def collect(self) -> ApplicationCredentialPostureReport:
        decision, baseline = (
            self.governance.authorize_application_credential_read(
                self.contract,
                tenant_id=self.settings.tenant_id,
                local_application_ids=self.settings.application_ids,
            )
        )
        domains: dict[
            ApplicationCredentialSnapshotDomain,
            list[dict[str, Any]],
        ] = {
            domain: []
            for domain in ApplicationCredentialSnapshotDomain
        }
        applications: dict[str, dict[str, Any]] = {}
        owners_by_application: dict[str, list[dict[str, str]]] = {}
        application_pages = 0
        owner_pages = 0
        for target in baseline.targets:
            target_id = str(target.application_id)
            application = await self._get_application(target_id)
            owners, pages = await self._get_owners(target_id)
            application_pages += 1
            owner_pages += pages
            if (
                application_pages > self.settings.assurance_max_pages_per_domain
                or owner_pages > self.settings.assurance_max_pages_per_domain
            ):
                raise SecurityError(
                    "application posture exceeded the runtime page bound"
                )
            applications[target_id] = application
            owners_by_application[target_id] = owners
            domains[
                ApplicationCredentialSnapshotDomain.APPLICATIONS
            ].append(application)
            domains[ApplicationCredentialSnapshotDomain.OWNERS].extend(owners)

        if any(
            len(records) > self.settings.assurance_max_records_per_domain
            for records in domains.values()
        ):
            raise SecurityError(
                "application posture exceeded the runtime record bound"
            )
        domains[ApplicationCredentialSnapshotDomain.APPLICATIONS].sort(
            key=lambda item: str(item["id"])
        )
        domains[ApplicationCredentialSnapshotDomain.OWNERS].sort(
            key=lambda item: (
                str(item["applicationId"]),
                str(item["ownerId"]),
            )
        )

        refreshed = self.governance.refresh()
        refreshed_decision, refreshed_baseline = (
            refreshed.authorize_application_credential_read(
                self.contract,
                tenant_id=self.settings.tenant_id,
                local_application_ids=self.settings.application_ids,
            )
        )
        if refreshed_decision != decision or refreshed_baseline != baseline:
            raise GovernancePolicyError(
                "governance authorization changed during application collection",
                reason_code="POLICY_CHANGED",
            )
        if decision.profile.value != "privileged-read":
            raise GovernancePolicyError(
                "application credential posture requires privileged-read",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )

        snapshot_id = uuid4()
        snapshot_reference = self.snapshots.store(
            snapshot_id=snapshot_id,
            contract_id=CONTRACT_ID,
            tenant_id=self.settings.tenant_id,
            domains=domains,
        )
        captured_at = datetime.now(UTC)
        baseline_reference = f"{baseline.baseline_id}:v{baseline.version}"
        target_results: list[ApplicationCredentialTargetPosture] = []
        findings: list[Finding] = []
        for target in baseline.targets:
            target_id = str(target.application_id)
            result, target_findings = self._classify_target(
                target=target,
                application=applications[target_id],
                owners=owners_by_application[target_id],
                snapshot_reference=snapshot_reference,
                baseline_reference=baseline_reference,
                exceptions=baseline.exceptions,
                now=captured_at,
            )
            target_results.append(result)
            findings.extend(target_findings)
        target_results.sort(key=lambda item: item.target_reference)
        findings.sort(
            key=lambda item: (
                SEVERITY_ORDER[item.severity],
                item.control_id,
                item.finding_id,
            )
        )
        return ApplicationCredentialPostureReport(
            contract_digest=sha256_digest(self.contract),
            contract_manifest_digest=sha256_digest(self.manifest),
            policy_digest=refreshed.policy_digest,
            snapshot_id=snapshot_id,
            snapshot_reference=snapshot_reference,
            captured_at=captured_at,
            tenant_namespace=self.settings.deployment_namespace,
            baseline_id=baseline.baseline_id,
            baseline_version=baseline.version,
            targets=target_results,
            findings=findings,
        )
