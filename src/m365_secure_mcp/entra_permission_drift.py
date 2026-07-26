"""Read-only drift detection for Entra delegated and application grants."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .assurance import AssuranceSnapshotStore
from .config import Settings
from .contract_manifest import ContractManifest, ContractSpec, sha256_digest
from .governance import (
    GovernancePolicyError,
    PermissionGrantBaseline,
    PermissionGrantKind,
    PermissionGrantTarget,
    VerifiedGovernancePolicy,
)
from .graph import GraphClient
from .operations import AlignmentStatus, Finding, ResponsibleParty
from .security import SecurityError, path_segment

CONTRACT_ID = "entra.permission_grants.drift.snapshot"
TOOL_NAME = "m365_get_entra_permission_grant_drift"
MICROSOFT_GRAPH_APP_ID = UUID("00000003-0000-0000-c000-000000000000")
OAUTH2_GRANTS_ENDPOINT = "/oauth2PermissionGrants"
SERVICE_PRINCIPAL_ENDPOINT = "/servicePrincipals/{service_principal_id}"
APP_ROLE_ASSIGNMENTS_ENDPOINT = (
    "/servicePrincipals/{service_principal_id}/appRoleAssignments"
)
MAX_PERMISSION_VALUE_LENGTH = 128
MAX_RESOURCE_CATALOGS = 250
PERMISSION_VALUE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class PermissionGrantSnapshotDomain(StrEnum):
    TARGETS = "targets"
    DELEGATED_GRANTS = "delegated_grants"
    APPLICATION_GRANTS = "application_grants"
    RESOURCE_CATALOG = "resource_catalog"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PermissionGrantTargetPosture(StrictModel):
    target_reference: str = Field(pattern=r"^sp:[0-9a-f]{24}$")
    baseline_reference: str = Field(min_length=3, max_length=128)
    contract_ids: list[str]
    digest: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    alignment: AlignmentStatus
    expected_delegated_permissions: int = Field(ge=0)
    observed_delegated_permissions: int = Field(ge=0)
    observed_application_permissions: int = Field(ge=0)
    missing_permissions: int = Field(ge=0)
    unexpected_permissions: int = Field(ge=0)
    approved_exceptions: int = Field(ge=0)


class PermissionGrantDriftReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["OBSERVED_COMPLETE"] = "OBSERVED_COMPLETE"
    contract_id: Literal["entra.permission_grants.drift.snapshot"] = (
        "entra.permission_grants.drift.snapshot"
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
    targets: list[PermissionGrantTargetPosture] = Field(
        min_length=1,
        max_length=100,
    )
    findings: list[Finding]
    writes_performed: Literal[False] = False
    admin_consent_is_manual: Literal[True] = True


@dataclass(frozen=True, order=True)
class ObservedPermission:
    target_id: str
    kind: PermissionGrantKind
    resource_id: str
    resource_app_id: str
    permission_value: str
    consent_type: str | None


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


def _permission_value(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_PERMISSION_VALUE_LENGTH
        or PERMISSION_VALUE_PATTERN.fullmatch(value) is None
    ):
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    return value


def _bounded_string(value: Any, *, field: str, max_length: int = 100) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or any(ord(character) < 32 for character in value)
    ):
        raise SecurityError(f"Microsoft Graph returned an invalid {field}")
    return value


class EntraPermissionGrantDriftService:
    """Compare exact signed contract expectations with complete Entra grants."""

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

    async def _collect_collection(
        self,
        endpoint: str,
        *,
        params: Mapping[str, str | int],
        remaining_records: int,
        remaining_pages: int,
    ) -> tuple[list[dict[str, Any]], int]:
        data = await self.graph.request_json("GET", endpoint, params=params)
        records: list[dict[str, Any]] = []
        pages = 0
        seen_next_links: set[str] = set()
        while True:
            pages += 1
            if pages > remaining_pages:
                raise SecurityError(
                    "permission-grant pagination exceeded the runtime bound"
                )
            raw_items = data.get("value")
            if not isinstance(raw_items, list):
                raise SecurityError(
                    "Microsoft Graph returned an invalid permission collection"
                )
            for raw_item in raw_items:
                if not isinstance(raw_item, dict):
                    raise SecurityError(
                        "Microsoft Graph returned an invalid permission record"
                    )
                records.append(raw_item)
                if len(records) > remaining_records:
                    raise SecurityError(
                        "permission-grant collection exceeded the runtime bound"
                    )
            next_link = data.get("@odata.nextLink")
            if next_link is None:
                break
            if (
                not isinstance(next_link, str)
                or next_link in seen_next_links
                or pages >= remaining_pages
            ):
                raise SecurityError(
                    "permission-grant pagination could not prove completeness"
                )
            seen_next_links.add(next_link)
            data = await self.graph.request_cursor(next_link)
        return records, pages

    async def _get_target(self, target_id: str) -> dict[str, Any]:
        safe_target = path_segment(target_id)
        data = await self.graph.request_json(
            "GET",
            f"/servicePrincipals/{safe_target}",
            params={
                "$select": (
                    "id,appId,servicePrincipalType,accountEnabled"
                )
            },
        )
        resolved_id = _uuid_text(data.get("id"), field="service principal ID")
        if resolved_id != target_id:
            raise SecurityError(
                "Microsoft Graph returned a different service principal"
            )
        account_enabled = data.get("accountEnabled")
        if not isinstance(account_enabled, bool):
            raise SecurityError(
                "Microsoft Graph returned an invalid service principal state"
            )
        return {
            "id": resolved_id,
            "appId": _uuid_text(
                data.get("appId"),
                field="service principal application ID",
            ),
            "servicePrincipalType": _bounded_string(
                data.get("servicePrincipalType"),
                field="service principal type",
            ),
            "accountEnabled": account_enabled,
        }

    async def _get_resource_catalog(
        self,
        resource_id: str,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        safe_resource = path_segment(resource_id)
        data = await self.graph.request_json(
            "GET",
            f"/servicePrincipals/{safe_resource}",
            params={"$select": "id,appId,appRoles"},
        )
        resolved_id = _uuid_text(
            data.get("id"),
            field="resource service principal ID",
        )
        if resolved_id != resource_id:
            raise SecurityError(
                "Microsoft Graph returned a different resource service principal"
            )
        app_id = _uuid_text(
            data.get("appId"),
            field="resource application ID",
        )
        raw_roles = data.get("appRoles")
        if not isinstance(raw_roles, list) or len(raw_roles) > 5_000:
            raise SecurityError(
                "Microsoft Graph returned an invalid app-role catalog"
            )
        role_values: dict[str, str] = {}
        normalized_roles: list[dict[str, str]] = []
        for raw_role in raw_roles:
            if not isinstance(raw_role, dict):
                raise SecurityError(
                    "Microsoft Graph returned an invalid app-role definition"
                )
            role_id = _uuid_text(raw_role.get("id"), field="app-role ID")
            raw_value = raw_role.get("value")
            if raw_value is None:
                continue
            value = _permission_value(raw_value, field="app-role value")
            if role_id in role_values:
                raise SecurityError(
                    "Microsoft Graph returned a duplicate app-role ID"
                )
            role_values[role_id] = value
            normalized_roles.append({"id": role_id, "value": value})
        normalized_roles.sort(key=lambda item: (item["value"], item["id"]))
        return (
            {
                "id": resolved_id,
                "appId": app_id,
                "appRoles": normalized_roles,
            },
            role_values,
        )

    async def _collect_target_permissions(
        self,
        target: PermissionGrantTarget,
        *,
        domain_counts: dict[PermissionGrantSnapshotDomain, int],
        domain_pages: dict[PermissionGrantSnapshotDomain, int],
        resource_cache: dict[str, tuple[dict[str, Any], dict[str, str]]],
    ) -> tuple[
        dict[str, Any],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[ObservedPermission],
    ]:
        target_id = str(target.service_principal_id)
        target_record = await self._get_target(target_id)
        delegated_raw, delegated_pages = await self._collect_collection(
            OAUTH2_GRANTS_ENDPOINT,
            params={
                "$filter": f"clientId eq '{target_id}'",
                "$select": (
                    "id,clientId,consentType,principalId,resourceId,scope"
                ),
            },
            remaining_records=(
                self.settings.assurance_max_records_per_domain
                - domain_counts[
                    PermissionGrantSnapshotDomain.DELEGATED_GRANTS
                ]
            ),
            remaining_pages=(
                self.settings.assurance_max_pages_per_domain
                - domain_pages[
                    PermissionGrantSnapshotDomain.DELEGATED_GRANTS
                ]
            ),
        )
        safe_target = path_segment(target_id)
        application_raw, application_pages = await self._collect_collection(
            f"/servicePrincipals/{safe_target}/appRoleAssignments",
            params={
                "$select": (
                    "id,principalId,resourceId,appRoleId"
                )
            },
            remaining_records=(
                self.settings.assurance_max_records_per_domain
                - domain_counts[
                    PermissionGrantSnapshotDomain.APPLICATION_GRANTS
                ]
            ),
            remaining_pages=(
                self.settings.assurance_max_pages_per_domain
                - domain_pages[
                    PermissionGrantSnapshotDomain.APPLICATION_GRANTS
                ]
            ),
        )

        resource_ids: set[str] = set()
        normalized_delegated: list[dict[str, Any]] = []
        for grant in delegated_raw:
            grant_client = _uuid_text(
                grant.get("clientId"),
                field="delegated grant client ID",
            )
            if grant_client != target_id:
                raise SecurityError(
                    "Microsoft Graph returned a grant for a different client"
                )
            resource_id = _uuid_text(
                grant.get("resourceId"),
                field="delegated grant resource ID",
            )
            consent_type = _bounded_string(
                grant.get("consentType"),
                field="delegated consent type",
            )
            if consent_type not in {"AllPrincipals", "Principal"}:
                raise SecurityError(
                    "Microsoft Graph returned an unknown delegated consent type"
                )
            principal_id = grant.get("principalId")
            if consent_type == "Principal":
                principal_id = _uuid_text(
                    principal_id,
                    field="delegated grant principal ID",
                )
            elif principal_id is not None:
                raise SecurityError(
                    "tenant-wide delegated grant unexpectedly names a principal"
                )
            raw_scope = grant.get("scope")
            if not isinstance(raw_scope, str) or len(raw_scope) > 3_850:
                raise SecurityError(
                    "Microsoft Graph returned an invalid delegated scope list"
                )
            scopes = sorted(
                {
                    _permission_value(item, field="delegated scope")
                    for item in raw_scope.split()
                }
            )
            resource_ids.add(resource_id)
            normalized_delegated.append(
                {
                    "id": _bounded_string(
                        grant.get("id"),
                        field="delegated grant ID",
                        max_length=256,
                    ),
                    "clientId": grant_client,
                    "consentType": consent_type,
                    "principalId": principal_id,
                    "resourceId": resource_id,
                    "scopes": scopes,
                }
            )

        normalized_application: list[dict[str, Any]] = []
        for assignment in application_raw:
            principal_id = _uuid_text(
                assignment.get("principalId"),
                field="app-role assignment principal ID",
            )
            if principal_id != target_id:
                raise SecurityError(
                    "Microsoft Graph returned an app role for a different client"
                )
            resource_id = _uuid_text(
                assignment.get("resourceId"),
                field="app-role assignment resource ID",
            )
            resource_ids.add(resource_id)
            normalized_application.append(
                {
                    "id": _bounded_string(
                        assignment.get("id"),
                        field="app-role assignment ID",
                        max_length=256,
                    ),
                    "principalId": principal_id,
                    "resourceId": resource_id,
                    "appRoleId": _uuid_text(
                        assignment.get("appRoleId"),
                        field="assigned app-role ID",
                    ),
                }
            )

        for resource_id in sorted(resource_ids):
            if resource_id not in resource_cache:
                if len(resource_cache) >= min(
                    self.settings.assurance_max_records_per_domain,
                    MAX_RESOURCE_CATALOGS,
                ):
                    raise SecurityError(
                        "permission resource catalog exceeded the runtime bound"
                    )
                resource_cache[resource_id] = await self._get_resource_catalog(
                    resource_id
                )

        observed: list[ObservedPermission] = []
        for grant in normalized_delegated:
            resource = resource_cache[str(grant["resourceId"])][0]
            for scope in grant["scopes"]:
                observed.append(
                    ObservedPermission(
                        target_id=target_id,
                        kind=PermissionGrantKind.DELEGATED,
                        resource_id=str(grant["resourceId"]),
                        resource_app_id=str(resource["appId"]),
                        permission_value=str(scope),
                        consent_type=str(grant["consentType"]),
                    )
                )
        for assignment in normalized_application:
            resource, role_values = resource_cache[
                str(assignment["resourceId"])
            ]
            app_role_id = str(assignment["appRoleId"])
            permission = role_values.get(app_role_id)
            if permission is None:
                raise SecurityError(
                    "an assigned app role is absent from its resource catalog"
                )
            observed.append(
                ObservedPermission(
                    target_id=target_id,
                    kind=PermissionGrantKind.APPLICATION,
                    resource_id=str(assignment["resourceId"]),
                    resource_app_id=str(resource["appId"]),
                    permission_value=permission,
                    consent_type=None,
                )
            )

        normalized_delegated.sort(
            key=lambda item: (
                str(item["resourceId"]),
                str(item["consentType"]),
                str(item["id"]),
            )
        )
        normalized_application.sort(
            key=lambda item: (
                str(item["resourceId"]),
                str(item["appRoleId"]),
                str(item["id"]),
            )
        )
        domain_counts[
            PermissionGrantSnapshotDomain.DELEGATED_GRANTS
        ] += len(normalized_delegated)
        domain_counts[
            PermissionGrantSnapshotDomain.APPLICATION_GRANTS
        ] += len(normalized_application)
        domain_pages[
            PermissionGrantSnapshotDomain.DELEGATED_GRANTS
        ] += delegated_pages
        domain_pages[
            PermissionGrantSnapshotDomain.APPLICATION_GRANTS
        ] += application_pages
        return (
            target_record,
            normalized_delegated,
            normalized_application,
            sorted(set(observed)),
        )

    def _expected_scopes(
        self,
        target: PermissionGrantTarget,
    ) -> set[str]:
        expected = {"User.Read"}
        for contract_id in target.contract_ids:
            expected.update(
                self.manifest.contract(
                    contract_id
                ).permissions.delegated_scopes
            )
        return expected

    def _active_exceptions(
        self,
        baseline: PermissionGrantBaseline,
        *,
        now: datetime,
    ) -> set[tuple[str, PermissionGrantKind, str, str, str | None]]:
        return {
            (
                str(item.service_principal_id),
                item.kind,
                str(item.resource_app_id),
                item.permission_value,
                item.consent_type,
            )
            for item in baseline.exceptions
            if item.expires_at > now
        }

    def _resource_reference(self, resource_app_id: str) -> str:
        if resource_app_id == str(MICROSOFT_GRAPH_APP_ID):
            return "microsoft-graph"
        return self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="api",
            resource_id=resource_app_id,
        )

    def _finding(
        self,
        *,
        snapshot_reference: str,
        baseline_reference: str,
        target_reference: str,
        control_id: str,
        severity: str,
        permission: str,
        resource_reference: str,
        operator_action: str,
        alignment: AlignmentStatus,
    ) -> Finding:
        finding_reference = self.snapshots.resource_reference(
            tenant_id=self.settings.tenant_id,
            category="finding",
            resource_id=(
                f"{target_reference}:{control_id}:"
                f"{resource_reference}:{permission}"
            ),
        )
        return Finding(
            finding_id=finding_reference,
            control_id=control_id,
            status=alignment.value,
            severity=severity,
            summary=(
                f"{permission} on {resource_reference} for "
                f"{target_reference}: {control_id.lower().replace('_', ' ')}."
            ),
            evidence_reference=snapshot_reference,
            alignment=alignment,
            operator_action=operator_action,
            responsible_party=(
                ResponsibleParty.GOVERNANCE_OWNER
                if alignment is AlignmentStatus.EXCEPTION_APPROVED
                else ResponsibleParty.TENANT_ADMIN
            ),
            baseline_reference=baseline_reference,
        )

    def _classify_target(
        self,
        *,
        target: PermissionGrantTarget,
        observed: list[ObservedPermission],
        snapshot_reference: str,
        target_reference: str,
        baseline_reference: str,
        active_exceptions: set[
            tuple[str, PermissionGrantKind, str, str, str | None]
        ],
    ) -> tuple[PermissionGrantTargetPosture, list[Finding]]:
        target_id = str(target.service_principal_id)
        expected_scopes = self._expected_scopes(target)
        actual_delegated = {
            (
                item.resource_app_id,
                item.permission_value,
                item.consent_type,
            )
            for item in observed
            if item.kind is PermissionGrantKind.DELEGATED
        }
        actual_application = {
            (item.resource_app_id, item.permission_value)
            for item in observed
            if item.kind is PermissionGrantKind.APPLICATION
        }
        allowed_consent_types = set(target.allowed_delegated_consent_types)
        findings: list[Finding] = []
        missing_count = 0
        unexpected_count = 0
        exception_count = 0

        for scope in sorted(expected_scopes):
            matching = {
                consent_type
                for resource_app_id, permission, consent_type in actual_delegated
                if (
                    resource_app_id == str(MICROSOFT_GRAPH_APP_ID)
                    and permission == scope
                )
            }
            if not matching:
                missing_count += 1
                findings.append(
                    self._finding(
                        snapshot_reference=snapshot_reference,
                        baseline_reference=baseline_reference,
                        target_reference=target_reference,
                        control_id="PERMISSION_EXPECTED_MISSING",
                        severity="medium",
                        permission=scope,
                        resource_reference="microsoft-graph",
                        operator_action=(
                            "Have the tenant administrator verify manual consent "
                            "for the signed contracts or update the private baseline."
                        ),
                        alignment=AlignmentStatus.NOT_ALIGNED,
                    )
                )

        for resource_app_id, permission, consent_type in sorted(
            actual_delegated
        ):
            expected = (
                resource_app_id == str(MICROSOFT_GRAPH_APP_ID)
                and permission in expected_scopes
            )
            consent_allowed = consent_type in allowed_consent_types
            if expected and consent_allowed:
                continue
            exception_key = (
                target_id,
                PermissionGrantKind.DELEGATED,
                resource_app_id,
                permission,
                consent_type,
            )
            excepted = exception_key in active_exceptions
            if excepted:
                exception_count += 1
            else:
                unexpected_count += 1
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    control_id=(
                        "PERMISSION_DELEGATED_UNEXPECTED"
                        if not expected
                        else "PERMISSION_CONSENT_TYPE_MISMATCH"
                    ),
                    severity="high" if not expected else "medium",
                    permission=permission,
                    resource_reference=self._resource_reference(
                        resource_app_id
                    ),
                    operator_action=(
                        "No automatic remediation is available. Review the "
                        "grant in Entra and either revoke it manually or add an "
                        "exact, expiring exception to signed Governance."
                    ),
                    alignment=(
                        AlignmentStatus.EXCEPTION_APPROVED
                        if excepted
                        else AlignmentStatus.NOT_ALIGNED
                    ),
                )
            )

        for resource_app_id, permission in sorted(actual_application):
            exception_key = (
                target_id,
                PermissionGrantKind.APPLICATION,
                resource_app_id,
                permission,
                None,
            )
            excepted = exception_key in active_exceptions
            if excepted:
                exception_count += 1
            else:
                unexpected_count += 1
            findings.append(
                self._finding(
                    snapshot_reference=snapshot_reference,
                    baseline_reference=baseline_reference,
                    target_reference=target_reference,
                    control_id="PERMISSION_APPLICATION_UNEXPECTED",
                    severity="critical",
                    permission=permission,
                    resource_reference=self._resource_reference(
                        resource_app_id
                    ),
                    operator_action=(
                        "No compiled contract requires application permissions. "
                        "Have the tenant administrator review and revoke the "
                        "assignment manually, or sign an exact expiring exception."
                    ),
                    alignment=(
                        AlignmentStatus.EXCEPTION_APPROVED
                        if excepted
                        else AlignmentStatus.NOT_ALIGNED
                    ),
                )
            )

        if missing_count or unexpected_count:
            alignment = AlignmentStatus.NOT_ALIGNED
        elif exception_count:
            alignment = AlignmentStatus.EXCEPTION_APPROVED
        else:
            alignment = AlignmentStatus.ALIGNED

        digest_records = [
            {
                "kind": item.kind.value,
                "resource_app_id": item.resource_app_id,
                "permission": item.permission_value,
                "consent_type": item.consent_type,
            }
            for item in observed
        ]
        digest = self.snapshots.domain_digest(
            tenant_id=self.settings.tenant_id,
            contract_id=CONTRACT_ID,
            domain=PermissionGrantSnapshotDomain.DELEGATED_GRANTS,
            records=digest_records,
        )
        return (
            PermissionGrantTargetPosture(
                target_reference=target_reference,
                baseline_reference=baseline_reference,
                contract_ids=target.contract_ids,
                digest=digest,
                alignment=alignment,
                expected_delegated_permissions=len(expected_scopes),
                observed_delegated_permissions=len(actual_delegated),
                observed_application_permissions=len(actual_application),
                missing_permissions=missing_count,
                unexpected_permissions=unexpected_count,
                approved_exceptions=exception_count,
            ),
            findings,
        )

    async def collect(self) -> PermissionGrantDriftReport:
        decision, baseline = self.governance.authorize_permission_grant_read(
            self.contract,
            tenant_id=self.settings.tenant_id,
            local_service_principal_ids=self.settings.service_principal_ids,
        )
        domains: dict[
            PermissionGrantSnapshotDomain,
            list[dict[str, Any]],
        ] = {
            domain: []
            for domain in PermissionGrantSnapshotDomain
        }
        domain_counts = {
            domain: 0
            for domain in PermissionGrantSnapshotDomain
        }
        domain_pages = {
            domain: 0
            for domain in PermissionGrantSnapshotDomain
        }
        resource_cache: dict[
            str,
            tuple[dict[str, Any], dict[str, str]],
        ] = {}
        observed_by_target: dict[str, list[ObservedPermission]] = {}
        for target in baseline.targets:
            (
                target_record,
                delegated,
                application,
                observed,
            ) = await self._collect_target_permissions(
                target,
                domain_counts=domain_counts,
                domain_pages=domain_pages,
                resource_cache=resource_cache,
            )
            domains[PermissionGrantSnapshotDomain.TARGETS].append(
                target_record
            )
            domains[PermissionGrantSnapshotDomain.DELEGATED_GRANTS].extend(
                delegated
            )
            domains[PermissionGrantSnapshotDomain.APPLICATION_GRANTS].extend(
                application
            )
            observed_by_target[str(target.service_principal_id)] = observed

        domains[PermissionGrantSnapshotDomain.RESOURCE_CATALOG] = sorted(
            (
                value[0]
                for value in resource_cache.values()
            ),
            key=lambda item: str(item["id"]),
        )
        domain_counts[PermissionGrantSnapshotDomain.TARGETS] = len(
            domains[PermissionGrantSnapshotDomain.TARGETS]
        )
        domain_counts[
            PermissionGrantSnapshotDomain.RESOURCE_CATALOG
        ] = len(domains[PermissionGrantSnapshotDomain.RESOURCE_CATALOG])
        if any(
            count > self.settings.assurance_max_records_per_domain
            for count in domain_counts.values()
        ):
            raise SecurityError(
                "permission-grant snapshot exceeded the runtime bound"
            )

        refreshed = self.governance.refresh()
        refreshed_decision, refreshed_baseline = (
            refreshed.authorize_permission_grant_read(
                self.contract,
                tenant_id=self.settings.tenant_id,
                local_service_principal_ids=self.settings.service_principal_ids,
            )
        )
        if (
            refreshed_decision != decision
            or refreshed_baseline != baseline
        ):
            raise GovernancePolicyError(
                "governance authorization changed during permission collection",
                reason_code="POLICY_CHANGED",
            )

        snapshot_id = uuid4()
        snapshot_reference = self.snapshots.store(
            snapshot_id=snapshot_id,
            contract_id=CONTRACT_ID,
            tenant_id=self.settings.tenant_id,
            domains=domains,
        )
        baseline_reference = f"{baseline.baseline_id}:v{baseline.version}"
        active_exceptions = self._active_exceptions(
            baseline,
            now=datetime.now(UTC),
        )
        target_results: list[PermissionGrantTargetPosture] = []
        findings: list[Finding] = []
        for target in baseline.targets:
            target_id = str(target.service_principal_id)
            target_reference = self.snapshots.resource_reference(
                tenant_id=self.settings.tenant_id,
                category="sp",
                resource_id=target_id,
            )
            result, target_findings = self._classify_target(
                target=target,
                observed=observed_by_target[target_id],
                snapshot_reference=snapshot_reference,
                target_reference=target_reference,
                baseline_reference=baseline_reference,
                active_exceptions=active_exceptions,
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
        if decision.profile.value != "privileged-read":
            raise GovernancePolicyError(
                "permission-grant drift requires privileged-read",
                reason_code="PROFILE_CONTRACT_MISMATCH",
            )
        return PermissionGrantDriftReport(
            contract_digest=sha256_digest(self.contract),
            contract_manifest_digest=sha256_digest(self.manifest),
            policy_digest=refreshed.policy_digest,
            snapshot_id=snapshot_id,
            snapshot_reference=snapshot_reference,
            captured_at=datetime.now(UTC),
            tenant_namespace=self.settings.deployment_namespace,
            baseline_id=baseline.baseline_id,
            baseline_version=baseline.version,
            targets=target_results,
            findings=findings,
        )
