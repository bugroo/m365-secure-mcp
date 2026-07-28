"""Closed Identity Slice providers for the common ChangeSafeOperator.

The providers are not registered while the schema-2.0 manifest remains an
unsigned candidate. Every Graph path, method, query and body shape below is
fixed code selected by one compiled contract ID.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .contract_manifest import canonical_json
from .governance import GovernanceResources
from .graph import GraphClient, GraphError
from .operator_authority import OperatorPlan, PreconditionBinding
from .operator_lifecycle import (
    OperationProvider,
    ProviderExecutionKind,
    ProviderExecutionResult,
    ProviderObservationKind,
    ProviderObservationResult,
    ProviderTransportError,
)
from .security import SecurityError, path_segment


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class UserProtectionEvidence(FrozenModel):
    user_id: UUID
    user_type: str
    account_enabled: bool
    on_premises_sync_enabled: bool | None
    usage_location: str | None
    active_role_assignments: int = Field(ge=0)
    active_role_schedule_instances: int = Field(ge=0)
    eligible_role_schedule_instances: int = Field(ge=0)
    role_assignable_group_memberships: int = Field(ge=0)
    evidence_complete: bool
    direct_sku_ids: tuple[UUID, ...] = ()
    inherited_sku_ids: tuple[UUID, ...] = ()


class GroupProtectionEvidence(FrozenModel):
    group_id: UUID
    dynamic: bool
    role_assignable: bool
    evidence_complete: bool


class SkuCapacityEvidence(FrozenModel):
    sku_id: UUID
    enabled_units: int = Field(ge=0)
    consumed_units: int = Field(ge=0)
    service_plan_ids: tuple[UUID, ...]
    evidence_complete: bool

    @property
    def available_units(self) -> int:
        return max(self.enabled_units - self.consumed_units, 0)


class ClosedIdentityBackend(Protocol):
    async def read_user(self, user_id: UUID) -> UserProtectionEvidence: ...

    async def read_group(self, group_id: UUID) -> GroupProtectionEvidence: ...

    async def membership_exists(self, group_id: UUID, user_id: UUID) -> bool: ...

    async def read_sku(self, sku_id: UUID) -> SkuCapacityEvidence: ...

    async def revoke_sessions(self, user_id: UUID) -> bool: ...

    async def set_account_enabled(self, user_id: UUID, enabled: bool) -> None: ...

    async def add_membership(self, group_id: UUID, user_id: UUID) -> None: ...

    async def remove_membership(self, group_id: UUID, user_id: UUID) -> None: ...

    async def set_direct_license(
        self,
        user_id: UUID,
        sku_id: UUID,
        *,
        assigned: bool,
        disabled_service_plan_ids: tuple[UUID, ...],
    ) -> None: ...


def _digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(value)).hexdigest()}"


def _parameters(plan: OperatorPlan) -> dict[str, str | bool | int | tuple[str, ...]]:
    return {item.name: item.value for item in plan.parameters}


def _uuid_parameter(parameters: Mapping[str, object], name: str) -> UUID:
    value = parameters.get(name)
    if not isinstance(value, str):
        raise SecurityError("Identity plan is missing an exact UUID parameter")
    try:
        return UUID(value)
    except ValueError as exc:
        raise SecurityError("Identity plan contains an invalid UUID parameter") from exc


class MicrosoftGraphIdentityBackend:
    """Exact Graph v1.0 adapter; it exposes no generic request surface."""

    def __init__(self, graph: GraphClient) -> None:
        self.graph = graph

    async def _role_count(self, endpoint: str, user_id: UUID) -> int:
        data = await self.graph.request_json(
            "GET",
            endpoint,
            params={
                "$filter": f"principalId eq '{user_id}'",
                "$select": "id,principalId",
                "$top": 1,
            },
        )
        value = data.get("value")
        if not isinstance(value, list) or data.get("@odata.nextLink"):
            raise SecurityError("privileged-role evidence is incomplete")
        return len(value)

    async def read_user(self, user_id: UUID) -> UserProtectionEvidence:
        safe = path_segment(str(user_id))
        data = await self.graph.request_json(
            "GET",
            f"/users/{safe}",
            params={
                "$select": (
                    "id,userType,accountEnabled,onPremisesSyncEnabled,"
                    "usageLocation,assignedLicenses,licenseAssignmentStates"
                )
            },
        )
        if str(data.get("id", "")).lower() != str(user_id):
            raise SecurityError("Graph returned another user")
        account_enabled = data.get("accountEnabled")
        sync = data.get("onPremisesSyncEnabled")
        if not isinstance(account_enabled, bool) or sync not in {True, False, None}:
            raise SecurityError("Graph returned invalid user protection evidence")
        direct: set[UUID] = set()
        inherited: set[UUID] = set()
        states = data.get("licenseAssignmentStates")
        if states is not None and not isinstance(states, list):
            raise SecurityError("Graph returned invalid license assignment evidence")
        for state in states or []:
            if not isinstance(state, dict):
                raise SecurityError("Graph returned invalid license assignment evidence")
            try:
                sku = UUID(str(state["skuId"]))
            except (KeyError, ValueError) as exc:
                raise SecurityError("Graph returned invalid license SKU evidence") from exc
            if state.get("assignedByGroup"):
                inherited.add(sku)
            else:
                direct.add(sku)
        group_roles = await self.graph.request_json(
            "GET",
            f"/users/{safe}/transitiveMemberOf/microsoft.graph.group",
            params={
                "$count": "true",
                "$filter": "isAssignableToRole eq true",
                "$select": "id",
                "$top": 1,
            },
            headers={"ConsistencyLevel": "eventual"},
        )
        group_values = group_roles.get("value")
        if not isinstance(group_values, list) or group_roles.get("@odata.nextLink"):
            raise SecurityError("group-derived role evidence is incomplete")
        return UserProtectionEvidence(
            user_id=user_id,
            user_type=str(data.get("userType", "")),
            account_enabled=account_enabled,
            on_premises_sync_enabled=sync,
            usage_location=(
                str(data["usageLocation"]) if data.get("usageLocation") else None
            ),
            active_role_assignments=await self._role_count(
                "/roleManagement/directory/roleAssignments",
                user_id,
            ),
            active_role_schedule_instances=await self._role_count(
                "/roleManagement/directory/roleAssignmentScheduleInstances",
                user_id,
            ),
            eligible_role_schedule_instances=await self._role_count(
                "/roleManagement/directory/roleEligibilityScheduleInstances",
                user_id,
            ),
            role_assignable_group_memberships=len(group_values),
            evidence_complete=True,
            direct_sku_ids=tuple(sorted(direct, key=str)),
            inherited_sku_ids=tuple(sorted(inherited, key=str)),
        )

    async def read_group(self, group_id: UUID) -> GroupProtectionEvidence:
        data = await self.graph.request_json(
            "GET",
            f"/groups/{path_segment(str(group_id))}",
            params={"$select": "id,groupTypes,isAssignableToRole"},
        )
        if str(data.get("id", "")).lower() != str(group_id):
            raise SecurityError("Graph returned another group")
        group_types = data.get("groupTypes")
        role_assignable = data.get("isAssignableToRole")
        if not isinstance(group_types, list) or role_assignable not in {
            True,
            False,
            None,
        }:
            raise SecurityError("Graph returned invalid group protection evidence")
        return GroupProtectionEvidence(
            group_id=group_id,
            dynamic="DynamicMembership" in group_types,
            role_assignable=role_assignable is True,
            evidence_complete=True,
        )

    async def membership_exists(self, group_id: UUID, user_id: UUID) -> bool:
        try:
            data = await self.graph.request_json(
                "GET",
                (
                    f"/groups/{path_segment(str(group_id))}/members/"
                    f"{path_segment(str(user_id))}"
                ),
                params={"$select": "id"},
            )
        except GraphError as exc:
            if exc.failure is not None and exc.failure.status_code == 404:
                return False
            raise
        return str(data.get("id", "")).lower() == str(user_id)

    async def read_sku(self, sku_id: UUID) -> SkuCapacityEvidence:
        data = await self.graph.request_json(
            "GET",
            "/subscribedSkus",
            params={"$select": "skuId,prepaidUnits,consumedUnits,servicePlans"},
        )
        values = data.get("value")
        if not isinstance(values, list) or data.get("@odata.nextLink"):
            raise SecurityError("subscribed SKU evidence is incomplete")
        for value in values:
            if not isinstance(value, dict) or str(value.get("skuId", "")).lower() != str(
                sku_id
            ):
                continue
            prepaid = value.get("prepaidUnits")
            service_plans = value.get("servicePlans")
            consumed = value.get("consumedUnits")
            if (
                not isinstance(prepaid, dict)
                or not isinstance(service_plans, list)
                or not isinstance(consumed, int)
                or not isinstance(prepaid.get("enabled"), int)
            ):
                raise SecurityError("Graph returned invalid SKU capacity evidence")
            try:
                plan_ids = tuple(
                    sorted(
                        (UUID(str(item["servicePlanId"])) for item in service_plans),
                        key=str,
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise SecurityError("Graph returned invalid service-plan evidence") from exc
            return SkuCapacityEvidence(
                sku_id=sku_id,
                enabled_units=prepaid["enabled"],
                consumed_units=consumed,
                service_plan_ids=plan_ids,
                evidence_complete=True,
            )
        raise SecurityError("planned SKU is not present in the tenant")

    async def revoke_sessions(self, user_id: UUID) -> bool:
        data = await self.graph.request_json(
            "POST",
            f"/users/{path_segment(str(user_id))}/revokeSignInSessions",
            json_body={},
        )
        return data.get("value") is True

    async def set_account_enabled(self, user_id: UUID, enabled: bool) -> None:
        await self.graph.request_json(
            "PATCH",
            f"/users/{path_segment(str(user_id))}",
            json_body={"accountEnabled": enabled},
        )

    async def add_membership(self, group_id: UUID, user_id: UUID) -> None:
        await self.graph.request_json(
            "POST",
            f"/groups/{path_segment(str(group_id))}/members/$ref",
            json_body={
                "@odata.id": (
                    "https://graph.microsoft.com/v1.0/directoryObjects/"
                    f"{path_segment(str(user_id))}"
                )
            },
        )

    async def remove_membership(self, group_id: UUID, user_id: UUID) -> None:
        await self.graph.remove_exact_group_member_reference(
            str(group_id),
            str(user_id),
        )

    async def set_direct_license(
        self,
        user_id: UUID,
        sku_id: UUID,
        *,
        assigned: bool,
        disabled_service_plan_ids: tuple[UUID, ...],
    ) -> None:
        add_licenses: list[dict[str, object]] = []
        remove_licenses: list[str] = []
        if assigned:
            add_licenses.append(
                {
                    "skuId": str(sku_id),
                    "disabledPlans": [
                        str(item) for item in disabled_service_plan_ids
                    ],
                }
            )
        else:
            remove_licenses.append(str(sku_id))
        await self.graph.request_json(
            "POST",
            f"/users/{path_segment(str(user_id))}/assignLicense",
            json_body={
                "addLicenses": add_licenses,
                "removeLicenses": remove_licenses,
            },
        )


class IdentityOperationProvider(OperationProvider):
    """One exact candidate contract provider, used only after catalog activation."""

    def __init__(
        self,
        *,
        backend: ClosedIdentityBackend,
        resources: GovernanceResources,
        operation_id: str,
    ) -> None:
        self.backend = backend
        self.resources = resources
        self.operation_id = operation_id

    @property
    def supports_cancellation(self) -> bool:
        return False

    async def cancel(self, observation_handle: str) -> ProviderObservationResult:
        del observation_handle
        raise SecurityError("Identity operation cancellation is not supported")

    def _check_plan(self, plan: OperatorPlan) -> tuple[UUID, dict[str, object]]:
        if (
            plan.operation_id != self.operation_id
            or plan.contract_id != self.operation_id
            or plan.target.resource_type.value != "user"
        ):
            raise SecurityError("Identity provider received another exact contract")
        user_id = plan.target.object_id
        if user_id not in self.resources.users:
            raise SecurityError("Identity target is outside the signed user allowlist")
        if user_id in {
            *self.resources.protected_user_ids,
            *self.resources.break_glass_user_ids,
            *self.resources.emergency_access_user_ids,
        }:
            raise SecurityError("Identity target is protected")
        return user_id, dict(_parameters(plan))

    async def _snapshot(self, plan: OperatorPlan) -> dict[str, object]:
        user_id, parameters = self._check_plan(plan)
        user = await self.backend.read_user(user_id)
        if (
            not user.evidence_complete
            or user.user_type != "Member"
            or user.on_premises_sync_enabled is True
            or user.active_role_assignments
            or user.active_role_schedule_instances
            or user.eligible_role_schedule_instances
            or user.role_assignable_group_memberships
        ):
            raise SecurityError("Identity target protection evidence failed closed")
        snapshot: dict[str, object] = {
            "operation_id": self.operation_id,
            "user": user.model_dump(mode="json"),
        }
        if "membership" in self.operation_id:
            group_id = _uuid_parameter(parameters, "group_id")
            if (
                group_id not in self.resources.groups
                or group_id in self.resources.protected_group_ids
            ):
                raise SecurityError("group is outside the signed safe fence")
            group = await self.backend.read_group(group_id)
            if not group.evidence_complete or group.dynamic or group.role_assignable:
                raise SecurityError("group protection evidence failed closed")
            snapshot["group"] = group.model_dump(mode="json")
            snapshot["membership_exists"] = await self.backend.membership_exists(
                group_id,
                user_id,
            )
        if self.operation_id == "entra.user.direct_license.set":
            sku_id = _uuid_parameter(parameters, "sku_id")
            if sku_id not in self.resources.allowed_sku_ids:
                raise SecurityError("license SKU is outside signed Governance")
            allowed_plans = set(
                self.resources.allowed_service_plan_ids.get(sku_id, [])
            )
            raw_plans = parameters.get("disabled_service_plan_ids")
            if not isinstance(raw_plans, tuple):
                raise SecurityError("license plan lacks a fixed service-plan set")
            planned = {_uuid_parameter({"value": item}, "value") for item in raw_plans}
            if planned - allowed_plans:
                raise SecurityError("license plan includes a non-allowlisted service plan")
            sku = await self.backend.read_sku(sku_id)
            desired = parameters.get("license_assigned")
            if not isinstance(desired, bool):
                raise SecurityError("license plan lacks an exact desired state")
            if (
                not sku.evidence_complete
                or planned - set(sku.service_plan_ids)
                or (desired and sku_id not in user.direct_sku_ids and sku.available_units < 1)
                or (desired and not user.usage_location)
                or (not desired and sku_id in user.inherited_sku_ids)
            ):
                raise SecurityError("license preconditions failed closed")
            snapshot["sku"] = sku.model_dump(mode="json")
        return snapshot

    async def preflight(
        self,
        plan: OperatorPlan,
    ) -> tuple[PreconditionBinding, ...]:
        snapshot = await self._snapshot(plan)
        return (
            PreconditionBinding(
                check_id="identity.complete_protected_snapshot",
                evidence_digest=_digest(snapshot),
            ),
        )

    async def execute(self, plan: OperatorPlan) -> ProviderExecutionResult:
        user_id, parameters = self._check_plan(plan)
        before = await self._snapshot(plan)
        evidence = _digest(before).removeprefix("sha256:")
        try:
            if self.operation_id == "entra.user.sessions.revoke":
                accepted = await self.backend.revoke_sessions(user_id)
                if not accepted:
                    return ProviderExecutionResult(
                        kind=ProviderExecutionKind.UNCERTAIN,
                        evidence_reference=f"evidence:{evidence}",
                    )
                return ProviderExecutionResult(
                    kind=ProviderExecutionKind.ACCEPTED,
                    evidence_reference=f"evidence:{evidence}",
                    observation_handle=f"observation:{evidence}",
                )
            if self.operation_id == "entra.user.account_state.set":
                desired = parameters.get("account_enabled")
                if not isinstance(desired, bool):
                    raise SecurityError("account-state plan lacks desired state")
                if bool(before["user"]["account_enabled"]) == desired:  # type: ignore[index]
                    return ProviderExecutionResult(
                        kind=ProviderExecutionKind.VERIFIED,
                        evidence_reference=f"evidence:{evidence}",
                    )
                await self.backend.set_account_enabled(user_id, desired)
            elif "membership" in self.operation_id:
                group_id = _uuid_parameter(parameters, "group_id")
                exists = bool(before["membership_exists"])
                add = self.operation_id.endswith(".add")
                if exists == add:
                    return ProviderExecutionResult(
                        kind=ProviderExecutionKind.VERIFIED,
                        evidence_reference=f"evidence:{evidence}",
                    )
                if add:
                    await self.backend.add_membership(group_id, user_id)
                else:
                    await self.backend.remove_membership(group_id, user_id)
            elif self.operation_id == "entra.user.direct_license.set":
                sku_id = _uuid_parameter(parameters, "sku_id")
                desired = parameters.get("license_assigned")
                raw = parameters.get("disabled_service_plan_ids")
                if not isinstance(desired, bool) or not isinstance(raw, tuple):
                    raise SecurityError("license plan is incomplete")
                direct = {
                    UUID(item)
                    for item in before["user"]["direct_sku_ids"]  # type: ignore[index]
                }
                if (sku_id in direct) == desired:
                    return ProviderExecutionResult(
                        kind=ProviderExecutionKind.VERIFIED,
                        evidence_reference=f"evidence:{evidence}",
                    )
                await self.backend.set_direct_license(
                    user_id,
                    sku_id,
                    assigned=desired,
                    disabled_service_plan_ids=tuple(UUID(item) for item in raw),
                )
            else:
                raise SecurityError("Identity executor ID is not closed")
        except GraphError as exc:
            raise ProviderTransportError(
                "Identity Graph operation failed",
                commit_possible=exc.write_may_have_committed,
            ) from exc
        after = await self._snapshot(plan)
        if self.operation_id == "entra.user.account_state.set":
            verified = (
                after["user"]["account_enabled"]  # type: ignore[index]
                == parameters["account_enabled"]
            )
        elif "membership" in self.operation_id:
            verified = bool(after["membership_exists"]) == self.operation_id.endswith(
                ".add"
            )
        else:
            sku_id = _uuid_parameter(parameters, "sku_id")
            direct = {
                UUID(item)
                for item in after["user"]["direct_sku_ids"]  # type: ignore[index]
            }
            verified = (sku_id in direct) == parameters["license_assigned"]
        return ProviderExecutionResult(
            kind=(
                ProviderExecutionKind.VERIFIED
                if verified
                else ProviderExecutionKind.UNCERTAIN
            ),
            evidence_reference=f"evidence:{_digest(after).removeprefix('sha256:')}",
        )

    async def observe(
        self,
        observation_handle: str,
    ) -> ProviderObservationResult:
        if not observation_handle.startswith("observation:"):
            raise SecurityError("observation handle is invalid")
        return ProviderObservationResult(
            kind=ProviderObservationKind.PENDING,
            evidence_reference=(
                "evidence:" + observation_handle.removeprefix("observation:")
            ),
        )
