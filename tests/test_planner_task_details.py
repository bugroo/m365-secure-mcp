from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from m365_secure_mcp.config import Settings
from m365_secure_mcp.models import (
    UpdateApplicationInput,
    UpdateConditionalAccessPolicyInput,
    UpdateEventInput,
    UpdatePlannerTaskDetailsInput,
    UpdatePlannerTaskInput,
    UpdateServicePrincipalInput,
    UpdateTodoTaskInput,
)
from m365_secure_mcp.security import AuditLogger, CursorCodec, SecurityPolicy
from m365_secure_mcp.server import Services, ToolRunner, _register_write_tools
from m365_secure_mcp.state import IdempotencyStore, WriteRateLimiter

from .conftest import CLIENT_ID, TENANT_ID, USER_ID

TASK_ID = "task-1"
PLAN_ID = "plan-1"
DETAILS_ETAG = 'W/"details-etag-1"'
EXISTING_ITEM_ID = "95e27074-6c4a-447a-aa24-9d718a0b86fa"
APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"
CONDITIONAL_ACCESS_POLICY_ID = "66666666-6666-4666-8666-666666666666"


class FakeGraph:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []
        self.write_attempt_count = 0
        self.write_confirmed_count = 0
        self.write_ambiguous_count = 0

    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        call = {
            "method": method,
            "endpoint": endpoint,
            "params": params,
            "json_body": dict(json_body) if json_body is not None else None,
            "headers": dict(headers) if headers is not None else None,
        }
        self.calls.append(call)
        if method in {"POST", "PATCH"}:
            self.write_attempt_count += 1
        result = self.handler(call)
        if method in {"POST", "PATCH"}:
            self.write_confirmed_count += 1
        return result


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
        "allowed_user_object_ids": USER_ID,
        "allowed_upn_domains": "example.com",
        "profile": "write",
        "write_enabled": True,
        "write_actions": "planner.update_task_details",
        "allowed_plan_ids": PLAN_ID,
        "audit_log_path": tmp_path / "audit.jsonl",
        "idempotency_db_path": tmp_path / "idempotency.sqlite3",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def make_server(tmp_path: Path, graph: FakeGraph) -> tuple[FastMCP, Services]:
    settings = make_settings(tmp_path)
    services = Services(
        settings=settings,
        policy=SecurityPolicy(settings),
        graph=graph,  # type: ignore[arg-type]
        cursors=CursorCodec(b"x" * 32),
        audit=AuditLogger(tmp_path / "audit.jsonl"),
        idempotency=IdempotencyStore(
            tmp_path / "idempotency.sqlite3",
            pending_seconds=300,
        ),
        write_limiter=WriteRateLimiter(10),
    )
    server = FastMCP("planner-details-test")
    _register_write_tools(server, services, ToolRunner(services))
    return server, services


def make_tool(tmp_path: Path, graph: FakeGraph) -> Any:
    server, _ = make_server(tmp_path, graph)
    return server._tool_manager.get_tool("m365_update_planner_task_details")  # noqa: SLF001


def base_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "task_id": TASK_ID,
        "plan_id": PLAN_ID,
        "details_etag": DETAILS_ETAG,
        "description": "Implementation notes",
        "idempotency_key": str(uuid4()),
    }
    payload.update(overrides)
    return payload


def test_details_input_rejects_delete_semantics_and_unsafe_etag() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        UpdatePlannerTaskDetailsInput.model_validate(
            base_payload(checklist_removals=[EXISTING_ITEM_ID])
        )
    with pytest.raises(ValidationError, match="at least one Planner task-details"):
        UpdatePlannerTaskDetailsInput.model_validate(
            {
                "task_id": TASK_ID,
                "plan_id": PLAN_ID,
                "details_etag": DETAILS_ETAG,
                "idempotency_key": str(uuid4()),
            }
        )
    with pytest.raises(ValidationError, match="control characters"):
        UpdatePlannerTaskDetailsInput.model_validate(
            base_payload(details_etag='W/"safe"\r\nX-Injected: true')
        )


def test_details_input_rejects_duplicate_or_empty_checklist_updates() -> None:
    duplicate = {
        "item_id": EXISTING_ITEM_ID,
        "is_checked": True,
    }
    with pytest.raises(ValidationError, match="duplicate item IDs"):
        UpdatePlannerTaskDetailsInput.model_validate(
            base_payload(
                description=None,
                checklist_updates=[duplicate, duplicate],
            )
        )
    with pytest.raises(ValidationError, match="at least one checklist item field"):
        UpdatePlannerTaskDetailsInput.model_validate(
            base_payload(
                description=None,
                checklist_updates=[{"item_id": EXISTING_ITEM_ID}],
            )
        )


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            UpdatePlannerTaskInput,
            {
                "task_id": TASK_ID,
                "plan_id": PLAN_ID,
                "etag": 'W/"safe"\r\nInjected: true',
                "title": "New title",
                "idempotency_key": str(uuid4()),
            },
        ),
        (
            UpdateEventInput,
            {
                "event_id": "event-1",
                "etag": 'W/"safe"\r\nInjected: true',
                "subject": "New subject",
                "idempotency_key": str(uuid4()),
            },
        ),
        (
            UpdateTodoTaskInput,
            {
                "list_id": "list-1",
                "task_id": "task-1",
                "etag": 'W/"safe"\r\nInjected: true',
                "title": "New title",
                "idempotency_key": str(uuid4()),
            },
        ),
    ],
)
def test_all_update_etags_reject_header_control_characters(
    model: type[Any],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="control characters"):
        model.model_validate(payload)


@pytest.mark.asyncio
async def test_details_update_sends_a_closed_patch_and_verifies_204_response(
    tmp_path: Path,
) -> None:
    details_reads = 0
    checklist_after_patch: dict[str, dict[str, Any]] = {}

    def handler(call: dict[str, Any]) -> dict[str, Any]:
        nonlocal details_reads, checklist_after_patch
        if call["method"] == "GET" and call["endpoint"] == f"/planner/tasks/{TASK_ID}":
            return {"id": TASK_ID, "planId": PLAN_ID}
        if call["method"] == "GET" and call["endpoint"].endswith("/details"):
            details_reads += 1
            if details_reads == 1:
                return {
                    "id": TASK_ID,
                    "@odata.etag": DETAILS_ETAG,
                    "description": "Old notes",
                    "checklist": {
                        EXISTING_ITEM_ID: {
                            "title": "Existing item",
                            "isChecked": False,
                        }
                    },
                }
            verified_checklist = {
                EXISTING_ITEM_ID: {
                    "title": "Existing item",
                    "isChecked": True,
                }
            }
            for item_id, item in checklist_after_patch.items():
                if item_id == EXISTING_ITEM_ID:
                    continue
                verified_checklist[item_id] = item
            return {
                "id": TASK_ID,
                "@odata.etag": 'W/"details-etag-2"',
                "description": "Implementation notes",
                "previewType": "checklist",
                "checklist": verified_checklist,
            }
        if call["method"] == "PATCH" and call["endpoint"].endswith("/details"):
            checklist_after_patch = dict(call["json_body"]["checklist"])
            return {}
        raise AssertionError(f"unexpected Graph call: {call}")

    graph = FakeGraph(handler)
    tool = make_tool(tmp_path, graph)
    payload = base_payload(
        preview_type="checklist",
        checklist_additions=[{"title": "New item"}],
        checklist_updates=[
            {
                "item_id": EXISTING_ITEM_ID,
                "is_checked": True,
            }
        ],
    )
    result = await tool.run({"params": payload})

    patch = next(call for call in graph.calls if call["method"] == "PATCH")
    assert patch["endpoint"] == f"/planner/tasks/{TASK_ID}/details"
    assert patch["headers"] == {
        "If-Match": DETAILS_ETAG,
        "Prefer": "return=representation",
    }
    body = patch["json_body"]
    assert body["description"] == "Implementation notes"
    assert body["previewType"] == "checklist"
    assert set(body) == {"description", "previewType", "checklist"}
    assert body["checklist"][EXISTING_ITEM_ID] == {
        "@odata.type": "microsoft.graph.plannerChecklistItem",
        "isChecked": True,
    }
    addition_ids = set(body["checklist"]) - {EXISTING_ITEM_ID}
    assert len(addition_ids) == 1
    addition_id = addition_ids.pop()
    assert UUID(addition_id).version == 5
    assert body["checklist"][addition_id] == {
        "@odata.type": "microsoft.graph.plannerChecklistItem",
        "title": "New item",
        "isChecked": False,
    }
    assert all(value is not None for value in body["checklist"].values())
    assert details_reads == 2
    assert result.isError is False
    assert '"task_id": "task-1"' in result.content[0].text
    assert 'W/\\"details-etag-2\\"' in result.content[0].text
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is True
    receipt = result.structuredContent["evidence"]["write_receipt"]
    assert receipt["tool"] == "m365_update_planner_task_details"
    assert receipt["status"] == "completed"

    call_count = len(graph.calls)
    duplicate_result = await tool.run({"params": payload})
    assert len(graph.calls) == call_count
    assert "no duplicate Microsoft Graph call was made" in duplicate_result.content[0].text
    assert duplicate_result.structuredContent is not None
    duplicate_receipt = duplicate_result.structuredContent["evidence"]["write_receipt"]
    assert duplicate_receipt["duplicate_suppressed"] is True
    assert duplicate_receipt["operation_id"] == receipt["operation_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("details", "updates", "additions", "message"),
    [
        (
            {
                "id": TASK_ID,
                "@odata.etag": 'W/"newer"',
                "checklist": {},
            },
            [],
            [],
            "changed after they were read",
        ),
        (
            {
                "id": TASK_ID,
                "@odata.etag": DETAILS_ETAG,
                "checklist": {},
            },
            [{"item_id": EXISTING_ITEM_ID, "is_checked": True}],
            [],
            "not present in the current task",
        ),
        (
            {
                "id": TASK_ID,
                "@odata.etag": DETAILS_ETAG,
                "checklist": {
                    str(uuid4()): {"title": f"Item {index}", "isChecked": False}
                    for index in range(19)
                },
            },
            [],
            [{"title": "Item 20"}, {"title": "Item 21"}],
            "at most 20 checklist items",
        ),
    ],
)
async def test_details_update_fails_closed_before_patch(
    tmp_path: Path,
    details: dict[str, Any],
    updates: list[dict[str, object]],
    additions: list[dict[str, object]],
    message: str,
) -> None:
    def handler(call: dict[str, Any]) -> dict[str, Any]:
        if call["endpoint"] == f"/planner/tasks/{TASK_ID}":
            return {"id": TASK_ID, "planId": PLAN_ID}
        if call["endpoint"].endswith("/details"):
            return details
        raise AssertionError(f"unexpected Graph call: {call}")

    graph = FakeGraph(handler)
    tool = make_tool(tmp_path, graph)
    result = await tool.run(
        {
            "params": base_payload(
                description="New notes" if message == "changed after they were read" else None,
                checklist_updates=updates,
                checklist_additions=additions,
            )
        }
    )

    assert result.isError is True
    assert message in result.content[0].text
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "POLICY_REJECTED"
    assert not any(call["method"] == "PATCH" for call in graph.calls)


@pytest.mark.asyncio
async def test_details_update_rejects_task_outside_declared_plan(tmp_path: Path) -> None:
    def handler(call: dict[str, Any]) -> dict[str, Any]:
        assert call["endpoint"] == f"/planner/tasks/{TASK_ID}"
        return {"id": TASK_ID, "planId": "other-plan"}

    graph = FakeGraph(handler)
    tool = make_tool(tmp_path, graph)
    result = await tool.run({"params": base_payload()})

    assert result.isError is True
    assert "does not belong to the declared allowlisted plan" in result.content[0].text
    assert len(graph.calls) == 1


@pytest.mark.asyncio
async def test_details_update_marks_mismatched_postcondition_uncertain(
    tmp_path: Path,
) -> None:
    details_reads = 0

    def handler(call: dict[str, Any]) -> dict[str, Any]:
        nonlocal details_reads
        if call["endpoint"] == f"/planner/tasks/{TASK_ID}":
            return {"id": TASK_ID, "planId": PLAN_ID}
        if call["method"] == "GET" and call["endpoint"].endswith("/details"):
            details_reads += 1
            return {
                "id": TASK_ID,
                "@odata.etag": (
                    DETAILS_ETAG if details_reads == 1 else 'W/"details-etag-2"'
                ),
                "description": "Old notes",
                "checklist": {},
            }
        if call["method"] == "PATCH":
            return {}
        raise AssertionError(f"unexpected Graph call: {call}")

    tool = make_tool(tmp_path, FakeGraph(handler))
    result = await tool.run({"params": base_payload(description="New notes")})

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "WRITE_VERIFICATION_FAILED"
    receipt = result.structuredContent["evidence"]["write_receipt"]
    assert receipt["status"] == "uncertain"
    assert receipt["uncertain_commit"] is True
    assert result.structuredContent["retry"]["safe_to_retry"] is False


@pytest.mark.asyncio
async def test_write_receipt_tool_queries_one_exact_local_operation(tmp_path: Path) -> None:
    graph = FakeGraph(lambda call: pytest.fail(f"unexpected Graph call: {call}"))
    server, services = make_server(tmp_path, graph)
    idempotency_key = str(uuid4())

    async def operation() -> str:
        return "completed"

    execution = await services.idempotency.execute(
        "m365_update_planner_task_details",
        idempotency_key,
        {"idempotency_key": idempotency_key},
        operation,
    )
    tool = server._tool_manager.get_tool("m365_get_write_operation")  # noqa: SLF001
    result = await tool.run(
        {
            "params": {
                "operation_id": str(execution.receipt.operation_id),
            }
        }
    )

    assert result.isError is False
    assert result.structuredContent is not None
    data = result.structuredContent["data"]
    assert data["operation_id"] == str(execution.receipt.operation_id)
    assert data["status"] == "completed"
    assert graph.calls == []


def make_admin_tool(
    tmp_path: Path,
    graph: FakeGraph,
    *,
    action: str,
    tool_name: str,
    settings_overrides: Mapping[str, object] | None = None,
) -> Any:
    overrides: dict[str, object] = {
        "write_actions": action,
        "allowed_plan_ids": "",
        "allowed_application_ids": APPLICATION_ID,
        "allowed_service_principal_ids": SERVICE_PRINCIPAL_ID,
        "allowed_conditional_access_policy_ids": (
            CONDITIONAL_ACCESS_POLICY_ID
        ),
        "privileged_writes_enabled": True,
    }
    overrides.update(settings_overrides or {})
    settings = make_settings(tmp_path, **overrides)
    services = Services(
        settings=settings,
        policy=SecurityPolicy(settings),
        graph=graph,  # type: ignore[arg-type]
        cursors=CursorCodec(b"x" * 32),
        audit=AuditLogger(tmp_path / f"{tool_name}-audit.jsonl"),
        idempotency=IdempotencyStore(
            tmp_path / f"{tool_name}-writes.sqlite3",
            pending_seconds=300,
        ),
        write_limiter=WriteRateLimiter(10),
    )
    server = FastMCP("admin-write-test")
    _register_write_tools(server, services, ToolRunner(services))
    return server._tool_manager.get_tool(tool_name)  # noqa: SLF001


def test_admin_update_models_exclude_credentials_grants_and_arbitrary_fields() -> None:
    base = {"idempotency_key": str(uuid4())}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        UpdateApplicationInput.model_validate(
            {
                **base,
                "application_id": APPLICATION_ID,
                "display_name": "Approved name",
                "password_credentials": [{"secretText": "blocked"}],
            }
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        UpdateServicePrincipalInput.model_validate(
            {
                **base,
                "service_principal_id": SERVICE_PRINCIPAL_ID,
                "account_enabled": True,
                "app_role_assignments": ["blocked"],
            }
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        UpdateConditionalAccessPolicyInput.model_validate(
            {
                **base,
                "policy_id": CONDITIONAL_ACCESS_POLICY_ID,
                "state": "enabled",
                "conditions": {"users": {"includeUsers": ["All"]}},
            }
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("role_state", [True, None])
async def test_group_update_rejects_role_assignable_or_unclassified_group(
    tmp_path: Path,
    role_state: bool | None,
) -> None:
    def handler(call: dict[str, Any]) -> dict[str, Any]:
        if call["method"] != "GET":
            raise AssertionError(f"unexpected Graph call: {call}")
        response: dict[str, Any] = {"id": APPLICATION_ID}
        if role_state is not None:
            response["isAssignableToRole"] = role_state
        return response

    graph = FakeGraph(handler)
    tool = make_admin_tool(
        tmp_path,
        graph,
        action="groups.update",
        tool_name="m365_update_directory_group",
        settings_overrides={"allowed_group_ids": APPLICATION_ID},
    )
    result = await tool.run(
        {
            "params": {
                "group_id": APPLICATION_ID,
                "description": "Approved description",
                "idempotency_key": str(uuid4()),
            }
        }
    )

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "POLICY_REJECTED"
    assert not any(call["method"] == "PATCH" for call in graph.calls)


@pytest.mark.asyncio
async def test_service_principal_update_uses_closed_patch_and_postcondition(
    tmp_path: Path,
) -> None:
    def handler(call: dict[str, Any]) -> dict[str, Any]:
        if call["method"] == "PATCH":
            return {}
        if call["method"] == "GET":
            return {
                "id": SERVICE_PRINCIPAL_ID,
                "appId": APPLICATION_ID,
                "displayName": "Protected workload",
                "accountEnabled": False,
                "appRoleAssignmentRequired": True,
            }
        raise AssertionError(f"unexpected Graph call: {call}")

    graph = FakeGraph(handler)
    tool = make_admin_tool(
        tmp_path,
        graph,
        action="entra.update_service_principal",
        tool_name="m365_update_entra_service_principal",
    )
    result = await tool.run(
        {
            "params": {
                "service_principal_id": SERVICE_PRINCIPAL_ID,
                "display_name": "Protected workload",
                "account_enabled": False,
                "app_role_assignment_required": True,
                "idempotency_key": str(uuid4()),
            }
        }
    )

    assert result.isError is False
    patch = graph.calls[0]
    assert patch["method"] == "PATCH"
    assert patch["endpoint"] == f"/servicePrincipals/{SERVICE_PRINCIPAL_ID}"
    assert patch["json_body"] == {
        "displayName": "Protected workload",
        "accountEnabled": False,
        "appRoleAssignmentRequired": True,
    }
    assert graph.calls[1]["method"] == "GET"
    assert result.structuredContent is not None
    assert result.structuredContent["evidence"]["write_receipt"]["status"] == (
        "completed"
    )


@pytest.mark.asyncio
async def test_conditional_access_mismatch_is_uncertain_and_not_retried(
    tmp_path: Path,
) -> None:
    def handler(call: dict[str, Any]) -> dict[str, Any]:
        if call["method"] == "PATCH":
            return {}
        if call["method"] == "GET":
            return {
                "id": CONDITIONAL_ACCESS_POLICY_ID,
                "displayName": "Baseline",
                "state": "disabled",
            }
        raise AssertionError(f"unexpected Graph call: {call}")

    graph = FakeGraph(handler)
    tool = make_admin_tool(
        tmp_path,
        graph,
        action="governance.update_conditional_access_policy",
        tool_name="m365_update_conditional_access_policy",
    )
    result = await tool.run(
        {
            "params": {
                "policy_id": CONDITIONAL_ACCESS_POLICY_ID,
                "state": "enabledForReportingButNotEnforced",
                "idempotency_key": str(uuid4()),
            }
        }
    )

    assert result.isError is True
    assert len([call for call in graph.calls if call["method"] == "PATCH"]) == 1
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == (
        "WRITE_VERIFICATION_FAILED"
    )
    assert result.structuredContent["retry"]["safe_to_retry"] is False
    assert result.structuredContent["evidence"]["write_receipt"]["status"] == (
        "uncertain"
    )


@pytest.mark.asyncio
async def test_entra_application_write_rejects_non_allowlisted_target(
    tmp_path: Path,
) -> None:
    graph = FakeGraph(lambda call: pytest.fail(f"unexpected Graph call: {call}"))
    tool = make_admin_tool(
        tmp_path,
        graph,
        action="entra.update_application",
        tool_name="m365_update_entra_application",
    )
    result = await tool.run(
        {
            "params": {
                "application_id": "77777777-7777-4777-8777-777777777777",
                "display_name": "Blocked",
                "idempotency_key": str(uuid4()),
            }
        }
    )

    assert result.isError is True
    assert graph.calls == []
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "POLICY_REJECTED"


@pytest.mark.asyncio
async def test_write_is_blocked_when_attempt_audit_cannot_be_recorded(
    tmp_path: Path,
) -> None:
    graph = FakeGraph(lambda call: pytest.fail(f"unexpected Graph call: {call}"))
    server, services = make_server(tmp_path, graph)
    broad = tmp_path / "broad-audit"
    broad.mkdir()
    broad.chmod(0o755)
    services.audit = AuditLogger(broad / "audit.jsonl")
    tool = server._tool_manager.get_tool(  # noqa: SLF001
        "m365_update_planner_task_details"
    )

    result = await tool.run({"params": base_payload()})

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["evidence"]["audit_recorded"] is False
    assert graph.calls == []
