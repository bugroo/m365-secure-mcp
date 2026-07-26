from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from m365_secure_mcp.config import Settings
from m365_secure_mcp.models import UpdatePlannerTaskDetailsInput
from m365_secure_mcp.security import AuditLogger, CursorCodec, SecurityPolicy
from m365_secure_mcp.server import Services, ToolRunner, _register_write_tools
from m365_secure_mcp.state import IdempotencyStore, WriteRateLimiter

from .conftest import CLIENT_ID, TENANT_ID, USER_ID

TASK_ID = "task-1"
PLAN_ID = "plan-1"
DETAILS_ETAG = 'W/"details-etag-1"'
EXISTING_ITEM_ID = "95e27074-6c4a-447a-aa24-9d718a0b86fa"


class FakeGraph:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

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
        return self.handler(call)


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


def make_tool(tmp_path: Path, graph: FakeGraph) -> Any:
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


@pytest.mark.asyncio
async def test_details_update_sends_a_closed_patch_and_verifies_204_response(
    tmp_path: Path,
) -> None:
    details_reads = 0

    def handler(call: dict[str, Any]) -> dict[str, Any]:
        nonlocal details_reads
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
            return {
                "id": TASK_ID,
                "@odata.etag": 'W/"details-etag-2"',
                "description": "Implementation notes",
                "previewType": "checklist",
                "checklist": {
                    EXISTING_ITEM_ID: {
                        "title": "Existing item",
                        "isChecked": True,
                    }
                },
            }
        if call["method"] == "PATCH" and call["endpoint"].endswith("/details"):
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
    assert '"task_id": "task-1"' in result
    assert 'W/\\"details-etag-2\\"' in result

    call_count = len(graph.calls)
    duplicate_result = await tool.run({"params": payload})
    assert len(graph.calls) == call_count
    assert "no duplicate Microsoft Graph call was made" in duplicate_result


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

    assert message in result
    assert not any(call["method"] == "PATCH" for call in graph.calls)


@pytest.mark.asyncio
async def test_details_update_rejects_task_outside_declared_plan(tmp_path: Path) -> None:
    def handler(call: dict[str, Any]) -> dict[str, Any]:
        assert call["endpoint"] == f"/planner/tasks/{TASK_ID}"
        return {"id": TASK_ID, "planId": "other-plan"}

    graph = FakeGraph(handler)
    tool = make_tool(tmp_path, graph)
    result = await tool.run({"params": base_payload()})

    assert "does not belong to the declared allowlisted plan" in result
    assert len(graph.calls) == 1
