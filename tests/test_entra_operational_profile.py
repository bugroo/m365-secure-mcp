from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_manifest import AuthorizationMode
from m365_secure_mcp.entra_operations import (
    CONTRACT_ID,
    EntraOperationalProfileService,
    GovernedOperationError,
    GovernedWriteUncertainError,
)
from m365_secure_mcp.governance import load_verified_governance_policy
from m365_secure_mcp.models import UpdateEntraUserOperationalProfileInput
from m365_secure_mcp.operations import OperationStatus
from m365_secure_mcp.security import SecurityPolicy

from .conftest import CLIENT_ID, TENANT_ID
from .governance_helpers import write_signed_governance

TARGET_ID = "77777777-7777-4777-8777-777777777777"


class FakeGraph:
    def __init__(
        self,
        *,
        user_type: str = "Member",
        synced: bool = False,
        privileged: bool = False,
        mutate_before_execute: bool = False,
        mismatch_after_patch: bool = False,
    ) -> None:
        self.user: dict[str, Any] = {
            "id": TARGET_ID,
            "userType": user_type,
            "onPremisesSyncEnabled": synced,
            "onPremisesLastSyncDateTime": (
                "2026-01-01T00:00:00Z" if synced else None
            ),
            "onPremisesImmutableId": "synced-id" if synced else None,
            "department": "Operations",
            "jobTitle": "Engineer",
            "officeLocation": "Berlin",
        }
        self.privileged = privileged
        self.mutate_before_execute = mutate_before_execute
        self.mismatch_after_patch = mismatch_after_patch
        self.user_reads = 0
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
        self.calls.append(
            {
                "method": method,
                "endpoint": endpoint,
                "params": dict(params or {}),
                "json_body": dict(json_body or {}),
                "headers": dict(headers or {}),
            }
        )
        if method == "GET" and endpoint == f"/users/{TARGET_ID}":
            self.user_reads += 1
            current = dict(self.user)
            if self.mutate_before_execute and self.user_reads == 2:
                current["officeLocation"] = "Concurrent change"
            return current
        if method == "GET" and endpoint.startswith("/roleManagement/"):
            return {"value": [{"id": "role"}] if self.privileged else []}
        if method == "GET" and "/transitiveMemberOf/" in endpoint:
            return {"value": []}
        if method == "PATCH" and endpoint == f"/users/{TARGET_ID}":
            assert json_body is not None
            for field, value in json_body.items():
                if self.mismatch_after_patch and field == "department":
                    continue
                self.user[field] = value
            return {}
        raise AssertionError(f"unexpected Graph call: {method} {endpoint}")


class FakeRecovery:
    def __init__(self) -> None:
        self.payload: dict[str, Any] | None = None

    def store(self, **kwargs: Any) -> str:
        self.payload = kwargs
        return f"capsule:{kwargs['operation_id']}"


def make_service(
    tmp_path: Path,
    graph: FakeGraph,
    *,
    authorization_mode: AuthorizationMode | None = None,
    protected: bool = False,
) -> tuple[EntraOperationalProfileService, FakeRecovery]:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        authorization_mode=authorization_mode,
        protected=protected,
    )
    settings = Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        profile="write",
        write_enabled=True,
        write_actions=CONTRACT_ID,
        allowed_target_user_ids=TARGET_ID,
        governance_policy_path=policy_path,
        governance_public_key_path=verifier_path,
        audit_log_path=tmp_path / "runtime" / "audit.jsonl",
        idempotency_db_path=tmp_path / "runtime" / "idempotency.sqlite3",
    )
    recovery = FakeRecovery()
    return (
        EntraOperationalProfileService(
            settings=settings,
            graph=graph,  # type: ignore[arg-type]
            runtime_policy=SecurityPolicy(settings),
            governance=load_verified_governance_policy(
                policy_path,
                verifier_path,
            ),
            recovery=recovery,  # type: ignore[arg-type]
        ),
        recovery,
    )


def params() -> UpdateEntraUserOperationalProfileInput:
    return UpdateEntraUserOperationalProfileInput(
        user_id=TARGET_ID,
        department="Platform Operations",
        job_title="Senior Engineer",
        idempotency_key=uuid4(),
    )


@pytest.mark.asyncio
async def test_standing_policy_executes_and_emits_metadata_only_evidence(
    tmp_path: Path,
) -> None:
    graph = FakeGraph()
    service, recovery = make_service(tmp_path, graph)
    operation_id = uuid4()

    record = await service.execute(params(), operation_id=operation_id)

    assert record.status is OperationStatus.EXECUTED_VERIFIED
    assert record.authorization_basis == "standing_policy"
    assert record.receipt is not None
    assert record.change_record is not None
    assert record.changed_fields == ["department", "jobTitle"]
    assert record.safe_to_retry is False
    assert recovery.payload is not None
    assert recovery.payload["previous_profile"]["department"] == "Operations"

    patch_calls = [call for call in graph.calls if call["method"] == "PATCH"]
    assert len(patch_calls) == 1
    assert patch_calls[0]["endpoint"] == f"/users/{TARGET_ID}"
    assert patch_calls[0]["json_body"] == {
        "department": "Platform Operations",
        "jobTitle": "Senior Engineer",
    }
    public_evidence = record.model_dump_json()
    assert "Platform Operations" not in public_evidence
    assert "Senior Engineer" not in public_evidence
    assert "Operations" not in public_evidence


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "graph",
    [
        FakeGraph(user_type="Guest"),
        FakeGraph(synced=True),
        FakeGraph(privileged=True),
    ],
)
async def test_member_source_and_privilege_fences_block_before_patch(
    tmp_path: Path,
    graph: FakeGraph,
) -> None:
    service, recovery = make_service(tmp_path, graph)
    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(params(), operation_id=uuid4())
    assert captured.value.operation_record.status is OperationStatus.BLOCKED_PRECONDITION
    assert not any(call["method"] == "PATCH" for call in graph.calls)
    assert recovery.payload is None


@pytest.mark.asyncio
async def test_explicit_plan_override_waits_for_host_without_model_approval(
    tmp_path: Path,
) -> None:
    graph = FakeGraph()
    service, recovery = make_service(
        tmp_path,
        graph,
        authorization_mode=AuthorizationMode.EXPLICIT_PLAN,
    )
    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(params(), operation_id=uuid4())
    record = captured.value.operation_record
    assert record.status is OperationStatus.AWAITING_APPROVAL
    assert record.authorization_mode is AuthorizationMode.EXPLICIT_PLAN
    assert not any(call["method"] == "PATCH" for call in graph.calls)
    assert recovery.payload is None


@pytest.mark.asyncio
async def test_toctou_change_expires_plan_before_patch(tmp_path: Path) -> None:
    graph = FakeGraph(mutate_before_execute=True)
    service, recovery = make_service(tmp_path, graph)
    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(params(), operation_id=uuid4())
    record = captured.value.operation_record
    assert record.status is OperationStatus.PLAN_EXPIRED
    assert record.new_plan_required is True
    assert not any(call["method"] == "PATCH" for call in graph.calls)
    assert recovery.payload is None


@pytest.mark.asyncio
async def test_post_read_mismatch_is_uncertain_and_never_retryable(
    tmp_path: Path,
) -> None:
    graph = FakeGraph(mismatch_after_patch=True)
    service, recovery = make_service(tmp_path, graph)
    with pytest.raises(GovernedWriteUncertainError) as captured:
        await service.execute(params(), operation_id=uuid4())
    record = captured.value.operation_record
    assert record.status is OperationStatus.EXECUTED_UNCERTAIN
    assert record.safe_to_retry is False
    assert recovery.payload is not None
    assert len([call for call in graph.calls if call["method"] == "PATCH"]) == 1


@pytest.mark.asyncio
async def test_protected_user_is_denied_without_graph_access(
    tmp_path: Path,
) -> None:
    graph = FakeGraph()
    service, recovery = make_service(tmp_path, graph, protected=True)
    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(params(), operation_id=uuid4())
    record = captured.value.operation_record
    assert record.status is OperationStatus.DENIED_BY_POLICY
    assert record.policy_change_required is True
    assert graph.calls == []
    assert recovery.payload is None
