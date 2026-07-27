from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m365_secure_mcp.change_safe import (
    ApprovalGrant,
    ApprovalRequest,
    ExternalApprovalBroker,
    SignedApprovalGrant,
    sign_approval_grant,
)
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
from m365_secure_mcp.security import (
    Principal,
    SecurityError,
    SecurityPolicy,
    open_private_file,
    read_private_file,
)

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

    async def ensure_principal(self) -> Principal:
        return Principal(
            object_id="11111111-1111-4111-8111-111111111111",
            user_principal_name="operator@example.com",
            mail="operator@example.com",
        )

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
    approval_signer: Ed25519PrivateKey | None = None,
    write_window_utc: str | None = None,
) -> tuple[EntraOperationalProfileService, FakeRecovery]:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        authorization_mode=authorization_mode,
        protected=protected,
        write_window_utc=write_window_utc,
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
    approval_broker = None
    if approval_signer is not None:
        approval_verifier_path = tmp_path / "approval" / "approver.pub"
        raw_public_key = approval_signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        descriptor = open_private_file(
            approval_verifier_path,
            os.O_WRONLY | os.O_EXCL,
        )
        try:
            os.write(
                descriptor,
                base64.b64encode(raw_public_key) + b"\n",
            )
        finally:
            os.close(descriptor)
        approval_broker = ExternalApprovalBroker(
            directory=tmp_path / "approval",
            public_key_path=approval_verifier_path,
            deployment_namespace=settings.deployment_namespace,
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
            approval_broker=approval_broker,
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


@pytest.mark.asyncio
async def test_signed_write_window_blocks_before_graph(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    start = now + timedelta(minutes=2)
    end = now + timedelta(minutes=3)
    window = f"{start:%H:%M}-{end:%H:%M}"
    graph = FakeGraph()
    service, recovery = make_service(
        tmp_path,
        graph,
        write_window_utc=window,
    )

    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(params(), operation_id=uuid4())

    record = captured.value.operation_record
    assert record.status is OperationStatus.DENIED_BY_POLICY
    assert record.reason_code == "WRITE_WINDOW_CLOSED"
    assert graph.calls == []
    assert recovery.payload is None


@pytest.mark.asyncio
async def test_preflight_preview_has_full_impact_and_never_calls_patch(
    tmp_path: Path,
) -> None:
    graph = FakeGraph()
    service, recovery = make_service(tmp_path, graph)

    record = await service.preview(params(), operation_id=uuid4())

    assert record.status is OperationStatus.CANCELLED_BEFORE_EFFECT
    assert record.reason_code == "PREFLIGHT_COMPLETE_NO_EFFECT"
    assert record.permission_impact is not None
    assert record.permission_impact.changed_fields == [
        "department",
        "jobTitle",
    ]
    assert record.details["preflight_only"] is True
    assert record.details["graph_write_attempted"] is False
    assert record.details["graph_simulation_claimed"] is False
    assert not any(call["method"] == "PATCH" for call in graph.calls)
    assert recovery.payload is None


@pytest.mark.asyncio
async def test_external_exact_plan_approval_executes_once_and_is_replay_safe(
    tmp_path: Path,
) -> None:
    signer = Ed25519PrivateKey.generate()
    graph = FakeGraph()
    service, recovery = make_service(
        tmp_path,
        graph,
        authorization_mode=AuthorizationMode.EXPLICIT_PLAN,
        approval_signer=signer,
    )
    request_params = params()

    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(request_params, operation_id=uuid4())
    pending = captured.value.operation_record
    assert pending.status is OperationStatus.AWAITING_APPROVAL
    assert pending.plan_id is not None
    assert pending.details["approval_is_external"] is True
    assert pending.details["approval_is_tool_argument"] is False
    assert not any(call["method"] == "PATCH" for call in graph.calls)

    request_path = (
        tmp_path / "approval" / f"{pending.plan_id}.request.json"
    )
    request_bytes = read_private_file(
        request_path,
        max_bytes=128_000,
        label="test approval request",
    )
    request = ApprovalRequest.model_validate_json(request_bytes)
    assert request.plan_digest == pending.details["plan_digest"]
    assert request.permission_impact.contract_id == CONTRACT_ID
    assert request.permission_impact.graph_method == "PATCH"
    assert request.permission_impact.target_count == 1
    assert request.permission_impact.admin_consent_is_manual is True
    assert b"Platform Operations" not in request_bytes
    assert b"Senior Engineer" not in request_bytes
    current_plan = await service.preflight(request_params)
    other_deployment = ExternalApprovalBroker(
        directory=tmp_path / "approval",
        public_key_path=tmp_path / "approval" / "approver.pub",
        deployment_namespace="0" * 16,
    )
    with pytest.raises(SecurityError, match="another deployment"):
        other_deployment.prepare(current_plan)

    issued_at = datetime.now(UTC)
    grant = ApprovalGrant(
        approval_id=uuid4(),
        plan=request.plan,
        plan_digest=request.plan_digest,
        issued_at=issued_at,
        expires_at=min(
            issued_at + timedelta(seconds=30),
            request.plan.expires_at,
        ),
    )
    bundle = sign_approval_grant(grant, signer, key_id="test-host-approver")
    approval_path = (
        tmp_path / "approval" / f"{pending.plan_id}.approval.json"
    )
    descriptor = open_private_file(
        approval_path,
        os.O_WRONLY | os.O_EXCL,
    )
    try:
        os.write(
            descriptor,
            (
                json.dumps(
                    bundle.model_dump(mode="json"),
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
        )
    finally:
        os.close(descriptor)

    record = await service.execute(request_params, operation_id=uuid4())

    assert record.status is OperationStatus.EXECUTED_VERIFIED
    assert record.authorization_basis == "explicit_plan"
    assert len([call for call in graph.calls if call["method"] == "PATCH"]) == 1
    assert recovery.payload is not None

    broker = service.change_safe.approval_broker
    assert broker is not None
    loaded = SignedApprovalGrant.model_validate_json(
        read_private_file(
            approval_path,
            max_bytes=128_000,
            label="test signed approval",
        )
    )
    with pytest.raises(SecurityError, match="already consumed"):
        broker.consumption.consume(loaded.grant)


@pytest.mark.asyncio
async def test_external_approval_tampering_fails_before_patch(
    tmp_path: Path,
) -> None:
    signer = Ed25519PrivateKey.generate()
    graph = FakeGraph()
    service, recovery = make_service(
        tmp_path,
        graph,
        authorization_mode=AuthorizationMode.EXPLICIT_PLAN,
        approval_signer=signer,
    )
    request_params = params()
    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(request_params, operation_id=uuid4())
    plan_id = captured.value.operation_record.plan_id
    assert plan_id is not None

    request = ApprovalRequest.model_validate_json(
        read_private_file(
            tmp_path / "approval" / f"{plan_id}.request.json",
            max_bytes=128_000,
            label="test approval request",
        )
    )
    issued_at = datetime.now(UTC)
    bundle = sign_approval_grant(
        ApprovalGrant(
            approval_id=uuid4(),
            plan=request.plan,
            plan_digest=request.plan_digest,
            issued_at=issued_at,
            expires_at=min(
                issued_at + timedelta(seconds=30),
                request.plan.expires_at,
            ),
        ),
        signer,
        key_id="test-host-approver",
    )
    document = bundle.model_dump(mode="json")
    document["grant"]["plan"]["precondition_digest"] = (
        "sha256:" + ("0" * 64)
    )
    approval_path = tmp_path / "approval" / f"{plan_id}.approval.json"
    descriptor = open_private_file(
        approval_path,
        os.O_WRONLY | os.O_EXCL,
    )
    try:
        os.write(
            descriptor,
            json.dumps(document, separators=(",", ":")).encode("utf-8"),
        )
    finally:
        os.close(descriptor)

    with pytest.raises(GovernedOperationError) as captured:
        await service.execute(request_params, operation_id=uuid4())
    assert (
        captured.value.operation_record.reason_code
        == "EXTERNAL_APPROVAL_INVALID"
    )
    assert (
        captured.value.operation_record.status
        is OperationStatus.BLOCKED_PRECONDITION
    )
    assert not any(call["method"] == "PATCH" for call in graph.calls)
    assert recovery.payload is None
