"""Stable MCP result envelopes with backwards-compatible text content."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal
from uuid import UUID

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict

from .graph import classify_agent_error
from .operations import OperationRecord

RESULT_SCHEMA_VERSION: Literal["1.0"] = "1.0"


class WriteReceipt(BaseModel):
    """Metadata-only evidence for one locally guarded write operation."""

    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    tool: str
    idempotency_key: str
    status: Literal["pending", "completed", "rejected", "uncertain"]
    created_at: str
    updated_at: str
    completed_at: str | None = None
    duplicate_suppressed: bool = False
    uncertain_commit: bool = False
    last_error_code: str | None = None


class ToolError(BaseModel):
    """Agent-actionable, secret-free error details."""

    model_config = ConfigDict(extra="forbid")

    code: str
    category: Literal[
        "authentication",
        "authorization",
        "validation",
        "conflict",
        "rate_limit",
        "upstream",
        "internal",
    ]
    message: str
    action: str
    graph_request_id: str | None = None


class RetryGuidance(BaseModel):
    """Explicit retry semantics so agents do not guess after failures."""

    model_config = ConfigDict(extra="forbid")

    safe_to_retry: bool
    retry_after_seconds: float | None = None
    reuse_idempotency_key: bool | None = None


class ToolEvidence(BaseModel):
    """Evidence emitted by the local security harness."""

    model_config = ConfigDict(extra="forbid")

    policy_enforced: bool = True
    audit_recorded: bool = True
    write_receipt: WriteReceipt | None = None
    operation: OperationRecord | None = None


class ToolEnvelope(BaseModel):
    """Versioned structured result returned by every registered MCP tool."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = RESULT_SCHEMA_VERSION
    ok: bool
    tool: str
    operation_id: UUID
    content_type: Literal["application/json", "text/markdown", "text/plain"]
    data: dict[str, Any] | list[Any] | str | None = None
    error: ToolError | None = None
    retry: RetryGuidance
    evidence: ToolEvidence


ToolResponse = Annotated[CallToolResult, ToolEnvelope]


def _structured_data(text: str) -> tuple[str, dict[str, Any] | list[Any] | str]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return "text/markdown", text
    if isinstance(value, (dict, list)):
        return "application/json", value
    return "text/plain", str(value)


def success_response(
    *,
    tool: str,
    operation_id: UUID,
    text: str,
    receipt: WriteReceipt | None = None,
    audit_recorded: bool = True,
    operation_record: OperationRecord | None = None,
) -> CallToolResult:
    """Build a successful result while preserving the legacy text response."""

    content_type, data = _structured_data(text)
    envelope = ToolEnvelope(
        ok=True,
        tool=tool,
        operation_id=operation_id,
        content_type=content_type,  # type: ignore[arg-type]
        data=data,
        retry=RetryGuidance(
            safe_to_retry=False,
            reuse_idempotency_key=True if receipt is not None else None,
        ),
        evidence=ToolEvidence(
            audit_recorded=audit_recorded,
            write_receipt=receipt,
            operation=operation_record,
        ),
    )
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structuredContent=envelope.model_dump(mode="json", exclude_none=True),
        isError=False,
    )


def error_response(
    *,
    tool: str,
    operation_id: UUID,
    exc: Exception,
    receipt: WriteReceipt | None = None,
    audit_recorded: bool = True,
) -> CallToolResult:
    """Build a protocol-level tool error with bounded recovery guidance."""

    details = classify_agent_error(exc)
    uncertain_write = receipt is not None and receipt.uncertain_commit
    operation_record = getattr(exc, "operation_record", None)
    if not isinstance(operation_record, OperationRecord):
        operation_record = None
    action = details.action
    if uncertain_write:
        action = (
            "Query the operation receipt and verify the external resource; "
            "do not retry with any key until the outcome is known."
        )
    envelope = ToolEnvelope(
        ok=False,
        tool=tool,
        operation_id=operation_id,
        content_type="text/plain",
        error=ToolError(
            code=details.code,
            category=details.category,
            message=details.message,
            action=action,
            graph_request_id=details.graph_request_id,
        ),
        retry=RetryGuidance(
            safe_to_retry=details.safe_to_retry and not uncertain_write,
            retry_after_seconds=details.retry_after_seconds,
            reuse_idempotency_key=(
                receipt.status == "rejected" if receipt is not None else None
            ),
        ),
        evidence=ToolEvidence(
            audit_recorded=audit_recorded,
            write_receipt=receipt,
            operation=operation_record,
        ),
    )
    return CallToolResult(
        content=[TextContent(type="text", text=f"Error: {details.message}")],
        structuredContent=envelope.model_dump(mode="json", exclude_none=True),
        isError=True,
    )
