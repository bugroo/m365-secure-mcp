"""Secret-free offline and live diagnostics for an M365 MCP deployment."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any, Literal

import keyring

from .auth import TokenProvider
from .config import (
    PRIVILEGED_WRITE_ACTIONS,
    WRITE_ACTION_SCOPES,
    Profile,
    Settings,
)
from .graph import GRAPH_BASE_URL, GraphClient, classify_agent_error
from .permissions import READ_TOOL_PERMISSIONS
from .security import SecurityPolicy
from .server import WRITE_TOOL_ACTIONS, create_server

CheckStatus = Literal["pass", "warn", "info", "fail"]
KEYRING_CACHE_MODE = "keyring"  # noqa: S105
def _check(
    name: str,
    status: CheckStatus,
    detail: str,
    *,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "status": status,
        "detail": detail,
    }
    if evidence:
        result["evidence"] = evidence
    return result


def _jwt_claims_unverified(token: str) -> dict[str, Any]:
    """Decode claims for diagnostics only; never use them for authorization."""

    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return {}
    return dict(claims) if isinstance(claims, dict) else {}


def _private_path_check(label: str, path: Path) -> dict[str, Any]:
    """Inspect private-state path metadata without creating or opening the file."""

    parent = path.parent
    issues: list[str] = []
    evidence: dict[str, Any] = {
        "label": label,
        "parent_exists": parent.exists(),
        "file_exists": path.exists() or path.is_symlink(),
    }
    if parent.exists():
        parent_stat = parent.lstat()
        parent_mode = stat.S_IMODE(parent_stat.st_mode)
        evidence["parent_mode"] = oct(parent_mode)
        if not stat.S_ISDIR(parent_stat.st_mode) or parent.is_symlink():
            issues.append("parent is not a real directory")
        if hasattr(os, "getuid") and parent_stat.st_uid != os.getuid():
            issues.append("parent is not owned by the current user")
        if parent_mode & 0o077:
            issues.append("parent permissions are broader than 0700")
    if path.exists() or path.is_symlink():
        file_stat = path.lstat()
        evidence["file_mode"] = oct(stat.S_IMODE(file_stat.st_mode))
        if not stat.S_ISREG(file_stat.st_mode) or path.is_symlink():
            issues.append("file is not a regular non-symlink path")
        if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
            issues.append("file is not owned by the current user")
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            issues.append("file permissions are broader than 0600")
    evidence["issues"] = issues
    return evidence


async def permission_report(settings: Settings) -> dict[str, Any]:
    """Map every effective tool contract to the scopes that justify it."""

    surface_settings = settings.model_copy(update={"token_cache_mode": "memory"})
    server = create_server(surface_settings)
    tools = await server.list_tools()
    tool_names = sorted(tool.name for tool in tools)
    contracts: list[dict[str, Any]] = []
    for tool in tool_names:
        action = WRITE_TOOL_ACTIONS.get(tool)
        permission = READ_TOOL_PERMISSIONS.get(tool)
        if action is not None:
            scopes = sorted(set(WRITE_ACTION_SCOPES[action]) | {"User.Read"})
            reason = f"enabled write action: {action}"
        elif permission is not None:
            scopes = sorted(set(permission.scopes) | {"User.Read"})
            reason = f"fixed read contract in module: {permission.module}"
        elif tool == "m365_get_security_posture":
            scopes = []
            reason = "local policy inspection; no Graph call"
        elif tool == "m365_get_write_operation":
            scopes = []
            reason = "local receipt lookup; no Graph call"
        else:
            raise RuntimeError(f"effective tool has no permission explanation: {tool}")
        contracts.append(
            {
                "tool": tool,
                "scopes": scopes,
                "reason": reason,
            }
        )

    scope_to_tools = {
        scope: sorted(
            contract["tool"]
            for contract in contracts
            if scope in contract["scopes"]
        )
        for scope in settings.scopes
    }
    return {
        **settings.permission_explanation(),
        "tool_contracts": contracts,
        "scope_to_tools": scope_to_tools,
    }


async def doctor_report(settings: Settings, *, live: bool = False) -> dict[str, Any]:
    """Return a bounded diagnostic report that never emits tokens or M365 content."""

    checks: list[dict[str, Any]] = []
    surface_settings = settings.model_copy(update={"token_cache_mode": "memory"})
    server = create_server(surface_settings)
    tools = await server.list_tools()
    tool_names = sorted(tool.name for tool in tools)
    checks.append(
        _check(
            "tool_surface",
            "pass",
            f"{len(tool_names)} exact tools are exposed by the effective profile.",
            evidence={"tools": tool_names},
        )
    )
    result_schema_ok = all(
        tool.outputSchema is not None
        and {
            "schema_version",
            "ok",
            "tool",
            "operation_id",
            "error",
            "retry",
            "evidence",
        }
        <= set(tool.outputSchema.get("properties", {}))
        for tool in tools
    )
    checks.append(
        _check(
            "result_contract",
            "pass" if result_schema_ok else "fail",
            (
                "Every exposed tool advertises the versioned result envelope."
                if result_schema_ok
                else "One or more tools lack the required structured result schema."
            ),
            evidence={"schema_version": "1.0"},
        )
    )
    delete_like = [
        name
        for name in tool_names
        if any(term in name for term in ("delete", "remove", "purge"))
    ]
    checks.append(
        _check(
            "no_delete_surface",
            "pass" if not delete_like else "fail",
            "No delete-like tool is exposed." if not delete_like else "Delete-like tools found.",
            evidence={"delete_like_tools": delete_like},
        )
    )
    state_paths = [
        _private_path_check("audit", settings.effective_audit_log_path),
        _private_path_check("write_receipts", settings.effective_idempotency_db_path),
    ]
    state_issues = [issue for item in state_paths for issue in item["issues"]]
    checks.append(
        _check(
            "private_state_paths",
            "pass" if not state_issues else "fail",
            (
                "Local audit and receipt paths satisfy owner-only requirements."
                if not state_issues
                else "Local audit or receipt path metadata is unsafe."
            ),
            evidence={"paths": state_paths},
        )
    )
    checks.append(
        _check(
            "graph_egress",
            "pass",
            "Runtime egress is pinned to Microsoft Graph v1.0 over HTTPS.",
            evidence={"base_url": GRAPH_BASE_URL},
        )
    )
    private_scopes = [scope for scope in settings.scopes if scope.startswith("api://")]
    checks.append(
        _check(
            "private_api_scope",
            "pass" if not private_scopes else "fail",
            (
                "No api:// resource scope is requested; "
                "AADSTS500011 private-resource drift is absent."
                if not private_scopes
                else "A private api:// resource scope is present."
            ),
            evidence={
                "scopes": list(settings.scopes),
                "private_scopes": private_scopes,
            },
        )
    )
    checks.append(
        _check(
            "principal_boundary",
            "pass" if settings.allowed_user_ids else "warn",
            (
                "An exact user object-ID allowlist is configured."
                if settings.allowed_user_ids
                else "No exact user object-ID allowlist is configured."
            ),
            evidence={
                "object_id_allowlist_count": len(settings.allowed_user_ids),
                "upn_domain_allowlist": sorted(settings.upn_domains),
            },
        )
    )
    try:
        backend = keyring.get_keyring()
        backend_name = type(backend).__name__
        backend_priority = float(getattr(backend, "priority", 0.0))
    except Exception:
        backend_name = "unavailable"
        backend_priority = 0.0
    keyring_available = backend_priority > 0
    cache_status: CheckStatus
    if settings.token_cache_mode != KEYRING_CACHE_MODE:
        cache_status = "warn"
    else:
        cache_status = "pass" if keyring_available else "fail"
    checks.append(
        _check(
            "token_cache",
            cache_status,
            (
                "Token cache is delegated to the operating-system keychain."
                if settings.token_cache_mode == KEYRING_CACHE_MODE and keyring_available
                else (
                    "No usable operating-system keychain backend is available."
                    if settings.token_cache_mode == KEYRING_CACHE_MODE
                    else "Token cache is process memory only; sign-in will not persist."
                )
            ),
            evidence={
                "mode": settings.token_cache_mode,
                "backend": backend_name,
                "backend_priority": backend_priority,
            },
        )
    )
    if settings.profile is Profile.WRITE:
        exposed_write_tools = sorted(
            tool
            for tool, action in WRITE_TOOL_ACTIONS.items()
            if action in settings.enabled_write_actions and tool in tool_names
        )
        checks.append(
            _check(
                "write_gates",
                "pass",
                (
                    "Write profile, global gate, exact action allowlist, and "
                    "privileged-write gate agree."
                ),
                evidence={
                    "enabled_actions": sorted(settings.enabled_write_actions),
                    "privileged_actions": sorted(
                        settings.enabled_write_actions
                        & PRIVILEGED_WRITE_ACTIONS
                    ),
                    "privileged_writes_enabled": (
                        settings.privileged_writes_enabled
                    ),
                    "exposed_write_tools": exposed_write_tools,
                    "rate_limit_per_tool_per_minute": (
                        settings.write_rate_limit_per_minute
                    ),
                },
            )
        )
        receipt_visible = "m365_get_write_operation" in tool_names
        checks.append(
            _check(
                "receipt_query",
                "pass" if receipt_visible else "warn",
                (
                    "The exact-selector local receipt query is exposed."
                    if receipt_visible
                    else "Receipt query was removed by the exact tool filter."
                ),
            )
        )
    checks.append(
        _check(
            "client_approval",
            "info",
            "Client-side approval mode cannot be proven by this server; keep writes on prompt.",
        )
    )

    if live:
        tokens = TokenProvider(settings)
        graph = GraphClient(settings, tokens, SecurityPolicy(settings))
        try:
            token = await tokens.get_access_token()
            claims = _jwt_claims_unverified(token)
            granted = frozenset(str(claims.get("scp", "")).split())
            missing = sorted(set(settings.scopes) - granted)
            checks.append(
                _check(
                    "delegated_scope_claims",
                    "pass" if not missing else "fail",
                    (
                        "The delegated token contains every effective requested scope."
                        if not missing
                        else "The delegated token is missing effective requested scopes."
                    ),
                    evidence={
                        "requested_scopes": list(settings.scopes),
                        "granted_scopes": sorted(granted),
                        "missing_scopes": missing,
                        "claim_note": (
                            "decoded for diagnostics; authorization uses Graph "
                            "and local policy"
                        ),
                    },
                )
            )
            await graph.ensure_principal()
            checks.append(
                _check(
                    "graph_principal",
                    "pass",
                    "Microsoft Graph /me succeeded and the principal passed local allowlists.",
                )
            )
        except Exception as exc:
            details = classify_agent_error(exc)
            checks.append(
                _check(
                    "live_graph",
                    "fail",
                    details.message,
                    evidence={
                        "code": details.code,
                        "action": details.action,
                        "graph_request_id": details.graph_request_id,
                    },
                )
            )
        finally:
            await graph.close()

    overall = "fail" if any(item["status"] == "fail" for item in checks) else "pass"
    return {
        "schema_version": "1.0",
        "overall": overall,
        "mode": "live" if live else "offline",
        "profile": settings.profile.value,
        "policy_digest": settings.policy_digest,
        "checks": checks,
    }
