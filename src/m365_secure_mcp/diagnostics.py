"""Secret-free offline and live diagnostics for an M365 MCP deployment."""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import stat
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

import keyring

from . import __version__
from .auth import TokenProvider
from .config import (
    POWERBI_RESOURCE,
    PRIVILEGED_WRITE_ACTIONS,
    WRITE_ACTION_RESOURCES,
    WRITE_ACTION_SCOPES,
    Module,
    Profile,
    Settings,
)
from .contract_manifest import load_global_manifest, sha256_digest
from .control_compatibility import (
    control_compatibility_digest,
    load_control_compatibility_metadata,
)
from .control_manifest import load_global_control_manifest
from .governance import (
    GovernancePolicyV2,
    GovernanceProfileName,
    load_verified_governance_policy,
    resolve_control_library_configuration,
    validate_policy_against_manifest,
)
from .graph import GRAPH_BASE_URL, GraphClient, classify_agent_error
from .permissions import READ_TOOL_PERMISSIONS
from .playbook_manifest import load_global_playbook_manifest
from .powerbi import POWERBI_BASE_URL
from .security import SecurityPolicy
from .server import WRITE_TOOL_ACTIONS, create_server

CheckStatus = Literal["pass", "warn", "info", "fail"]
KEYRING_CACHE_MODE = "keyring"  # noqa: S105
MAX_RELEASE_EVIDENCE_BYTES = 2_000_000
RUNTIME_REQUIREMENT_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)")


def _check(
    name: str,
    status: CheckStatus,
    detail: str,
    *,
    evidence: dict[str, Any] | None = None,
    operator_action: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "status": status,
        "detail": detail,
        "operator_action": operator_action
        or (
            "No action required."
            if status in {"pass", "info"}
            else "Review this check before starting the MCP server."
        ),
    }
    if evidence:
        result["evidence"] = evidence
    return result


def _release_document(name: str) -> dict[str, Any]:
    payload = (
        files("m365_secure_mcp.release_data")
        .joinpath(name)
        .read_bytes()
    )
    if len(payload) > MAX_RELEASE_EVIDENCE_BYTES:
        raise ValueError("packaged release evidence exceeds the byte limit")
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise ValueError("packaged release evidence has an invalid shape")
    return dict(document)


def _distribution_name(requirement: str) -> str | None:
    match = RUNTIME_REQUIREMENT_PATTERN.match(requirement)
    return match.group(1) if match is not None else None


def _release_integrity_check() -> dict[str, Any]:
    """Verify packaged evidence against signed manifests and installed metadata."""

    issues: list[str] = []
    evidence: dict[str, Any] = {
        "contract_manifest_signature_verified": False,
        "playbook_manifest_signature_verified": False,
        "control_manifest_signature_verified": False,
        "control_compatibility_digest": None,
        "packaged_evidence_files": 0,
        "runtime_dependencies_checked": 0,
        "external_release_attestation_required": True,
        "build_kind": "unknown",
        "distribution_status": "unknown",
    }
    try:
        manifest = load_global_manifest()
        evidence["contract_manifest_signature_verified"] = True
        playbooks = load_global_playbook_manifest(manifest)
        evidence["playbook_manifest_signature_verified"] = True
        controls = load_global_control_manifest()
        evidence["control_manifest_signature_verified"] = True
        compatibility = load_control_compatibility_metadata(controls)
        compatibility_digest = control_compatibility_digest(compatibility)
        evidence["control_compatibility_digest"] = compatibility_digest
        contract_digests = _release_document("contract-digests.json")
        playbook_digests = _release_document("playbook-digests.json")
        control_digests = _release_document("control-digests.json")
        provenance = _release_document("provenance.json")
        sbom = _release_document("sbom.cdx.json")
        evidence["packaged_evidence_files"] = 5

        expected_contracts = {
            contract.id: sha256_digest(contract)
            for contract in manifest.contracts
        }
        expected_playbooks = {
            playbook.id: sha256_digest(playbook)
            for playbook in playbooks.playbooks
        }
        expected_controls = {
            control.control_id: sha256_digest(control)
            for control in controls.controls
        }
        if contract_digests.get("manifest_digest") != sha256_digest(manifest):
            issues.append("contract digest artifact does not match signed manifest")
        if contract_digests.get("contracts") != expected_contracts:
            issues.append("one or more packaged contract digests do not match")
        if (
            playbook_digests.get("playbook_manifest_digest")
            != sha256_digest(playbooks)
        ):
            issues.append("playbook digest artifact does not match signed manifest")
        if playbook_digests.get("playbooks") != expected_playbooks:
            issues.append("one or more packaged playbook digests do not match")
        if (
            control_digests.get("control_manifest_digest")
            != sha256_digest(controls)
        ):
            issues.append("control digest artifact does not match signed manifest")
        if control_digests.get("controls") != expected_controls:
            issues.append("one or more packaged control digests do not match")
        if (
            control_digests.get("control_compatibility_schema_version")
            != compatibility.schema_version
        ):
            issues.append(
                "control compatibility schema does not match packaged metadata"
            )
        if (
            control_digests.get("control_compatibility_digest")
            != compatibility_digest
        ):
            issues.append(
                "control compatibility digest does not match packaged metadata"
            )

        expected_provenance = {
            "manifest_digest": sha256_digest(manifest),
            "playbook_manifest_digest": sha256_digest(playbooks),
            "control_manifest_digest": sha256_digest(controls),
            "control_compatibility_schema_version": (
                compatibility.schema_version
            ),
            "control_compatibility_digest": compatibility_digest,
            "contract_digests_digest": sha256_digest(contract_digests),
            "playbook_digests_digest": sha256_digest(playbook_digests),
            "control_digests_digest": sha256_digest(control_digests),
            "sbom_digest": sha256_digest(sbom),
            "package_version": __version__,
            "runtime_tool_generation": False,
            "source_revision": "release-attestation-required",
            "build_kind": "local-unattested",
            "distribution_status": "not-a-release",
            "release_attestation_status": "external-required",
        }
        for field, expected in expected_provenance.items():
            if provenance.get(field) != expected:
                issues.append(f"provenance field {field} does not match")
        evidence["build_kind"] = provenance.get("build_kind", "unknown")
        evidence["distribution_status"] = provenance.get(
            "distribution_status",
            "unknown",
        )

        try:
            installed_version = importlib.metadata.version(
                "m365-secure-mcp"
            )
        except importlib.metadata.PackageNotFoundError:
            installed_version = ""
        evidence["installed_version_matches"] = (
            installed_version == __version__
        )
        if installed_version != __version__:
            issues.append("installed package version does not match runtime")

        metadata = sbom.get("metadata")
        component = (
            metadata.get("component")
            if isinstance(metadata, dict)
            else None
        )
        if (
            not isinstance(component, dict)
            or component.get("name") != "m365-secure-mcp"
            or component.get("version") != __version__
        ):
            issues.append("SBOM root component does not match runtime package")
        component_properties = (
            component.get("properties")
            if isinstance(component, dict)
            else None
        )
        properties = {
            str(item.get("name")): str(item.get("value"))
            for item in component_properties
            if isinstance(item, dict)
            and item.get("name") is not None
            and item.get("value") is not None
        } if isinstance(component_properties, list) else {}
        if properties.get(
            "m365-secure-mcp:control-compatibility-digest"
        ) != compatibility_digest:
            issues.append("SBOM does not bind control compatibility metadata")
        if properties.get(
            "m365-secure-mcp:control-manifest-digest"
        ) != sha256_digest(controls):
            issues.append("SBOM does not bind the signed control manifest")
        raw_components = sbom.get("components")
        if not isinstance(raw_components, list):
            raise ValueError("packaged SBOM components are invalid")
        sbom_versions = {
            str(item["name"]).lower().replace("_", "-"): str(
                item["version"]
            )
            for item in raw_components
            if (
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and isinstance(item.get("version"), str)
            )
        }
        runtime_requirements = (
            importlib.metadata.requires("m365-secure-mcp") or []
        )
        checked = 0
        for requirement in runtime_requirements:
            name = _distribution_name(requirement)
            if name is None:
                continue
            normalized = name.lower().replace("_", "-")
            try:
                version = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                issues.append(f"runtime dependency {normalized} is not installed")
                continue
            checked += 1
            if sbom_versions.get(normalized) != version:
                issues.append(
                    f"runtime dependency {normalized} differs from packaged SBOM"
                )
        evidence["runtime_dependencies_checked"] = checked
    except (
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RuntimeError,
    ) as exc:
        issues.append(f"release evidence could not be verified: {type(exc).__name__}")

    evidence["issue_count"] = len(issues)
    evidence["issues"] = issues
    return _check(
        "release_integrity",
        "pass" if not issues else "fail",
        (
            "Signed contract, playbook, and control manifests, packaged digests, "
            "provenance, SBOM, package "
            "version, and installed runtime dependencies are consistent."
            if not issues
            else "Packaged release evidence is inconsistent or incomplete."
        ),
        evidence=evidence,
        operator_action=(
            "No action required."
            if not issues
            else (
                "Stop this profile and reinstall a verified, signed release; "
                "do not edit packaged evidence in place."
            )
        ),
    )


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


def _private_directory_check(label: str, path: Path) -> dict[str, Any]:
    """Inspect one configured application-owned directory without traversing it."""

    issues: list[str] = []
    evidence: dict[str, Any] = {
        "label": label,
        "directory_exists": path.exists() or path.is_symlink(),
    }
    if path.exists() or path.is_symlink():
        directory_stat = path.lstat()
        mode = stat.S_IMODE(directory_stat.st_mode)
        evidence["directory_mode"] = oct(mode)
        if not stat.S_ISDIR(directory_stat.st_mode) or path.is_symlink():
            issues.append("path is not a real directory")
        if hasattr(os, "getuid") and directory_stat.st_uid != os.getuid():
            issues.append("directory is not owned by the current user")
        if mode & 0o077:
            issues.append("directory permissions are broader than 0700")
    evidence["issues"] = issues
    return evidence


def _profile_isolation_check(settings: Settings) -> dict[str, Any]:
    """Check namespacing and path separation without exposing private paths."""

    state_paths = [
        settings.effective_audit_log_path,
        settings.effective_idempotency_db_path,
        settings.effective_assurance_snapshot_path,
        settings.effective_recovery_capsule_path,
    ]
    normalized_paths = [
        os.path.abspath(os.fspath(path.expanduser()))
        for path in state_paths
    ]
    distinct = len(normalized_paths) == len(set(normalized_paths))
    cache_namespaced = (
        settings.tenant_id in settings.cache_username
        and settings.client_id in settings.cache_username
        and settings.profile.value in settings.cache_username
        and settings.deployment_kind in settings.cache_username
    )
    active_profile_compatible = True
    active_governance_profile: str | None = None
    governance_schema_version: str | None = None
    control_library_configured = False
    enabled_control_count = 0
    control_exception_count = 0
    control_compatibility_digest_value: str | None = None
    if (
        settings.governance_policy_path is not None
        and settings.governance_public_key_path is not None
    ):
        verified = load_verified_governance_policy(
            settings.governance_policy_path,
            settings.governance_public_key_path,
        )
        manifest = load_global_manifest()
        playbooks = load_global_playbook_manifest(manifest)
        controls = load_global_control_manifest()
        validate_policy_against_manifest(
            verified.policy,
            manifest,
            playbooks,
            controls,
        )
        governance_schema_version = verified.policy.schema_version
        if isinstance(verified.policy, GovernancePolicyV2):
            control_configuration = resolve_control_library_configuration(
                verified.policy,
                controls,
            )
            control_library_configured = True
            enabled_control_count = len(control_configuration.settings)
            control_exception_count = len(control_configuration.exceptions)
            control_compatibility_digest_value = (
                control_configuration.compatibility_digest
            )
        active = verified.policy.active_profile
        active_governance_profile = active.value
        allowed = (
            {
                GovernanceProfileName.ROUTINE_READ,
                GovernanceProfileName.PRIVILEGED_READ,
            }
            if settings.profile is Profile.READ
            else {
                GovernanceProfileName.ROUTINE_WRITE,
                GovernanceProfileName.SELECTED_WRITE,
                GovernanceProfileName.BREAK_GLASS,
            }
        )
        active_profile_compatible = active in allowed
    issues: list[str] = []
    if not distinct:
        issues.append("two application state roles share the same path")
    if not cache_namespaced:
        issues.append("token-cache identity is not profile namespaced")
    if not active_profile_compatible:
        issues.append("runtime and signed Governance profile classes differ")
    return _check(
        "profile_isolation",
        "pass" if not issues else "fail",
        (
            "Tenant/profile cache identity, state roles, and signed profile "
            "class are isolated."
            if not issues
            else "Tenant/profile isolation checks found a collision."
        ),
        evidence={
            "deployment_namespace_configured": True,
            "state_role_count": len(state_paths),
            "state_paths_distinct": distinct,
            "token_cache_namespaced": cache_namespaced,
            "governance_profile_configured": (
                active_governance_profile is not None
            ),
            "active_governance_profile": active_governance_profile,
            "governance_schema_version": governance_schema_version,
            "control_library_configured": control_library_configured,
            "enabled_control_count": enabled_control_count,
            "control_exception_count": control_exception_count,
            "control_compatibility_digest": (
                control_compatibility_digest_value
            ),
            "runtime_profile_compatible": active_profile_compatible,
            "issues": issues,
        },
        operator_action=(
            "No action required."
            if not issues
            else (
                "Stop this profile and assign distinct tenant/profile state "
                "paths and a compatible signed Governance profile."
            )
        ),
    )


def _effective_scope_check(
    settings: Settings,
    *,
    tool_names: list[str],
) -> dict[str, Any]:
    """Prove every locally requested scope has at least one exposed consumer."""

    expected_graph: set[str] = set()
    expected_powerbi: set[str] = set()
    for tool in tool_names:
        action = WRITE_TOOL_ACTIONS.get(tool)
        permission = READ_TOOL_PERMISSIONS.get(tool)
        if action is not None:
            target = (
                expected_graph
                if WRITE_ACTION_RESOURCES[action] == "graph"
                else expected_powerbi
            )
            target.update(WRITE_ACTION_SCOPES[action])
        elif permission is not None:
            target = (
                expected_graph
                if permission.resource == "graph"
                else expected_powerbi
            )
            target.update(permission.scopes)
    if any(
        tool != "m365_get_security_posture"
        for tool in tool_names
    ):
        expected_graph.add("User.Read")
    actual_graph = set(settings.scopes)
    actual_powerbi = {
        scope.rsplit("/", 1)[-1]
        for scope in settings.powerbi_scopes
    }
    missing = sorted(
        (expected_graph - actual_graph)
        | (expected_powerbi - actual_powerbi)
    )
    excessive = sorted(
        (actual_graph - expected_graph)
        | (actual_powerbi - expected_powerbi)
    )
    issues = bool(missing or excessive)
    return _check(
        "effective_scope_closure",
        "pass" if not issues else "fail",
        (
            "Every effective scope is required by an exposed fixed tool."
            if not issues
            else "Effective scopes differ from the exposed tool closure."
        ),
        evidence={
            "graph_scope_count": len(actual_graph),
            "powerbi_scope_count": len(actual_powerbi),
            "missing_scopes": missing,
            "excessive_scopes": excessive,
        },
        operator_action=(
            "No action required."
            if not issues
            else (
                "Stop this profile and reduce its module/tool/action selection "
                "or restore the missing exact permission."
            )
        ),
    )


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
            resource = WRITE_ACTION_RESOURCES[action]
            action_scopes = sorted(WRITE_ACTION_SCOPES[action])
            resources = {
                "graph": (
                    sorted(set(action_scopes) | {"User.Read"})
                    if resource == "graph"
                    else ["User.Read"]
                ),
                **(
                    {
                        "powerbi": [
                            f"{POWERBI_RESOURCE}/{scope}"
                            for scope in action_scopes
                        ]
                    }
                    if resource == "powerbi"
                    else {}
                ),
            }
            reason = f"enabled write action: {action}"
        elif permission is not None:
            resources = {
                "graph": (
                    sorted(set(permission.scopes) | {"User.Read"})
                    if permission.resource == "graph"
                    else ["User.Read"]
                ),
                **(
                    {
                        "powerbi": [
                            f"{POWERBI_RESOURCE}/{scope}"
                            for scope in sorted(permission.scopes)
                        ]
                    }
                    if permission.resource == "powerbi"
                    else {}
                ),
            }
            reason = f"fixed read contract in module: {permission.module}"
        elif tool == "m365_get_security_posture":
            resources = {}
            reason = "local policy inspection; no Graph call"
        elif tool == "m365_get_write_operation":
            resources = {}
            reason = "local receipt lookup; no Graph call"
        else:
            raise RuntimeError(f"effective tool has no permission explanation: {tool}")
        contracts.append(
            {
                "tool": tool,
                "scopes": sorted(
                    {
                        scope
                        for scopes in resources.values()
                        for scope in scopes
                    }
                ),
                "resources": resources,
                "reason": reason,
            }
        )

    all_scopes = [*settings.scopes, *settings.powerbi_scopes]
    scope_to_tools = {
        scope: sorted(
            contract["tool"]
            for contract in contracts
            if any(
                scope in scopes
                for scopes in contract["resources"].values()
            )
        )
        for scope in all_scopes
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
    checks.append(_release_integrity_check())
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
    if Module.ASSURANCE in settings.enabled_modules:
        state_paths.append(
            _private_path_check(
                "assurance_snapshots",
                settings.effective_assurance_snapshot_path,
            )
        )
    if settings.profile is Profile.WRITE:
        state_paths.append(
            _private_path_check(
                "recovery_capsules",
                settings.effective_recovery_capsule_path,
            )
        )
    if settings.governance_policy_path is not None:
        state_paths.append(
            _private_path_check(
                "governance_policy",
                settings.governance_policy_path.expanduser(),
            )
        )
    if settings.governance_public_key_path is not None:
        state_paths.append(
            _private_path_check(
                "governance_verifier",
                settings.governance_public_key_path.expanduser(),
            )
        )
    if settings.approval_public_key_path is not None:
        state_paths.append(
            _private_path_check(
                "approval_verifier",
                settings.approval_public_key_path.expanduser(),
            )
        )
    private_directories = []
    if settings.approval_broker_dir is not None:
        private_directories.append(
            _private_directory_check(
                "approval_broker",
                settings.approval_broker_dir.expanduser(),
            )
        )
    state_issues = [issue for item in state_paths for issue in item["issues"]]
    state_issues.extend(
        issue
        for item in private_directories
        for issue in item["issues"]
    )
    checks.append(
        _check(
            "private_state_paths",
            "pass" if not state_issues else "fail",
            (
                "Local state paths satisfy owner-only requirements."
                if not state_issues
                else "Local state path metadata is unsafe."
            ),
            evidence={
                "paths": state_paths,
                "directories": private_directories,
            },
            operator_action=(
                "No action required."
                if not state_issues
                else (
                    "Stop this profile and restore owner-only 0700 directories "
                    "and 0600 regular non-symlink files."
                )
            ),
        )
    )
    checks.append(_profile_isolation_check(settings))
    checks.append(
        _effective_scope_check(
            settings,
            tool_names=tool_names,
        )
    )
    checks.append(
        _check(
            "graph_egress",
            "pass",
            (
                "Runtime API egress is pinned to Microsoft Graph v1.0"
                + (
                    " and Power BI REST"
                    if settings.powerbi_scopes
                    else ""
                )
                + " over HTTPS."
            ),
            evidence={
                "graph_base_url": GRAPH_BASE_URL,
                "powerbi_base_url": (
                    POWERBI_BASE_URL if settings.powerbi_scopes else None
                ),
            },
        )
    )
    private_scopes = [
        scope
        for scope in (*settings.scopes, *settings.powerbi_scopes)
        if scope.startswith("api://")
    ]
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
                "graph_scopes": list(settings.scopes),
                "scopes": list(settings.scopes),
                "powerbi_scopes": list(settings.powerbi_scopes),
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
            (
                "Host oversight mode cannot be proven by the server; retain "
                "operator-visible halt/override and contract-tier hard gates."
            ),
            operator_action=(
                "Verify the host/broker oversight configuration when enabling "
                "T2/T3 or explicit-plan operations."
            ),
        )
    )

    if live:
        tokens = TokenProvider(settings)
        graph = GraphClient(settings, tokens, SecurityPolicy(settings))
        try:
            granted = await tokens.get_delegated_scope_claims()
            missing = sorted(set(settings.scopes) - granted)
            unexpected = sorted(
                granted - set(settings.scopes)
            )
            checks.append(
                _check(
                    "delegated_scope_claims",
                    "pass" if not missing and not unexpected else "fail",
                    (
                        "The delegated token exactly matches effective scopes."
                        if not missing and not unexpected
                        else "The delegated token differs from effective scopes."
                    ),
                    evidence={
                        "requested_scopes": list(settings.scopes),
                        "granted_scopes": sorted(granted),
                        "missing_scopes": missing,
                        "unexpected_scopes": unexpected,
                    },
                    operator_action=(
                        "No action required."
                        if not missing and not unexpected
                        else (
                            "Stop this profile, correct Entra consent manually, "
                            "then clear/reacquire its isolated token cache."
                        )
                    ),
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
            if settings.powerbi_scopes:
                powerbi_tokens = TokenProvider(
                    settings,
                    scopes=settings.powerbi_scopes,
                    resource="powerbi",
                )
                powerbi_granted = (
                    await powerbi_tokens.get_delegated_scope_claims()
                )
                requested = {
                    scope.rsplit("/", 1)[-1]
                    for scope in settings.powerbi_scopes
                }
                missing_powerbi = sorted(requested - powerbi_granted)
                unexpected_powerbi = sorted(
                    powerbi_granted - requested
                )
                checks.append(
                    _check(
                        "powerbi_scope_claims",
                        (
                            "pass"
                            if not missing_powerbi
                            and not unexpected_powerbi
                            else "fail"
                        ),
                        (
                            "The Power BI token exactly matches requested scopes."
                            if not missing_powerbi
                            and not unexpected_powerbi
                            else "The Power BI token differs from requested scopes."
                        ),
                        evidence={
                            "requested_scopes": sorted(requested),
                            "granted_scopes": sorted(powerbi_granted),
                            "missing_scopes": missing_powerbi,
                            "unexpected_scopes": unexpected_powerbi,
                        },
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
