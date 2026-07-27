"""External, read-only MSP radar with one isolated MCP child per deployment."""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .security import PrivateStateError, read_private_file

MAX_RADAR_CONFIG_BYTES = 256_000
RADAR_TOOLS = frozenset(
    {
        "m365_get_entra_identity_governance_posture",
        "m365_get_entra_permission_grant_drift",
        "m365_get_entra_profile_debt_posture",
        "m365_get_entra_app_credential_posture",
        "m365_get_entra_workload_identity_readiness",
    }
)
ALLOWED_ALIGNMENT = frozenset(
    {
        "aligned",
        "not_aligned",
        "not_applicable",
        "not_evaluated",
        "exception_approved",
    }
)
ALLOWED_SEVERITY = frozenset({"info", "low", "medium", "high", "critical"})
ALLOWED_COVERAGE = frozenset({"complete", "not_evaluated"})


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RadarDeployment(StrictModel):
    deployment_reference: str = Field(
        pattern=r"^msp:[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$"
    )
    policy_file: Path
    tool_name: str
    timeout_seconds: int = Field(default=120, ge=10, le=600)

    @field_validator("tool_name")
    @classmethod
    def fixed_assurance_tool(cls, value: str) -> str:
        if value not in RADAR_TOOLS:
            raise ValueError("radar accepts only fixed read-only Assurance tools")
        return value


class RadarConfig(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    maximum_parallel: int = Field(default=2, ge=1, le=4)
    deployments: list[RadarDeployment] = Field(min_length=1, max_length=250)

    @model_validator(mode="after")
    def deployments_are_isolated(self) -> RadarConfig:
        references = [item.deployment_reference for item in self.deployments]
        policies = [
            str(item.policy_file.expanduser().absolute())
            for item in self.deployments
        ]
        if references != sorted(set(references)):
            raise ValueError("deployment references must be unique and sorted")
        if len(policies) != len(set(policies)):
            raise ValueError("each radar deployment requires its own policy file")
        return self


class RadarTenantResult(StrictModel):
    deployment_reference: str
    status: Literal["observed", "failed"]
    operation_status: str | None = Field(default=None, max_length=64)
    coverage: dict[str, str] = Field(default_factory=dict)
    finding_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    finding_counts_by_alignment: dict[str, int] = Field(default_factory=dict)
    evidence_reference_available: bool = False
    error_code: str | None = Field(default=None, max_length=100)
    operator_action: str


def load_radar_config(path: Path) -> RadarConfig:
    try:
        return RadarConfig.model_validate_json(
            read_private_file(
                path,
                max_bytes=MAX_RADAR_CONFIG_BYTES,
                label="MSP radar configuration",
            )
        )
    except (ValueError, TypeError) as exc:
        raise PrivateStateError("MSP radar configuration is invalid") from exc


def minimize_result(
    deployment: RadarDeployment,
    envelope: dict[str, Any],
) -> RadarTenantResult:
    if envelope.get("ok") is not True:
        error = envelope.get("error")
        safe_error = error if isinstance(error, dict) else {}
        return RadarTenantResult(
            deployment_reference=deployment.deployment_reference,
            status="failed",
            error_code=(
                str(safe_error["code"])[:100]
                if isinstance(safe_error.get("code"), str)
                else "MCP_CHILD_FAILED"
            ),
            operator_action=(
                "Review this deployment's local MCP audit and policy; other "
                "customer runs were not affected."
            ),
        )
    data = envelope.get("data")
    if not isinstance(data, dict):
        raise ValueError("Assurance child returned an invalid data shape")
    raw_coverage = data.get("coverage_status")
    coverage = {
        str(key)[:64]: str(value)
        for key, value in (
            raw_coverage.items()
            if isinstance(raw_coverage, dict)
            else []
        )
        if (
            isinstance(key, str)
            and isinstance(value, str)
            and value in ALLOWED_COVERAGE
        )
    }
    severity: Counter[str] = Counter()
    alignment: Counter[str] = Counter()
    findings = data.get("findings")
    if isinstance(findings, list):
        for finding in findings[:5_000]:
            if not isinstance(finding, dict):
                continue
            finding_severity = finding.get("severity")
            finding_alignment = finding.get("alignment")
            if (
                isinstance(finding_severity, str)
                and finding_severity in ALLOWED_SEVERITY
            ):
                severity[finding_severity] += 1
            if (
                isinstance(finding_alignment, str)
                and finding_alignment in ALLOWED_ALIGNMENT
            ):
                alignment[finding_alignment] += 1
    return RadarTenantResult(
        deployment_reference=deployment.deployment_reference,
        status="observed",
        operation_status=(
            str(data["status"])[:64]
            if isinstance(data.get("status"), str)
            else None
        ),
        coverage=dict(sorted(coverage.items())),
        finding_counts_by_severity=dict(sorted(severity.items())),
        finding_counts_by_alignment=dict(sorted(alignment.items())),
        evidence_reference_available=bool(data.get("snapshot_reference")),
        operator_action="Review findings in this deployment's local evidence boundary.",
    )


async def _run_child(deployment: RadarDeployment) -> dict[str, Any]:
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "m365_secure_mcp",
            "--policy-file",
            str(deployment.policy_file.expanduser()),
        ],
    )
    hidden_stderr = io.StringIO()
    async with stdio_client(server, errlog=hidden_stderr) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            result = await session.call_tool(
                deployment.tool_name,
                {"params": {"response_format": "json"}},
                read_timeout_seconds=timedelta(
                    seconds=deployment.timeout_seconds
                ),
            )
    structured = result.structuredContent
    if not isinstance(structured, dict):
        raise ValueError("MCP child returned no structured result")
    return dict(structured)


async def run_radar(
    config: RadarConfig,
    *,
    runner: Callable[[RadarDeployment], Awaitable[dict[str, Any]]] = _run_child,
) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(config.maximum_parallel)

    async def one(deployment: RadarDeployment) -> RadarTenantResult:
        async with semaphore:
            try:
                envelope = await runner(deployment)
                return minimize_result(deployment, envelope)
            except Exception:
                return RadarTenantResult(
                    deployment_reference=deployment.deployment_reference,
                    status="failed",
                    error_code="ISOLATED_CHILD_FAILURE",
                    operator_action=(
                        "Review this deployment's local MCP audit and policy; "
                        "other customer runs were not affected."
                    ),
                )

    results = await asyncio.gather(
        *(one(item) for item in config.deployments)
    )
    observed = sum(item.status == "observed" for item in results)
    return {
        "schema_version": "1.0",
        "status": (
            "complete"
            if observed == len(results)
            else "partial"
        ),
        "captured_at": datetime.now(UTC).isoformat(),
        "deployment_count": len(results),
        "observed_count": observed,
        "failed_count": len(results) - observed,
        "writes_performed": False,
        "remediation_available": False,
        "shared_token_pool": False,
        "results": [
            item.model_dump(mode="json")
            for item in results
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="m365-msp-radar",
        description=(
            "Run fixed read-only Assurance in isolated tenant/profile children."
        ),
    )
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        config = load_radar_config(Path(args.config))
        report = asyncio.run(run_radar(config))
    except PrivateStateError as exc:
        raise SystemExit(f"Radar error:\n{exc}") from None
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
