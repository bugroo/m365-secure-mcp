from __future__ import annotations

import json
from pathlib import Path

import pytest

from m365_secure_mcp.msp_radar import (
    RadarConfig,
    RadarDeployment,
    load_radar_config,
    run_radar,
)


def _config(tmp_path: Path) -> RadarConfig:
    return RadarConfig(
        maximum_parallel=2,
        deployments=[
            RadarDeployment(
                deployment_reference="msp:customer-a",
                policy_file=tmp_path / "a.json",
                tool_name="m365_get_entra_profile_debt_posture",
            ),
            RadarDeployment(
                deployment_reference="msp:customer-b",
                policy_file=tmp_path / "b.json",
                tool_name="m365_get_entra_profile_debt_posture",
            ),
        ],
    )


@pytest.mark.asyncio
async def test_radar_minimizes_results_and_isolates_failure(
    tmp_path: Path,
) -> None:
    async def runner(deployment: RadarDeployment) -> dict[str, object]:
        if deployment.deployment_reference == "msp:customer-b":
            raise RuntimeError("private tenant failure")
        return {
            "ok": True,
            "data": {
                "status": "OBSERVED_COMPLETE",
                "tenant_id": "private-tenant-id",
                "snapshot_reference": "snapshot:private",
                "coverage_status": {
                    "token_scopes": "complete",
                    "private": "invalid-value",
                },
                "findings": [
                    {
                        "severity": "high",
                        "alignment": "not_aligned",
                        "summary": "private tenant content",
                    }
                ],
            },
        }

    report = await run_radar(_config(tmp_path), runner=runner)

    assert report["status"] == "partial"
    assert report["observed_count"] == 1
    assert report["failed_count"] == 1
    assert report["writes_performed"] is False
    assert report["remediation_available"] is False
    assert report["shared_token_pool"] is False
    serialized = json.dumps(report)
    assert "private-tenant-id" not in serialized
    assert "private tenant content" not in serialized
    assert "private tenant failure" not in serialized


def test_radar_rejects_arbitrary_tools_and_shared_policy(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="fixed read-only"):
        RadarDeployment(
            deployment_reference="msp:customer-a",
            policy_file=tmp_path / "a.json",
            tool_name="m365_update_entra_user_operational_profile",
        )
    document = _config(tmp_path).model_dump(mode="json")
    document["deployments"][1]["policy_file"] = document["deployments"][0][
        "policy_file"
    ]
    with pytest.raises(ValueError, match="own policy"):
        RadarConfig.model_validate(document)


def test_radar_config_must_be_owner_only(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "radar.json"
    path.write_text(_config(tmp_path).model_dump_json())
    path.chmod(0o644)

    with pytest.raises(Exception, match="mode-0600"):
        load_radar_config(path)
