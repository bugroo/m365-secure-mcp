from __future__ import annotations

from typing import Any

import httpx
import pytest

from m365_secure_mcp.graph import GraphError
from m365_secure_mcp.powerbi import PowerBIClient
from m365_secure_mcp.security import Principal

from .conftest import USER_ID


class FakeTokens:
    def __init__(self) -> None:
        self.refreshes = 0

    async def get_access_token(self, *, force_refresh: bool = False) -> str:
        if force_refresh:
            self.refreshes += 1
        return "powerbi-token"  # noqa: S105


async def _principal() -> Principal:
    return Principal(
        object_id=USER_ID,
        user_principal_name="person@example.com",
        mail="person@example.com",
    )


@pytest.mark.asyncio
async def test_powerbi_client_is_pinned_and_tracks_accepted_writes(
    settings: Any,
) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer powerbi-token"
        if request.method == "GET":
            return httpx.Response(
                200,
                json={"value": [{"id": "workspace-1"}]},
            )
        return httpx.Response(
            202,
            headers={"RequestId": "safe-powerbi-request"},
        )

    client = PowerBIClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        ensure_principal=_principal,
        transport=httpx.MockTransport(handler),
    )
    try:
        data = await client.request_json("GET", "/groups")
        accepted = await client.request_json(
            "POST",
            "/groups/workspace-1/datasets/dataset-1/refreshes",
            json_body={"notifyOption": "MailOnFailure"},
        )
        with pytest.raises(GraphError, match="endpoint"):
            await client.request_json(
                "GET",
                "https://example.invalid/groups",
            )
    finally:
        await client.close()

    assert data["value"][0]["id"] == "workspace-1"
    assert accepted["accepted"] is True
    assert accepted["request_id"] == "safe-powerbi-request"
    assert client.write_confirmed_count == 1
    assert all(
        request.url.host == "api.powerbi.com" for request in calls
    )


@pytest.mark.asyncio
async def test_powerbi_marks_unparseable_successful_write_as_uncertain(
    settings: Any,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"accepted but not json")

    client = PowerBIClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        ensure_principal=_principal,
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(GraphError) as captured:
            await client.request_json(
                "POST",
                "/groups/workspace-1/reports/report-1/Rebind",
                json_body={"datasetId": "dataset-1"},
            )
    finally:
        await client.close()

    assert captured.value.write_may_have_committed is True
    assert client.write_confirmed_count == 1
    assert client.write_ambiguous_count == 1
