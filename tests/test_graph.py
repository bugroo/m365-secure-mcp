from __future__ import annotations

from typing import Any

import httpx
import pytest

from m365_secure_mcp.graph import GraphClient, GraphError
from m365_secure_mcp.security import SecurityPolicy

from .conftest import USER_ID


class FakeTokens:
    def __init__(self) -> None:
        self.refreshes = 0

    async def get_access_token(self, *, force_refresh: bool = False) -> str:
        if force_refresh:
            self.refreshes += 1
        return "test-token"  # noqa: S105


@pytest.mark.asyncio
async def test_graph_principal_is_checked_before_data_request(settings: Any) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer test-token"
        if request.url.path == "/v1.0/me":
            return httpx.Response(
                200,
                json={
                    "id": USER_ID,
                    "userPrincipalName": "person@example.com",
                    "mail": "person@example.com",
                },
            )
        if request.url.path == "/v1.0/me/drive":
            return httpx.Response(200, json={"id": "drive-1"})
        raise AssertionError(f"unexpected path {request.url.path}")

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        data = await graph.request_json("GET", "/me/drive")
    finally:
        await graph.close()
    assert data["id"] == "drive-1"
    assert [request.url.path for request in requests] == ["/v1.0/me", "/v1.0/me/drive"]


@pytest.mark.asyncio
async def test_graph_refreshes_once_after_401(settings: Any) -> None:
    tokens = FakeTokens()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken"}})
        return httpx.Response(
            200,
            json={
                "id": USER_ID,
                "userPrincipalName": "person@example.com",
                "mail": "person@example.com",
            },
        )

    graph = GraphClient(
        settings,
        tokens,  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        principal = await graph.ensure_principal()
    finally:
        await graph.close()
    assert principal.object_id == USER_ID
    assert tokens.refreshes == 1


@pytest.mark.asyncio
async def test_graph_rejects_large_response(settings: Any) -> None:
    settings.max_response_bytes = 64_000

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1.0/me":
            return httpx.Response(
                200,
                json={
                    "id": USER_ID,
                    "userPrincipalName": "person@example.com",
                    "mail": "person@example.com",
                },
            )
        return httpx.Response(200, content=b"x" * 64_001)

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(GraphError, match="byte limit"):
            await graph.request_json("GET", "/me/drive")
    finally:
        await graph.close()


@pytest.mark.asyncio
async def test_graph_does_not_expose_provider_error_body(settings: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"request-id": "safe-request-id"},
            json={"error": {"message": "private tenant policy and user data"}},
        )

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(GraphError) as captured:
            await graph.ensure_principal()
    finally:
        await graph.close()
    message = str(captured.value)
    assert "safe-request-id" in message
    assert "private tenant policy" not in message
