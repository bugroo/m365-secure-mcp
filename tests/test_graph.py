from __future__ import annotations

from typing import Any

import httpx
import pytest

from m365_secure_mcp.graph import GraphClient, GraphError, classify_agent_error
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


@pytest.mark.asyncio
async def test_graph_never_retries_ambiguous_write_timeout(settings: Any) -> None:
    settings.graph_max_retries = 3
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path == "/v1.0/me":
            return httpx.Response(
                200,
                json={
                    "id": USER_ID,
                    "userPrincipalName": "person@example.com",
                    "mail": "person@example.com",
                },
            )
        calls += 1
        raise httpx.ReadTimeout("response was lost", request=request)

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(GraphError) as captured:
            await graph.request_json("POST", "/me/messages", json_body={"subject": "test"})
    finally:
        await graph.close()

    assert calls == 1
    assert captured.value.write_may_have_committed is True
    assert graph.write_attempt_count == 1
    assert graph.write_ambiguous_count == 1
    assert graph.write_confirmed_count == 0
    details = classify_agent_error(captured.value)
    assert details.code == "GRAPH_WRITE_OUTCOME_UNCERTAIN"
    assert details.safe_to_retry is False


@pytest.mark.asyncio
async def test_graph_never_retries_ambiguous_write_503(settings: Any) -> None:
    settings.graph_max_retries = 3
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path == "/v1.0/me":
            return httpx.Response(
                200,
                json={
                    "id": USER_ID,
                    "userPrincipalName": "person@example.com",
                    "mail": "person@example.com",
                },
            )
        calls += 1
        return httpx.Response(503, headers={"request-id": "write-503"})

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(GraphError) as captured:
            await graph.request_json("PATCH", "/planner/tasks/task-1", json_body={"title": "x"})
    finally:
        await graph.close()

    assert calls == 1
    assert captured.value.write_may_have_committed is True
    assert graph.write_ambiguous_count == 1


@pytest.mark.asyncio
async def test_graph_retries_explicitly_failed_429_write(settings: Any) -> None:
    settings.graph_max_retries = 1
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path == "/v1.0/me":
            return httpx.Response(
                200,
                json={
                    "id": USER_ID,
                    "userPrincipalName": "person@example.com",
                    "mail": "person@example.com",
                },
            )
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(201, json={"id": "created"})

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        result = await graph.request_json(
            "POST",
            "/me/messages",
            json_body={"subject": "test"},
        )
    finally:
        await graph.close()

    assert result == {"id": "created"}
    assert calls == 2
    assert graph.write_confirmed_count == 1
    assert graph.write_ambiguous_count == 0


@pytest.mark.asyncio
async def test_graph_marks_unparseable_successful_write_as_uncertain(
    settings: Any,
) -> None:
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
        return httpx.Response(200, content=b"accepted but not json")

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(GraphError) as captured:
            await graph.request_json(
                "PATCH",
                "/users/user-1",
                json_body={"displayName": "Approved"},
            )
    finally:
        await graph.close()

    assert captured.value.write_may_have_committed is True
    assert graph.write_confirmed_count == 1
    assert graph.write_ambiguous_count == 1


@pytest.mark.asyncio
async def test_office_download_drops_auth_on_preauthorized_redirect(
    settings: Any,
) -> None:
    content = b"PK-safe-office"
    graph_requests: list[httpx.Request] = []
    download_requests: list[httpx.Request] = []

    def graph_handler(request: httpx.Request) -> httpx.Response:
        graph_requests.append(request)
        if request.url.path == "/v1.0/me":
            return httpx.Response(
                200,
                json={
                    "id": USER_ID,
                    "userPrincipalName": "person@example.com",
                    "mail": "person@example.com",
                },
            )
        if request.url.path == "/v1.0/drives/drive-1/items/item-1":
            return httpx.Response(
                200,
                json={
                    "id": "item-1",
                    "name": "document.docx",
                    "size": len(content),
                    "eTag": '"etag-1"',
                    "file": {
                        "mimeType": (
                            "application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document"
                        )
                    },
                },
            )
        if (
            request.url.path
            == "/v1.0/drives/drive-1/items/item-1/content"
        ):
            return httpx.Response(
                302,
                headers={
                    "Location": (
                        "https://tenant.sharepoint.com/download?id=signed"
                    )
                },
            )
        raise AssertionError(f"unexpected path {request.url.path}")

    def download_handler(request: httpx.Request) -> httpx.Response:
        download_requests.append(request)
        assert "Authorization" not in request.headers
        return httpx.Response(200, content=content)

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(graph_handler),
        download_transport=httpx.MockTransport(download_handler),
    )
    try:
        item = await graph.download_drive_item("drive-1", "item-1")
    finally:
        await graph.close()

    assert item.content == content
    assert item.etag == '"etag-1"'
    assert len(download_requests) == 1
    assert all(
        request.headers["Authorization"] == "Bearer test-token"
        for request in graph_requests
    )


@pytest.mark.asyncio
async def test_office_upload_requires_etag_and_tracks_confirmation(
    settings: Any,
) -> None:
    uploaded = b"PK-updated-office"

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
        assert request.method == "PUT"
        assert request.headers["If-Match"] == '"etag-1"'
        assert request.content == uploaded
        return httpx.Response(
            200,
            json={"id": "item-1", "eTag": '"etag-2"'},
        )

    graph = GraphClient(
        settings,
        FakeTokens(),  # type: ignore[arg-type]
        SecurityPolicy(settings),
        transport=httpx.MockTransport(handler),
    )
    try:
        result = await graph.upload_drive_item(
            "drive-1",
            "item-1",
            uploaded,
            etag='"etag-1"',
            content_type="application/octet-stream",
        )
    finally:
        await graph.close()

    assert result["eTag"] == '"etag-2"'
    assert graph.write_confirmed_count == 1
    assert graph.write_ambiguous_count == 0


@pytest.mark.asyncio
async def test_office_upload_marks_oversized_success_response_uncertain(
    settings: Any,
) -> None:
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
        with pytest.raises(GraphError) as captured:
            await graph.upload_drive_item(
                "drive-1",
                "item-1",
                b"PK-updated-office",
                etag='"etag-1"',
                content_type="application/octet-stream",
            )
    finally:
        await graph.close()

    assert captured.value.write_may_have_committed is True
    assert graph.write_confirmed_count == 1
    assert graph.write_ambiguous_count == 1
