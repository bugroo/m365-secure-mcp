"""Narrow Microsoft Graph v1.0 client with egress and response controls."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin

import httpx

from .auth import AuthenticationError, TokenProvider
from .config import Settings
from .security import Principal, SecurityPolicy, validate_graph_url

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0/"
RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})


@dataclass(frozen=True)
class GraphFailure:
    status_code: int
    request_id: str | None
    retry_after_seconds: float | None


class GraphError(RuntimeError):
    """Sanitized Microsoft Graph failure safe for an agent-facing response."""

    def __init__(self, message: str, failure: GraphFailure | None = None) -> None:
        super().__init__(message)
        self.failure = failure


class GraphClient:
    """Async Graph client that exposes no arbitrary URL or header capability."""

    def __init__(
        self,
        settings: Settings,
        tokens: TokenProvider,
        policy: SecurityPolicy,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.tokens = tokens
        self.policy = policy
        self._principal: Principal | None = None
        self._principal_lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            base_url=GRAPH_BASE_URL,
            timeout=httpx.Timeout(settings.graph_timeout_seconds),
            follow_redirects=False,
            transport=transport,
            headers={
                "Accept": "application/json",
                "User-Agent": "m365-secure-mcp/0.1.0",
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    @property
    def principal(self) -> Principal | None:
        return self._principal

    async def ensure_principal(self) -> Principal:
        if self._principal is not None:
            return self._principal
        async with self._principal_lock:
            if self._principal is not None:
                return self._principal
            data = await self._request_json_internal(
                "GET",
                urljoin(GRAPH_BASE_URL, "me"),
                params={"$select": "id,userPrincipalName,mail"},
            )
            principal = Principal(
                object_id=str(data.get("id", "")),
                user_principal_name=str(data.get("userPrincipalName", "")).lower(),
                mail=str(data["mail"]).lower() if data.get("mail") else None,
            )
            if not principal.object_id or not principal.user_principal_name:
                raise GraphError("Microsoft Graph returned an incomplete signed-in principal")
            self.policy.authorize_principal(principal)
            self._principal = principal
            return principal

    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        await self.ensure_principal()
        if not endpoint.startswith("/") or endpoint.startswith("//") or "://" in endpoint:
            raise GraphError("internal Graph endpoint failed validation")
        url = urljoin(GRAPH_BASE_URL, endpoint.lstrip("/"))
        validate_graph_url(url)
        return await self._request_json_internal(
            method,
            url,
            params=params,
            json_body=json_body,
            headers=headers,
        )

    async def request_cursor(self, url: str) -> dict[str, Any]:
        await self.ensure_principal()
        return await self._request_json_internal("GET", validate_graph_url(url))

    async def _request_json_internal(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        method = method.upper()
        if method not in {"GET", "POST", "PATCH"}:
            raise GraphError("internal Graph method failed validation")

        token = await self.tokens.get_access_token()
        auth_headers = {"Authorization": f"Bearer {token}"}
        if headers:
            auth_headers.update(headers)

        refreshed = False
        for attempt in range(self.settings.graph_max_retries + 1):
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=auth_headers,
                )
            except httpx.TimeoutException as exc:
                if attempt < self.settings.graph_max_retries:
                    await asyncio.sleep(min(2**attempt, 8))
                    continue
                raise GraphError("Microsoft Graph timed out; retry with a narrower query") from exc
            except httpx.RequestError as exc:
                raise GraphError("Microsoft Graph could not be reached securely") from exc

            if response.status_code == 401 and not refreshed:
                refreshed = True
                token = await self.tokens.get_access_token(force_refresh=True)
                auth_headers["Authorization"] = f"Bearer {token}"
                continue

            if response.status_code in RETRYABLE_STATUS_CODES:
                if attempt < self.settings.graph_max_retries:
                    await asyncio.sleep(self._retry_delay(response, attempt))
                    continue

            if response.status_code >= 400:
                raise self._safe_http_error(response)

            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > self.settings.max_response_bytes:
                raise GraphError("Microsoft Graph response exceeded the configured byte limit")
            if len(response.content) > self.settings.max_response_bytes:
                raise GraphError("Microsoft Graph response exceeded the configured byte limit")
            if response.status_code == 204 or not response.content:
                return {}
            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                raise GraphError("Microsoft Graph returned a non-JSON response") from exc
            if not isinstance(data, dict):
                raise GraphError("Microsoft Graph returned an unexpected response shape")
            return dict(data)

        raise GraphError("Microsoft Graph request exhausted its retry budget")

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(max(float(retry_after), 0.0), 30.0)
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(retry_after)
                    return min(max(parsed.timestamp() - datetime.now(UTC).timestamp(), 0), 30)
                except (TypeError, ValueError):
                    pass
        return float(min(2**attempt, 8))

    @staticmethod
    def _safe_http_error(response: httpx.Response) -> GraphError:
        request_id = response.headers.get("request-id") or response.headers.get("client-request-id")
        retry_after: float | None = None
        try:
            retry_after = float(response.headers["Retry-After"])
        except (KeyError, ValueError):
            pass
        failure = GraphFailure(response.status_code, request_id, retry_after)
        guidance = {
            400: "Graph rejected the query; simplify filters or verify identifiers",
            401: "Microsoft session is invalid or expired; re-authenticate",
            403: "permission denied; verify the enabled module, delegated scope, and tenant policy",
            404: "resource not found or not visible to the signed-in principal",
            409: "Graph reported a write conflict; use a new idempotency key only if appropriate",
            412: "resource changed since it was read; refresh it before updating",
            429: "Graph rate limit reached; wait before retrying",
        }.get(
            response.status_code,
            f"Microsoft Graph request failed with HTTP {response.status_code}",
        )
        suffix = f"; request ID: {request_id}" if request_id else ""
        return GraphError(f"{guidance}{suffix}", failure)


def agent_safe_error(exc: Exception) -> str:
    """Map internal failures to actionable messages without sensitive details."""

    from .security import SecurityError

    if isinstance(exc, (GraphError, AuthenticationError, SecurityError)):
        return f"Error: {exc}"
    return f"Error: operation failed safely ({type(exc).__name__})"
