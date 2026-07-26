"""Pinned Power BI REST client with a separate OAuth audience."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from . import __version__
from .auth import TokenProvider
from .config import Settings
from .graph import GraphError, GraphFailure
from .security import Principal

POWERBI_BASE_URL = "https://api.powerbi.com/v1.0/myorg/"
POWERBI_HOST = "api.powerbi.com"


def validate_powerbi_url(url: str) -> str:
    """Reject any Power BI URL outside the pinned tenant-scoped API root."""

    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != POWERBI_HOST
        or parsed.port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/v1.0/myorg/")
        or parsed.fragment
    ):
        raise GraphError("Power BI URL failed the egress allowlist")
    return url


class PowerBIClient:
    """Async Power BI client with no arbitrary URL, token, or header surface."""

    def __init__(
        self,
        settings: Settings,
        tokens: TokenProvider,
        *,
        ensure_principal: Callable[[], Awaitable[Principal]],
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.tokens = tokens
        self._ensure_principal = ensure_principal
        self._write_attempt_count = 0
        self._write_confirmed_count = 0
        self._write_ambiguous_count = 0
        self._client = httpx.AsyncClient(
            base_url=POWERBI_BASE_URL,
            timeout=httpx.Timeout(settings.graph_timeout_seconds),
            follow_redirects=False,
            transport=transport,
            headers={
                "Accept": "application/json",
                "User-Agent": f"m365-secure-mcp/{__version__}",
            },
        )

    @property
    def write_attempt_count(self) -> int:
        return self._write_attempt_count

    @property
    def write_confirmed_count(self) -> int:
        return self._write_confirmed_count

    @property
    def write_ambiguous_count(self) -> int:
        return self._write_ambiguous_count

    async def close(self) -> None:
        await self._client.aclose()

    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        await self._ensure_principal()
        if (
            not endpoint.startswith("/")
            or endpoint.startswith("//")
            or "://" in endpoint
        ):
            raise GraphError("internal Power BI endpoint failed validation")
        url = validate_powerbi_url(
            urljoin(POWERBI_BASE_URL, endpoint.lstrip("/"))
        )
        method = method.upper()
        if method not in {"GET", "POST"}:
            raise GraphError("internal Power BI method failed validation")
        is_write = method == "POST"
        token = await self.tokens.get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        refreshed = False

        for attempt in range(self.settings.graph_max_retries + 1):
            try:
                if is_write:
                    self._write_attempt_count += 1
                response = await self._client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                )
            except (httpx.TimeoutException, httpx.RequestError) as exc:
                if is_write:
                    self._write_ambiguous_count += 1
                    raise GraphError(
                        "Power BI write lost its response; "
                        "the external outcome is uncertain",
                        write_may_have_committed=True,
                    ) from exc
                if (
                    isinstance(exc, httpx.TimeoutException)
                    and attempt < self.settings.graph_max_retries
                ):
                    await asyncio.sleep(min(2**attempt, 8))
                    continue
                raise GraphError("Power BI could not be reached securely") from exc

            if response.status_code == 401 and not refreshed:
                refreshed = True
                token = await self.tokens.get_access_token(
                    force_refresh=True
                )
                headers["Authorization"] = f"Bearer {token}"
                continue

            if response.status_code == 429:
                if attempt < self.settings.graph_max_retries:
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        delay = min(max(float(retry_after), 0.0), 30.0)
                    except ValueError:
                        delay = float(min(2**attempt, 8))
                    await asyncio.sleep(delay)
                    continue
            elif (
                response.status_code in {502, 503, 504}
                and not is_write
                and attempt < self.settings.graph_max_retries
            ):
                await asyncio.sleep(min(2**attempt, 8))
                continue
            elif response.status_code in {502, 503, 504} and is_write:
                self._write_ambiguous_count += 1
                error = self._safe_http_error(response)
                raise GraphError(
                    str(error),
                    error.failure,
                    write_may_have_committed=True,
                )

            if response.status_code >= 400:
                raise self._safe_http_error(response)
            if response.status_code >= 300 and response.status_code != 202:
                if is_write:
                    self._write_ambiguous_count += 1
                raise GraphError(
                    "Power BI returned an unexpected redirect response",
                    write_may_have_committed=is_write,
                )
            if is_write:
                self._write_confirmed_count += 1
            try:
                self._validate_size(response)
            except GraphError as exc:
                if is_write:
                    self._write_ambiguous_count += 1
                raise GraphError(
                    str(exc),
                    exc.failure,
                    write_may_have_committed=is_write,
                ) from exc
            if not response.content:
                return {
                    "accepted": response.status_code == 202,
                    "status_code": response.status_code,
                    "request_id": (
                        response.headers.get("RequestId")
                        or response.headers.get("request-id")
                    ),
                }
            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                if is_write:
                    self._write_ambiguous_count += 1
                raise GraphError(
                    "Power BI returned a non-JSON response",
                    write_may_have_committed=is_write,
                ) from exc
            if not isinstance(data, dict):
                if is_write:
                    self._write_ambiguous_count += 1
                raise GraphError(
                    "Power BI returned an unexpected response shape",
                    write_may_have_committed=is_write,
                )
            return dict(data)
        raise GraphError("Power BI request exhausted its retry budget")

    def _validate_size(self, response: httpx.Response) -> None:
        declared = response.headers.get("Content-Length")
        if declared:
            try:
                length = int(declared)
            except ValueError as exc:
                raise GraphError(
                    "Power BI returned an invalid response length"
                ) from exc
            if length < 0 or length > self.settings.max_response_bytes:
                raise GraphError("Power BI response exceeded the byte limit")
        if len(response.content) > self.settings.max_response_bytes:
            raise GraphError("Power BI response exceeded the byte limit")

    @staticmethod
    def _safe_http_error(response: httpx.Response) -> GraphError:
        request_id = (
            response.headers.get("RequestId")
            or response.headers.get("request-id")
            or response.headers.get("ActivityId")
        )
        retry_after: float | None = None
        try:
            retry_after = float(response.headers["Retry-After"])
        except (KeyError, ValueError):
            pass
        failure = GraphFailure(
            response.status_code,
            request_id,
            retry_after,
        )
        guidance = {
            400: "Power BI rejected the request; verify the resource identifiers",
            401: "Power BI session is invalid or expired; re-authenticate",
            403: (
                "Power BI permission denied; verify delegated scope, workspace "
                "role, Build permission, and tenant policy"
            ),
            404: "Power BI resource was not found or is not visible",
            409: "Power BI reported a write conflict",
            429: "Power BI rate limit reached; wait before retrying",
        }.get(
            response.status_code,
            f"Power BI request failed with HTTP {response.status_code}",
        )
        suffix = f"; request ID: {request_id}" if request_id else ""
        return GraphError(f"{guidance}{suffix}", failure)
