"""Narrow Microsoft Graph v1.0 client with egress and response controls."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Literal
from urllib.parse import urljoin

import httpx

from . import __version__
from .auth import AuthenticationError, TokenProvider
from .config import Settings
from .security import Principal, SecurityPolicy, validate_graph_url

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0/"
RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})
SAFE_WRITE_RETRY_STATUS_CODES = frozenset({429})
ErrorCategory = Literal[
    "authentication",
    "authorization",
    "validation",
    "conflict",
    "rate_limit",
    "upstream",
    "internal",
]


@dataclass(frozen=True)
class GraphFailure:
    status_code: int
    request_id: str | None
    retry_after_seconds: float | None


class GraphError(RuntimeError):
    """Sanitized Microsoft Graph failure safe for an agent-facing response."""

    def __init__(
        self,
        message: str,
        failure: GraphFailure | None = None,
        *,
        write_may_have_committed: bool = False,
    ) -> None:
        super().__init__(message)
        self.failure = failure
        self.write_may_have_committed = write_may_have_committed


@dataclass(frozen=True)
class AgentSafeError:
    """Stable error classification safe to expose through MCP."""

    code: str
    category: ErrorCategory
    message: str
    action: str
    safe_to_retry: bool = False
    retry_after_seconds: float | None = None
    graph_request_id: str | None = None


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
        self._write_attempt_count = 0
        self._write_confirmed_count = 0
        self._write_ambiguous_count = 0
        self._client = httpx.AsyncClient(
            base_url=GRAPH_BASE_URL,
            timeout=httpx.Timeout(settings.graph_timeout_seconds),
            follow_redirects=False,
            transport=transport,
            headers={
                "Accept": "application/json",
                "User-Agent": f"m365-secure-mcp/{__version__}",
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    @property
    def principal(self) -> Principal | None:
        return self._principal

    @property
    def write_attempt_count(self) -> int:
        """Monotonic count used only to classify ambiguous local write outcomes."""

        return self._write_attempt_count

    @property
    def write_confirmed_count(self) -> int:
        """Number of write requests that received a successful Graph response."""

        return self._write_confirmed_count

    @property
    def write_ambiguous_count(self) -> int:
        """Number of writes whose transport/upstream outcome could not be proven."""

        return self._write_ambiguous_count

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
        is_write = method in {"POST", "PATCH"}

        token = await self.tokens.get_access_token()
        auth_headers = {"Authorization": f"Bearer {token}"}
        if headers:
            auth_headers.update(headers)

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
                    headers=auth_headers,
                )
            except httpx.TimeoutException as exc:
                if is_write:
                    self._write_ambiguous_count += 1
                    raise GraphError(
                        "Microsoft Graph write timed out after transmission; "
                        "the external outcome is uncertain",
                        write_may_have_committed=True,
                    ) from exc
                if attempt < self.settings.graph_max_retries:
                    await asyncio.sleep(min(2**attempt, 8))
                    continue
                raise GraphError("Microsoft Graph timed out; retry with a narrower query") from exc
            except httpx.RequestError as exc:
                if is_write:
                    self._write_ambiguous_count += 1
                    raise GraphError(
                        "Microsoft Graph write lost its transport response; "
                        "the external outcome is uncertain",
                        write_may_have_committed=True,
                    ) from exc
                raise GraphError("Microsoft Graph could not be reached securely") from exc

            if response.status_code == 401 and not refreshed:
                refreshed = True
                token = await self.tokens.get_access_token(force_refresh=True)
                auth_headers["Authorization"] = f"Bearer {token}"
                continue

            if response.status_code in RETRYABLE_STATUS_CODES:
                safe_write_retry = response.status_code in SAFE_WRITE_RETRY_STATUS_CODES
                if (not is_write or safe_write_retry) and (
                    attempt < self.settings.graph_max_retries
                ):
                    await asyncio.sleep(self._retry_delay(response, attempt))
                    continue
                if is_write and not safe_write_retry:
                    self._write_ambiguous_count += 1
                    error = self._safe_http_error(response)
                    raise GraphError(
                        str(error),
                        error.failure,
                        write_may_have_committed=True,
                    )

            if response.status_code >= 400:
                raise self._safe_http_error(response)
            if response.status_code >= 300:
                if is_write:
                    self._write_ambiguous_count += 1
                raise GraphError(
                    "Microsoft Graph returned an unexpected redirect response",
                    GraphFailure(
                        response.status_code,
                        response.headers.get("request-id"),
                        None,
                    ),
                    write_may_have_committed=is_write,
                )

            if is_write:
                # Count the write before parsing the body. A successful HTTP response
                # proves Graph accepted the mutation even if local result parsing or
                # the subsequent verification read fails.
                self._write_confirmed_count += 1

            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise GraphError(
                        "Microsoft Graph returned an invalid response length"
                    ) from exc
                if declared_length > self.settings.max_response_bytes:
                    raise GraphError(
                        "Microsoft Graph response exceeded the configured byte limit"
                    )
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


def classify_agent_error(exc: Exception) -> AgentSafeError:
    """Map internal failures to stable, actionable details without secrets."""

    from .security import SecurityError

    if isinstance(exc, AuthenticationError):
        return AgentSafeError(
            code="AUTHENTICATION_FAILED",
            category="authentication",
            message=str(exc),
            action="Re-authenticate with the configured tenant and delegated Graph scopes.",
        )
    if isinstance(exc, SecurityError):
        if getattr(exc, "private_state_error", False):
            return AgentSafeError(
                code="PRIVATE_STATE_REJECTED",
                category="internal",
                message=str(exc),
                action=(
                    "Use a current-user-owned regular file inside a mode-0700 "
                    "directory, then retry."
                ),
            )
        if getattr(exc, "local_rate_limit", False):
            return AgentSafeError(
                code="LOCAL_RATE_LIMITED",
                category="rate_limit",
                message=str(exc),
                action="Wait for the local per-tool window before retrying.",
                safe_to_retry=True,
                retry_after_seconds=float(
                    getattr(exc, "retry_after_seconds", 60.0)
                ),
            )
        if getattr(exc, "write_state_conflict", False):
            return AgentSafeError(
                code="WRITE_STATE_UNCERTAIN",
                category="conflict",
                message=str(exc),
                action=(
                    "Query the operation receipt and verify the external resource; "
                    "do not retry with a new key blindly."
                ),
            )
        if getattr(exc, "write_verification_failed", False):
            return AgentSafeError(
                code="WRITE_VERIFICATION_FAILED",
                category="conflict",
                message=str(exc),
                action=(
                    "Query the operation receipt and inspect the external resource; "
                    "do not repeat the write until its state is known."
                ),
            )
        return AgentSafeError(
            code="POLICY_REJECTED",
            category="authorization",
            message=str(exc),
            action="Change the request or the operator-controlled allowlist; do not bypass policy.",
        )
    if isinstance(exc, GraphError):
        if exc.write_may_have_committed:
            failure = exc.failure
            return AgentSafeError(
                code="GRAPH_WRITE_OUTCOME_UNCERTAIN",
                category="conflict",
                message=str(exc),
                action=(
                    "Query the operation receipt and verify the external resource; "
                    "do not retry with any key until the outcome is known."
                ),
                safe_to_retry=False,
                retry_after_seconds=(
                    failure.retry_after_seconds if failure is not None else None
                ),
                graph_request_id=(
                    failure.request_id if failure is not None else None
                ),
            )
        failure = exc.failure
        status = failure.status_code if failure is not None else None
        category: ErrorCategory = "upstream"
        code = "GRAPH_REQUEST_FAILED"
        action = "Inspect the message and retry only when the result explicitly permits it."
        safe_to_retry = failure is None
        if status == 400:
            code, category = "GRAPH_INVALID_REQUEST", "validation"
            action = "Correct the identifiers or reduce the query."
            safe_to_retry = False
        elif status == 401:
            code, category = "GRAPH_AUTHENTICATION_FAILED", "authentication"
            action = "Re-authenticate and verify the tenant-bound public client."
            safe_to_retry = False
        elif status == 403:
            code, category = "GRAPH_PERMISSION_DENIED", "authorization"
            action = "Verify delegated consent and the enabled local module or action."
            safe_to_retry = False
        elif status == 404:
            code, category = "GRAPH_RESOURCE_NOT_FOUND", "validation"
            action = "Refresh the resource identifier within the active allowlist."
            safe_to_retry = False
        elif status in {409, 412}:
            code, category = "GRAPH_CONCURRENCY_CONFLICT", "conflict"
            action = "Re-read the resource and retry with its current ETag."
            safe_to_retry = True
        elif status == 429:
            code, category = "GRAPH_RATE_LIMITED", "rate_limit"
            action = "Wait for the specified interval before retrying."
            safe_to_retry = True
        elif status is not None and status >= 500:
            code = "GRAPH_UNAVAILABLE"
            action = "Retry after a delay; preserve the same idempotency key for writes."
            safe_to_retry = True
        return AgentSafeError(
            code=code,
            category=category,
            message=str(exc),
            action=action,
            safe_to_retry=safe_to_retry,
            retry_after_seconds=failure.retry_after_seconds if failure is not None else None,
            graph_request_id=failure.request_id if failure is not None else None,
        )
    if isinstance(exc, ValueError):
        return AgentSafeError(
            code="LOCAL_VALIDATION_FAILED",
            category="validation",
            message="request failed a local validation check",
            action="Correct the tool arguments and retry.",
        )
    return AgentSafeError(
        code="SAFE_INTERNAL_FAILURE",
        category="internal",
        message=f"operation failed safely ({type(exc).__name__})",
        action="Inspect local metadata-only logs; do not retry a write with a new key blindly.",
    )


def agent_safe_error(exc: Exception) -> str:
    """Backward-compatible safe error text."""

    return f"Error: {classify_agent_error(exc).message}"
