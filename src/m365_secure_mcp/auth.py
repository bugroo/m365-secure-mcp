"""Microsoft identity authentication with an OS-keychain token cache."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import time
from typing import Any
from urllib.parse import urlparse

import keyring
import msal
from keyring.errors import KeyringError

from .config import Settings

MEMORY_CACHE_MODE = "memory"
GRAPH_RESOURCE = "https://graph.microsoft.com"
POWERBI_RESOURCE = "https://analysis.windows.net/powerbi/api"
RESOURCE_AUDIENCES = {
    "graph": frozenset(
        {
            GRAPH_RESOURCE,
            "00000003-0000-0000-c000-000000000000",
        }
    ),
    "powerbi": frozenset(
        {
            POWERBI_RESOURCE,
            "00000009-0000-0000-c000-000000000000",
        }
    ),
}
RESOURCE_URIS = {
    "graph": GRAPH_RESOURCE,
    "powerbi": POWERBI_RESOURCE,
}
AMBIENT_SCOPES = frozenset(
    {"openid", "profile", "email", "offline_access"}
)


class AuthenticationError(RuntimeError):
    """Authentication failed without exposing token or provider internals."""


class TokenProvider:
    """Acquire and validate delegated tokens for one tenant-bound resource."""

    def __init__(
        self,
        settings: Settings,
        *,
        scopes: tuple[str, ...] | None = None,
        resource: str = "graph",
    ) -> None:
        if resource not in RESOURCE_URIS:
            raise ValueError("unsupported OAuth resource")
        self.settings = settings
        self.resource = resource
        self.expected_scopes = tuple(scopes or settings.scopes)
        if not self.expected_scopes:
            raise ValueError("OAuth resource requires at least one expected scope")
        self.oauth_scopes = self._oauth_scopes()
        self._cache = msal.SerializableTokenCache()
        self._load_cache()
        self._app: msal.PublicClientApplication | None = None
        self._lock = asyncio.Lock()

    def _get_app(self) -> msal.PublicClientApplication:
        """Build MSAL lazily so listing MCP tools never triggers network discovery."""

        if self._app is None:
            self._app = msal.PublicClientApplication(
                client_id=self.settings.client_id,
                authority=self.settings.authority,
                token_cache=self._cache,
            )
        return self._app

    def _load_cache(self) -> None:
        if self.settings.token_cache_mode == MEMORY_CACHE_MODE:
            return
        try:
            serialized = keyring.get_password(
                self.settings.keyring_service,
                self.settings.cache_username_for(self.resource),
            )
        except KeyringError as exc:
            raise AuthenticationError(
                "OS keychain is unavailable; refusing to persist tokens insecurely. "
                "Fix the keychain or explicitly use M365_TOKEN_CACHE_MODE=memory."
            ) from exc
        if serialized:
            self._cache.deserialize(serialized)

    def _save_cache(self) -> None:
        if (  # noqa: S105
            self.settings.token_cache_mode == MEMORY_CACHE_MODE or not self._cache.has_state_changed
        ):
            return
        try:
            keyring.set_password(
                self.settings.keyring_service,
                self.settings.cache_username_for(self.resource),
                self._cache.serialize(),
            )
        except KeyringError as exc:
            raise AuthenticationError("could not store the token cache in the OS keychain") from exc

    def _select_account(self) -> dict[str, Any] | None:
        accounts: list[dict[str, Any]] = self._get_app().get_accounts()
        if not accounts:
            return None

        allowed_ids = self.settings.allowed_user_ids
        allowed_domains = self.settings.upn_domains
        candidates: list[dict[str, Any]] = []
        for account in accounts:
            local_id = str(account.get("local_account_id", "")).lower()
            account_object_id = local_id.split(".", 1)[0]
            username = str(account.get("username", "")).lower()
            domain = username.rsplit("@", 1)[-1] if "@" in username else ""
            if allowed_ids and account_object_id not in allowed_ids:
                continue
            if allowed_domains and domain not in allowed_domains:
                continue
            candidates.append(account)

        if len(candidates) > 1:
            raise AuthenticationError(
                "multiple cached accounts match policy; configure an object-ID allowlist "
                "that selects exactly one principal"
            )
        return candidates[0] if candidates else None

    async def get_access_token(self, *, force_refresh: bool = False) -> str:
        """Return a delegated access token; never expose refresh tokens to MCP clients."""

        async with self._lock:
            result = await asyncio.to_thread(self._acquire_token, force_refresh)
            token = result.get("access_token")
            if not isinstance(token, str) or not token:
                code = str(result.get("error", "authentication_failed"))
                correlation = str(result.get("correlation_id", "unavailable"))
                raise AuthenticationError(
                    f"Microsoft authentication failed ({code}); correlation ID: {correlation}"
                )
            self._validate_access_token(token)
            self._save_cache()
            return token

    def _acquire_token(self, force_refresh: bool) -> dict[str, Any]:
        app = self._get_app()
        account = self._select_account()
        if account is not None:
            silent = app.acquire_token_silent(
                scopes=list(self.oauth_scopes),
                account=account,
                force_refresh=force_refresh,
            )
            if silent and "access_token" in silent:
                return dict(silent)

        if self.settings.auth_flow == "interactive":
            result = app.acquire_token_interactive(
                scopes=list(self.oauth_scopes),
                port=0,
                parent_window_handle=None,
                prompt="select_account",
            )
            return dict(result)

        flow = app.initiate_device_flow(scopes=list(self.oauth_scopes))
        if "user_code" not in flow:
            return dict(flow)
        message = str(flow.get("message", "Complete Microsoft sign-in in your browser."))
        print(message, file=sys.stderr, flush=True)
        return dict(app.acquire_token_by_device_flow(flow))

    def _oauth_scopes(self) -> tuple[str, ...]:
        return (f"{RESOURCE_URIS[self.resource]}/.default",)

    @staticmethod
    def _claims(token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthenticationError(
                "Microsoft access token has an invalid JWT shape"
            )
        try:
            payload = base64.urlsafe_b64decode(
                parts[1] + "=" * (-len(parts[1]) % 4)
            )
            decoded = json.loads(payload)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthenticationError(
                "Microsoft access token claims could not be decoded"
            ) from exc
        if not isinstance(decoded, dict):
            raise AuthenticationError(
                "Microsoft access token claims have an invalid shape"
            )
        return dict(decoded)

    @staticmethod
    def _short_scope(scope: str) -> str:
        return scope.rsplit("/", 1)[-1].lower()

    def _validate_access_token(self, token: str) -> None:
        """Fail closed on tenant, audience, lifetime, principal, and scope drift."""

        claims = self._claims(token)
        tenant_id = str(claims.get("tid", "")).lower()
        if tenant_id != self.settings.tenant_id.lower():
            raise AuthenticationError(
                "Microsoft token tenant does not match the tenant-bound policy"
            )

        audience = str(claims.get("aud", "")).rstrip("/")
        if audience not in RESOURCE_AUDIENCES[self.resource]:
            raise AuthenticationError(
                "Microsoft token audience does not match the requested API"
            )

        try:
            issuer = urlparse(str(claims.get("iss", "")))
            issuer_port = issuer.port
        except ValueError as exc:
            raise AuthenticationError(
                "Microsoft token issuer does not match the tenant-bound policy"
            ) from exc
        trusted_issuer = (
            issuer.scheme == "https"
            and issuer.hostname
            in {"login.microsoftonline.com", "sts.windows.net"}
            and issuer_port in {None, 443}
            and issuer.username is None
            and issuer.password is None
            and not issuer.query
            and not issuer.fragment
            and self.settings.tenant_id.lower()
            in issuer.path.lower().split("/")
        )
        if not trusted_issuer:
            raise AuthenticationError(
                "Microsoft token issuer does not match the tenant-bound policy"
            )

        now = time.time()
        try:
            expires = float(claims["exp"])
            not_before = float(claims.get("nbf", 0))
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError(
                "Microsoft token lifetime claims are invalid"
            ) from exc
        if expires <= now - 300 or not_before > now + 300:
            raise AuthenticationError(
                "Microsoft token is expired or not yet valid"
            )

        token_object_id = str(claims.get("oid", "")).lower()
        if (
            self.settings.allowed_user_ids
            and token_object_id not in self.settings.allowed_user_ids
        ):
            raise AuthenticationError(
                "Microsoft token principal is not in the object-ID allowlist"
            )

        actual_scopes = {
            item.lower()
            for item in str(claims.get("scp", "")).split()
            if item
        }
        expected_scopes = {
            self._short_scope(item) for item in self.expected_scopes
        }
        missing = expected_scopes - actual_scopes
        if missing:
            raise AuthenticationError(
                "Microsoft token is missing admin-preconsented delegated scopes"
            )
        unexpected = actual_scopes - expected_scopes - AMBIENT_SCOPES
        if (
            unexpected
            and self.settings.reject_unexpected_token_scopes
        ):
            raise AuthenticationError(
                "Microsoft token contains scopes outside the compiled policy; "
                "use a dedicated App Registration for this tenant and profile"
            )
