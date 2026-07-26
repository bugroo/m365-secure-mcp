"""Microsoft identity authentication with an OS-keychain token cache."""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import keyring
import msal
from keyring.errors import KeyringError

from .config import Settings

MEMORY_CACHE_MODE = "memory"


class AuthenticationError(RuntimeError):
    """Authentication failed without exposing token or provider internals."""


class TokenProvider:
    """Acquire delegated Microsoft Graph tokens using a tenant-bound MSAL client."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
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
                self.settings.cache_username,
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
                self.settings.cache_username,
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
            username = str(account.get("username", "")).lower()
            domain = username.rsplit("@", 1)[-1] if "@" in username else ""
            if allowed_ids and local_id not in allowed_ids:
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
            self._save_cache()
            return token

    def _acquire_token(self, force_refresh: bool) -> dict[str, Any]:
        app = self._get_app()
        account = self._select_account()
        if account is not None:
            silent = app.acquire_token_silent(
                scopes=list(self.settings.scopes),
                account=account,
                force_refresh=force_refresh,
            )
            if silent and "access_token" in silent:
                return dict(silent)

        if self.settings.auth_flow == "interactive":
            result = app.acquire_token_interactive(
                scopes=list(self.settings.scopes),
                port=0,
                parent_window_handle=None,
            )
            return dict(result)

        flow = app.initiate_device_flow(scopes=list(self.settings.scopes))
        if "user_code" not in flow:
            return dict(flow)
        message = str(flow.get("message", "Complete Microsoft sign-in in your browser."))
        print(message, file=sys.stderr, flush=True)
        return dict(app.acquire_token_by_device_flow(flow))
