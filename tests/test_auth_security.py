from __future__ import annotations

import base64
import json
import time

import pytest

from m365_secure_mcp.auth import AuthenticationError, TokenProvider
from m365_secure_mcp.config import Settings

from .conftest import CLIENT_ID, TENANT_ID, USER_ID


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
        "allowed_user_object_ids": USER_ID,
        "modules": "profile,mail",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _jwt(**overrides: object) -> str:
    claims: dict[str, object] = {
        "tid": TENANT_ID,
        "aud": "https://graph.microsoft.com",
        "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        "oid": USER_ID,
        "exp": int(time.time()) + 3_600,
        "nbf": int(time.time()) - 60,
        "scp": "Mail.Read User.Read",
    }
    claims.update(overrides)
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).decode().rstrip("=")
    return f"header.{payload}.signature"


def test_admin_preconsented_default_is_the_only_oauth_request() -> None:
    provider = TokenProvider(_settings())
    assert provider.oauth_scopes == (
        "https://graph.microsoft.com/.default",
    )


def test_token_claims_are_bound_to_tenant_principal_audience_and_scope() -> None:
    provider = TokenProvider(_settings())
    provider._validate_access_token(_jwt())  # noqa: SLF001

    for token, message in (
        (_jwt(tid=CLIENT_ID), "tenant"),
        (_jwt(oid=CLIENT_ID), "principal"),
        (_jwt(aud="https://example.invalid"), "audience"),
        (
            _jwt(
                iss=(
                    f"https://login.microsoftonline.com/{TENANT_ID}/"
                    "v2.0?redirect=unsafe"
                )
            ),
            "issuer",
        ),
        (_jwt(scp="User.Read"), "missing"),
        (_jwt(scp="Mail.Read User.Read Files.Read"), "outside"),
    ):
        with pytest.raises(AuthenticationError, match=message):
            provider._validate_access_token(token)  # noqa: SLF001


def test_powerbi_token_uses_its_own_audience() -> None:
    scope = (
        "https://analysis.windows.net/powerbi/api/Dataset.Read.All",
    )
    provider = TokenProvider(
        _settings(modules="profile"),
        scopes=scope,
        resource="powerbi",
    )
    assert provider.oauth_scopes == (
        "https://analysis.windows.net/powerbi/api/.default",
    )
    provider._validate_access_token(  # noqa: SLF001
        _jwt(
            aud="https://analysis.windows.net/powerbi/api",
            scp="Dataset.Read.All",
        )
    )


@pytest.mark.asyncio
async def test_assurance_scope_view_exposes_names_but_not_ambient_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = TokenProvider(_settings())

    async def validated_token() -> str:
        return _jwt(
            scp="openid profile offline_access Mail.Read User.Read"
        )

    monkeypatch.setattr(provider, "get_access_token", validated_token)

    scopes = await provider.get_delegated_scope_claims()

    assert scopes == frozenset({"Mail.Read", "User.Read"})
