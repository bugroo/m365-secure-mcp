from __future__ import annotations

import pytest

from m365_secure_mcp.config import Settings

TENANT_ID = "11111111-1111-4111-8111-111111111111"
CLIENT_ID = "22222222-2222-4222-8222-222222222222"
USER_ID = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        allowed_user_object_ids=USER_ID,
        allowed_upn_domains="example.com",
        allowed_recipient_domains="example.com",
    )
