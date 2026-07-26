from __future__ import annotations

from types import SimpleNamespace

import pytest

from m365_secure_mcp.catalog import (
    SPECS,
    ReadSpec,
    _apply_policies,
    _filter_items,
)
from m365_secure_mcp.config import Settings
from m365_secure_mcp.models import CatalogReadInput
from m365_secure_mcp.security import SecurityError, SecurityPolicy

from .conftest import CLIENT_ID, TENANT_ID

APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"


def _services() -> SimpleNamespace:
    settings = Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        allowed_application_ids=APPLICATION_ID,
        allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
    )
    return SimpleNamespace(
        settings=settings,
        policy=SecurityPolicy(settings),
    )


def _spec(name: str) -> ReadSpec:
    return next(spec for spec in SPECS if spec.name == name)


def test_entra_object_reads_enforce_local_uuid_allowlists() -> None:
    services = _services()
    _apply_policies(
        _spec("m365_get_application"),
        CatalogReadInput(application_id=APPLICATION_ID),
        services,
    )
    with pytest.raises(SecurityError, match="not allowlisted"):
        _apply_policies(
            _spec("m365_get_application"),
            CatalogReadInput(
                application_id="77777777-7777-4777-8777-777777777777"
            ),
            services,
        )


def test_entra_inventory_filters_out_every_non_allowlisted_object() -> None:
    services = _services()
    items = [
        {"id": APPLICATION_ID, "displayName": "Allowed"},
        {
            "id": "77777777-7777-4777-8777-777777777777",
            "displayName": "Blocked",
        },
    ]
    filtered = _filter_items(
        _spec("m365_list_allowed_applications"),
        items,
        services,
    )
    assert filtered == [{"id": APPLICATION_ID, "displayName": "Allowed"}]


def test_license_endpoints_do_not_send_unsupported_top_parameter() -> None:
    for name in ("m365_list_subscribed_skus", "m365_list_domains"):
        spec = _spec(name)
        assert spec.supports_top is False
