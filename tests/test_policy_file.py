from __future__ import annotations

import json
from pathlib import Path

import pytest

from m365_secure_mcp.config import Settings
from m365_secure_mcp.policy_file import export_private_policy, load_private_policy
from m365_secure_mcp.security import PrivateStateError

from .conftest import CLIENT_ID, TENANT_ID, USER_ID


def make_settings(tmp_path: Path) -> Settings:
    return Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        allowed_user_object_ids=USER_ID,
        allowed_upn_domains="example.com",
        modules="profile,planner",
        allowed_plan_ids="private-plan-id",
        audit_log_path=tmp_path / "state" / "audit.jsonl",
        idempotency_db_path=tmp_path / "state" / "writes.sqlite3",
    )


def test_private_policy_round_trip_is_owner_only(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    path = tmp_path / "private" / "read-policy.json"

    export_private_policy(settings, path)
    loaded = load_private_policy(path)

    assert loaded.policy_digest == settings.policy_digest
    assert loaded.plan_ids == frozenset({"private-plan-id"})
    assert path.stat().st_mode & 0o077 == 0
    assert path.parent.stat().st_mode & 0o077 == 0
    assert "access_token" not in path.read_text().lower()
    assert "client_secret" not in path.read_text().lower()


def test_private_policy_never_overwrites_existing_file(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    path = tmp_path / "private" / "read-policy.json"
    export_private_policy(settings, path)

    with pytest.raises(PrivateStateError, match="could not be opened safely"):
        export_private_policy(settings, path)


def test_private_policy_rejects_broad_permissions(tmp_path: Path) -> None:
    path = tmp_path / "private" / "read-policy.json"
    export_private_policy(make_settings(tmp_path), path)
    path.chmod(0o644)

    with pytest.raises(PrivateStateError, match="mode-0600"):
        load_private_policy(path)


def test_private_policy_rejects_unknown_settings(tmp_path: Path) -> None:
    path = tmp_path / "private" / "read-policy.json"
    export_private_policy(make_settings(tmp_path), path)
    document = json.loads(path.read_text())
    document["settings"]["typo_write_enable"] = True
    path.write_text(json.dumps(document))
    path.chmod(0o600)

    with pytest.raises(PrivateStateError, match="unknown settings"):
        load_private_policy(path)


def test_private_policy_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "private" / "read-policy.json"
    export_private_policy(make_settings(tmp_path), target)
    link = tmp_path / "private" / "linked-policy.json"
    link.symlink_to(target)

    with pytest.raises(PrivateStateError, match="opened safely"):
        load_private_policy(link)
