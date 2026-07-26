from __future__ import annotations

import json
from pathlib import Path

import pytest

from m365_secure_mcp.security import (
    AuditLogger,
    CursorCodec,
    Principal,
    SecurityError,
    SecurityPolicy,
    clean_external_text,
    html_to_plain_text,
    path_segment,
    validate_graph_url,
)

from .conftest import USER_ID


def test_graph_url_allowlist_accepts_only_v1_https() -> None:
    valid = "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc"
    assert validate_graph_url(valid) == valid
    for invalid in (
        "http://graph.microsoft.com/v1.0/me",
        "https://evil.example/v1.0/me",
        "https://graph.microsoft.com/beta/me",
        "https://user@graph.microsoft.com/v1.0/me",
        "https://graph.microsoft.com/v1.0/me#fragment",
    ):
        with pytest.raises(SecurityError):
            validate_graph_url(invalid)


def test_signed_cursor_cannot_be_forged_or_reused_across_tools() -> None:
    codec = CursorCodec(secret=b"x" * 32)
    url = "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc"
    cursor = codec.encode("mail", url)
    assert codec.decode("mail", cursor) == url
    with pytest.raises(SecurityError, match="different tool"):
        codec.decode("files", cursor)
    replacement = ("A" if cursor[0] != "A" else "B") + cursor[1:]
    with pytest.raises(SecurityError):
        codec.decode("mail", replacement)


def test_html_is_reduced_to_visible_plain_text() -> None:
    source = (
        "<style>secret-style</style><p>Hello</p>"
        "<script>stealTokens()</script><svg>hidden</svg><div>World</div>"
    )
    text = html_to_plain_text(source)
    assert "Hello" in text
    assert "World" in text
    assert "stealTokens" not in text
    assert "secret-style" not in text
    assert "hidden" not in text


def test_external_text_removes_control_characters_and_caps_size() -> None:
    assert clean_external_text("a\x00b\x07c", 10) == "abc"
    assert "truncated" in clean_external_text("x" * 100, 10)


def test_path_identifier_is_encoded_not_interpreted() -> None:
    assert path_segment("../messages/other") == "..%2Fmessages%2Fother"
    with pytest.raises(SecurityError):
        path_segment("bad\x00id")


def test_principal_and_recipient_policy(settings: object) -> None:
    policy = SecurityPolicy(settings)  # type: ignore[arg-type]
    policy.authorize_principal(
        Principal(
            object_id=USER_ID,
            user_principal_name="person@example.com",
            mail="person@example.com",
        )
    )
    assert policy.authorize_recipient("Person@Example.com") == "person@example.com"
    with pytest.raises(SecurityError, match="recipient domain"):
        policy.authorize_recipient("person@external.example")


def test_audit_log_contains_no_raw_parameters(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    logger = AuditLogger(path)
    logger.record(
        tool="m365_search_mail",
        outcome="success",
        parameters={"query": "very sensitive subject"},
    )
    content = path.read_text()
    assert "very sensitive subject" not in content
    record = json.loads(content)
    assert record["tool"] == "m365_search_mail"
    assert len(record["parameter_sha256"]) == 64
    assert path.stat().st_mode & 0o077 == 0


def test_private_state_rejects_symlinks_and_broad_directories(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("unchanged")
    link = tmp_path / "linked.jsonl"
    link.symlink_to(target)

    with pytest.raises(SecurityError, match="could not be opened safely"):
        AuditLogger(link).record(tool="tool", outcome="attempt")
    assert target.read_text() == "unchanged"

    broad = tmp_path / "broad"
    broad.mkdir()
    broad.chmod(0o755)
    with pytest.raises(SecurityError, match="permissions must be 0700"):
        AuditLogger(broad / "audit.jsonl").record(tool="tool", outcome="attempt")
