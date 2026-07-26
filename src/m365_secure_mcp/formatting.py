"""Context-efficient and provenance-aware tool response formatting."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from .models import ResponseFormat
from .security import UNTRUSTED_CONTENT_NOTICE, clean_external_text


def _truncate_items(payload: dict[str, Any], key: str, character_limit: int) -> dict[str, Any]:
    rendered = json.dumps(payload, ensure_ascii=False, default=str)
    items = payload.get(key)
    if len(rendered) <= character_limit or not isinstance(items, list):
        return payload
    original = len(items)
    while items and len(json.dumps(payload, ensure_ascii=False, default=str)) > character_limit:
        items.pop()
    payload["truncated"] = True
    payload["truncation_message"] = (
        f"Response reduced from {original} to {len(items)} items. "
        "Use filters or the signed cursor to request a narrower page."
    )
    return payload


def render_collection(
    *,
    title: str,
    key: str,
    items: list[dict[str, Any]],
    response_format: ResponseFormat,
    character_limit: int,
    cursor: str | None = None,
    external_content: bool = True,
) -> str:
    payload: dict[str, Any] = {
        "count": len(items),
        key: items,
        "has_more": cursor is not None,
        "next_cursor": cursor,
    }
    if external_content:
        payload["content_is_untrusted"] = True
        payload["security_notice"] = UNTRUSTED_CONTENT_NOTICE
    payload = _truncate_items(payload, key, character_limit)
    if response_format is ResponseFormat.JSON:
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)

    lines = [f"# {title}", ""]
    if external_content:
        lines.extend([f"> {UNTRUSTED_CONTENT_NOTICE}", ""])
    if not payload[key]:
        lines.append("No results.")
    for index, item in enumerate(payload[key], start=1):
        label = clean_external_text(
            item.get("subject") or item.get("name") or item.get("displayName") or f"Item {index}",
            300,
        )
        lines.append(f"## {index}. {label}")
        for field, value in item.items():
            if field in {"subject", "name", "displayName"} or value in (None, "", []):
                continue
            if isinstance(value, (dict, list)):
                text = json.dumps(value, ensure_ascii=False, default=str)
            else:
                text = clean_external_text(value, 4_000)
            lines.append(f"- **{field}**: {text}")
        lines.append("")
    if payload.get("truncation_message"):
        lines.append(str(payload["truncation_message"]))
    if cursor:
        lines.extend(["", f"Next signed cursor: `{cursor}`"])
    return "\n".join(lines)[:character_limit]


def render_record(
    *,
    title: str,
    record: Mapping[str, Any],
    response_format: ResponseFormat,
    character_limit: int,
    external_content: bool = True,
) -> str:
    payload = dict(record)
    if external_content:
        payload["content_is_untrusted"] = True
        payload["security_notice"] = UNTRUSTED_CONTENT_NOTICE
    if response_format is ResponseFormat.JSON:
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)[:character_limit]
    lines = [f"# {title}", ""]
    if external_content:
        lines.extend([f"> {UNTRUSTED_CONTENT_NOTICE}", ""])
    for field, value in payload.items():
        if field in {"security_notice", "content_is_untrusted"} or value in (None, "", []):
            continue
        text = (
            json.dumps(value, ensure_ascii=False, default=str)
            if isinstance(value, (dict, list))
            else clean_external_text(value, 8_000)
        )
        lines.append(f"- **{field}**: {text}")
    return "\n".join(lines)[:character_limit]


def addresses(values: Iterable[Mapping[str, Any]]) -> list[str]:
    result: list[str] = []
    for value in values:
        address = value.get("emailAddress", {}).get("address")
        if address:
            result.append(clean_external_text(address, 320))
    return result
