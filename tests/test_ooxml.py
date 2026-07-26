from __future__ import annotations

import io
import zipfile
from uuid import uuid4

import pytest

from m365_secure_mcp.models import UpdateWorkbookRangeInput
from m365_secure_mcp.ooxml import (
    extract_powerpoint_text,
    extract_word_text,
    replace_ooxml_text,
)
from m365_secure_mcp.security import SecurityError

LIMITS = {
    "max_file_bytes": 1_000_000,
    "max_members": 100,
    "max_expanded_bytes": 2_000_000,
}


def _package(parts: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for name, content in parts.items():
            archive.writestr(name, content)
    return output.getvalue()


def _word(text: str = "Secure tenant") -> bytes:
    return _package(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": (
                "<?xml version='1.0'?>"
                "<w:document "
                "xmlns:w='http://schemas.openxmlformats.org/"
                "wordprocessingml/2006/main'>"
                f"<w:body><w:p><w:r><w:t>{text}</w:t>"
                "</w:r></w:p></w:body></w:document>"
            ).encode(),
        }
    )


def _powerpoint(text: str = "MSP baseline") -> bytes:
    return _package(
        {
            "[Content_Types].xml": b"<Types/>",
            "ppt/presentation.xml": b"<p:presentation xmlns:p='urn:p'/>",
            "ppt/slides/slide1.xml": (
                "<?xml version='1.0'?>"
                "<p:sld xmlns:p='urn:p' "
                "xmlns:a='http://schemas.openxmlformats.org/"
                "drawingml/2006/main'>"
                f"<a:t>{text}</a:t></p:sld>"
            ).encode(),
        }
    )


def test_word_text_is_extracted_and_replaced_without_new_dependencies() -> None:
    original = _word()
    extracted = extract_word_text(
        original,
        max_characters=10_000,
        **LIMITS,
    )
    assert "Secure tenant" in extracted.text
    assert extracted.parts_read == 1

    changed = replace_ooxml_text(
        original,
        {"Secure tenant": "Isolated customer tenant"},
        kind="word",
        **LIMITS,
    )
    assert changed.replacements == {"Secure tenant": 1}
    assert changed.parts_modified == 1
    verified = extract_word_text(
        changed.content,
        max_characters=10_000,
        **LIMITS,
    )
    assert "Isolated customer tenant" in verified.text


def test_powerpoint_text_is_extracted_in_slide_order() -> None:
    extracted = extract_powerpoint_text(
        _powerpoint(),
        max_characters=10_000,
        **LIMITS,
    )
    assert extracted.text.endswith("MSP baseline")
    assert extracted.parts_read == 1


@pytest.mark.parametrize(
    "content",
    [
        _package({"../word/document.xml": b"<x/>"}),
        _package(
            {
                "word/document.xml": (
                    b"<!DOCTYPE x [<!ENTITY y 'unsafe'>]><x>&y;</x>"
                )
            }
        ),
        _package(
            {
                "word/document.xml": (
                    b" " * 70_000
                    + b"<!DOCTYPE x [<!ENTITY y 'unsafe'>]><x>&y;</x>"
                )
            }
        ),
        _package(
            {
                "word/document.xml": b"<x/>",
                "word/vbaProject.bin": b"active",
            }
        ),
    ],
)
def test_ooxml_rejects_traversal_entities_and_active_content(
    content: bytes,
) -> None:
    with pytest.raises(SecurityError):
        extract_word_text(
            content,
            max_characters=10_000,
            **LIMITS,
        )


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_excel_write_rejects_formula_like_strings(prefix: str) -> None:
    with pytest.raises(ValueError, match="formula-like"):
        UpdateWorkbookRangeInput.model_validate(
            {
                "drive_id": "drive-1",
                "item_id": "item-1",
                "worksheet": "Sheet 1",
                "address": "A1",
                "values": [[f"{prefix}external-input"]],
                "idempotency_key": str(uuid4()),
            }
        )
