"""Bounded OOXML text extraction and replacement without executing Office content."""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from xml.etree import ElementTree

from .security import SecurityError, clean_external_text

WORD_TEXT_TAG = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"
WORD_PARAGRAPH_TAG = (
    "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"
)
DRAWING_TEXT_TAG = (
    "{http://schemas.openxmlformats.org/drawingml/2006/main}t"
)
SLIDE_NUMBER = re.compile(r"^ppt/slides/slide([1-9][0-9]*)\.xml$")
NOTES_NUMBER = re.compile(r"^ppt/notesSlides/notesSlide([1-9][0-9]*)\.xml$")
WORD_TEXT_PART = re.compile(
    r"^word/(?:document|footnotes|endnotes|comments|header[1-9][0-9]*|"
    r"footer[1-9][0-9]*)\.xml$"
)
UNSAFE_XML_DECLARATION = re.compile(
    br"<!DOCTYPE|<!ENTITY",
    re.IGNORECASE,
)
ACTIVE_PACKAGE_MARKERS = (
    "vbaproject.bin",
    "/activex/",
    "/embeddings/",
    "/oleobjects/",
)
MAX_COMPRESSION_RATIO = 200


@dataclass(frozen=True)
class OOXMLReadResult:
    """Safe text representation of one bounded OOXML package."""

    kind: str
    text: str
    parts_read: int
    truncated: bool


@dataclass(frozen=True)
class OOXMLWriteResult:
    """Rebuilt OOXML package and deterministic replacement evidence."""

    content: bytes
    replacements: dict[str, int]
    parts_modified: int


def _safe_member_name(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        raise SecurityError("Office package contains an invalid member path")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise SecurityError("Office package contains a traversal member path")
    return path.as_posix()


def _validate_xml(content: bytes) -> None:
    # Parts are already bounded by the package policy. Scan the complete part so
    # declarations cannot be hidden behind a long prologue.
    if UNSAFE_XML_DECLARATION.search(content):
        raise SecurityError("Office package XML declarations are not allowed")


def _validated_members(
    archive: zipfile.ZipFile,
    *,
    max_members: int,
    max_expanded_bytes: int,
) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if not infos or len(infos) > max_members:
        raise SecurityError("Office package member count exceeds policy")
    members: dict[str, zipfile.ZipInfo] = {}
    expanded = 0
    for info in infos:
        name = _safe_member_name(info.filename)
        lowered = f"/{name.lower()}"
        if any(marker in lowered for marker in ACTIVE_PACKAGE_MARKERS):
            raise SecurityError(
                "Office package contains macros, ActiveX, or embedded objects"
            )
        if info.flag_bits & 0x1:
            raise SecurityError("encrypted Office packages are not supported")
        if name in members:
            raise SecurityError("Office package contains duplicate member names")
        expanded += info.file_size
        if expanded > max_expanded_bytes:
            raise SecurityError("Office package expanded size exceeds policy")
        if (
            info.file_size > 1_000_000
            and info.compress_size > 0
            and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
        ):
            raise SecurityError("Office package compression ratio exceeds policy")
        members[name] = info
    return members


def _open_validated(
    content: bytes,
    *,
    max_file_bytes: int,
    max_members: int,
    max_expanded_bytes: int,
) -> tuple[zipfile.ZipFile, dict[str, zipfile.ZipInfo]]:
    if not content or len(content) > max_file_bytes:
        raise SecurityError("Office package size is outside policy")
    if not content.startswith(b"PK"):
        raise SecurityError("Office content is not an OOXML ZIP package")
    buffer = io.BytesIO(content)
    try:
        archive = zipfile.ZipFile(buffer, "r")
        members = _validated_members(
            archive,
            max_members=max_members,
            max_expanded_bytes=max_expanded_bytes,
        )
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise SecurityError("Office package could not be opened safely") from exc
    return archive, members


def _xml_root(archive: zipfile.ZipFile, member: str) -> ElementTree.Element:
    try:
        content = archive.read(member)
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise SecurityError("Office package XML part could not be read") from exc
    _validate_xml(content)
    try:
        # XML entities and doctypes are rejected above; package/member sizes are
        # bounded before this standard-library parser is reached.
        return ElementTree.fromstring(content)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise SecurityError("Office package contains malformed XML") from exc


def _ordered_word_parts(members: Iterable[str]) -> list[str]:
    return sorted(
        (name for name in members if WORD_TEXT_PART.fullmatch(name)),
        key=lambda item: (
            item != "word/document.xml",
            item,
        ),
    )


def _numbered_parts(
    members: Iterable[str],
    pattern: re.Pattern[str],
) -> list[str]:
    numbered: list[tuple[int, str]] = []
    for name in members:
        match = pattern.fullmatch(name)
        if match:
            numbered.append((int(match.group(1)), name))
    return [name for _, name in sorted(numbered)]


def _bounded_text(parts: list[str], max_characters: int) -> tuple[str, bool]:
    normalized = "\n\n".join(item for item in parts if item).strip()
    truncated = len(normalized) > max_characters
    return clean_external_text(normalized, max_characters), truncated


def extract_word_text(
    content: bytes,
    *,
    max_file_bytes: int,
    max_members: int,
    max_expanded_bytes: int,
    max_characters: int,
) -> OOXMLReadResult:
    """Extract paragraph text from a macro-free DOCX package."""

    archive, members = _open_validated(
        content,
        max_file_bytes=max_file_bytes,
        max_members=max_members,
        max_expanded_bytes=max_expanded_bytes,
    )
    try:
        if "word/document.xml" not in members:
            raise SecurityError("Word package is missing word/document.xml")
        parts = _ordered_word_parts(members)
        output: list[str] = []
        for member in parts:
            root = _xml_root(archive, member)
            paragraphs: list[str] = []
            for paragraph in root.iter(WORD_PARAGRAPH_TAG):
                text = "".join(
                    node.text or ""
                    for node in paragraph.iter(WORD_TEXT_TAG)
                ).strip()
                if text:
                    paragraphs.append(text)
            if paragraphs:
                output.append(
                    f"[{member}]\n" + "\n".join(paragraphs)
                )
        text, truncated = _bounded_text(output, max_characters)
        return OOXMLReadResult(
            kind="word",
            text=text,
            parts_read=len(parts),
            truncated=truncated,
        )
    finally:
        archive.close()


def extract_powerpoint_text(
    content: bytes,
    *,
    max_file_bytes: int,
    max_members: int,
    max_expanded_bytes: int,
    max_characters: int,
    include_notes: bool = False,
) -> OOXMLReadResult:
    """Extract visible text from a macro-free PPTX package."""

    archive, members = _open_validated(
        content,
        max_file_bytes=max_file_bytes,
        max_members=max_members,
        max_expanded_bytes=max_expanded_bytes,
    )
    try:
        if "ppt/presentation.xml" not in members:
            raise SecurityError("PowerPoint package is missing ppt/presentation.xml")
        parts = _numbered_parts(members, SLIDE_NUMBER)
        if include_notes:
            parts.extend(_numbered_parts(members, NOTES_NUMBER))
        if not parts:
            raise SecurityError("PowerPoint package contains no readable slides")
        output: list[str] = []
        for member in parts:
            root = _xml_root(archive, member)
            text = "\n".join(
                (node.text or "").strip()
                for node in root.iter(DRAWING_TEXT_TAG)
                if (node.text or "").strip()
            )
            if text:
                output.append(f"[{member}]\n{text}")
        text, truncated = _bounded_text(output, max_characters)
        return OOXMLReadResult(
            kind="powerpoint",
            text=text,
            parts_read=len(parts),
            truncated=truncated,
        )
    finally:
        archive.close()


def _replacement_parts(
    kind: str,
    members: Iterable[str],
    *,
    include_notes: bool,
) -> tuple[list[str], str]:
    if kind == "word":
        parts = _ordered_word_parts(members)
        required = "word/document.xml"
    elif kind == "powerpoint":
        parts = _numbered_parts(members, SLIDE_NUMBER)
        if include_notes:
            parts.extend(_numbered_parts(members, NOTES_NUMBER))
        required = "ppt/presentation.xml"
    else:
        raise SecurityError("unsupported OOXML document kind")
    return parts, required


def replace_ooxml_text(
    content: bytes,
    replacements: Mapping[str, str],
    *,
    kind: str,
    max_file_bytes: int,
    max_members: int,
    max_expanded_bytes: int,
    include_notes: bool = False,
) -> OOXMLWriteResult:
    """Replace text inside individual OOXML text runs and rebuild the package."""

    if not replacements or len(replacements) > 20:
        raise SecurityError("Office text replacement count is outside policy")
    if any(
        not old
        or old == new
        or len(old) > 2_000
        or len(new) > 4_000
        for old, new in replacements.items()
    ):
        raise SecurityError("Office text replacement values are outside policy")

    archive, members = _open_validated(
        content,
        max_file_bytes=max_file_bytes,
        max_members=max_members,
        max_expanded_bytes=max_expanded_bytes,
    )
    try:
        parts, required = _replacement_parts(
            kind,
            members,
            include_notes=include_notes,
        )
        if required not in members:
            raise SecurityError("Office package does not match the requested kind")
        text_tag = WORD_TEXT_TAG if kind == "word" else DRAWING_TEXT_TAG
        modified: dict[str, bytes] = {}
        counts = {old: 0 for old in replacements}
        for member in parts:
            root = _xml_root(archive, member)
            part_changed = False
            for node in root.iter(text_tag):
                text = node.text or ""
                updated = text
                for old, new in replacements.items():
                    occurrences = updated.count(old)
                    if occurrences:
                        updated = updated.replace(old, new)
                        counts[old] += occurrences
                if updated != text:
                    node.text = updated
                    part_changed = True
            if part_changed:
                modified[member] = ElementTree.tostring(
                    root,
                    encoding="utf-8",
                    xml_declaration=True,
                )

        if not any(counts.values()):
            raise SecurityError(
                "none of the requested text was found inside a single Office text run"
            )

        output = io.BytesIO()
        try:
            with zipfile.ZipFile(
                output,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
                strict_timestamps=True,
            ) as rebuilt:
                for info in archive.infolist():
                    name = _safe_member_name(info.filename)
                    data = modified.get(name)
                    if data is None:
                        data = archive.read(info)
                    rebuilt.writestr(info, data)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise SecurityError("Office package could not be rebuilt safely") from exc
        rebuilt_content = output.getvalue()
        if len(rebuilt_content) > max_file_bytes:
            raise SecurityError("rebuilt Office package exceeds policy")
        return OOXMLWriteResult(
            content=rebuilt_content,
            replacements=counts,
            parts_modified=len(modified),
        )
    finally:
        archive.close()
