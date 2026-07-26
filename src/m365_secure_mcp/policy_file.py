"""Owner-only policy bundles for private tenant and resource configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .config import Settings
from .security import PrivateStateError, open_private_file, read_private_file

POLICY_SCHEMA_VERSION = "1.0"
MAX_POLICY_BYTES = 256_000


def _read_owner_only(path: Path) -> bytes:
    """Read an existing regular mode-0600 file without following symlinks."""

    return read_private_file(
        path,
        max_bytes=MAX_POLICY_BYTES,
        label="private policy",
    )


def _document(settings: Settings) -> dict[str, Any]:
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "settings": settings.model_dump(mode="json"),
    }


def export_private_policy(settings: Settings, path: Path) -> None:
    """Create a new owner-only policy file and refuse to overwrite any path."""

    payload = (
        json.dumps(
            _document(settings),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    if len(payload) > MAX_POLICY_BYTES:
        raise PrivateStateError("private policy exceeds the configured byte limit")
    descriptor = open_private_file(
        path.expanduser(),
        os.O_WRONLY | os.O_EXCL,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_private_policy(path: Path) -> Settings:
    """Load and strictly validate one owner-only policy document."""

    try:
        document = json.loads(_read_owner_only(path.expanduser()))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrivateStateError("private policy is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise PrivateStateError("private policy root must be a JSON object")
    if set(document) != {"schema_version", "settings"}:
        raise PrivateStateError(
            "private policy accepts only schema_version and settings at its root"
        )
    if document.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise PrivateStateError("private policy schema version is unsupported")
    values = document.get("settings")
    if not isinstance(values, dict):
        raise PrivateStateError("private policy settings must be a JSON object")
    unknown = set(values) - set(Settings.model_fields)
    if unknown:
        raise PrivateStateError(
            f"private policy contains unknown settings: {sorted(unknown)}"
        )
    return Settings.model_validate(values)
