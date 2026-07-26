"""Owner-only policy bundles for private tenant and resource configuration."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .config import Settings
from .security import PrivateStateError, open_private_file

POLICY_SCHEMA_VERSION = "1.0"
MAX_POLICY_BYTES = 256_000


def _read_owner_only(path: Path) -> bytes:
    """Read an existing regular mode-0600 file without following symlinks."""

    parent = path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        raise PrivateStateError("private policy parent directory does not exist") from exc
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent.is_symlink()
        or (hasattr(os, "getuid") and parent_stat.st_uid != os.getuid())
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise PrivateStateError(
            "private policy parent must be a current-user-owned mode-0700 directory"
        )

    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise PrivateStateError("private policy file could not be opened safely") from exc
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or (hasattr(os, "getuid") and file_stat.st_uid != os.getuid())
            or stat.S_IMODE(file_stat.st_mode) & 0o077
        ):
            raise PrivateStateError(
                "private policy must be a current-user-owned regular mode-0600 file"
            )
        if file_stat.st_size > MAX_POLICY_BYTES:
            raise PrivateStateError("private policy exceeds the configured byte limit")
        content = os.read(descriptor, MAX_POLICY_BYTES + 1)
        if len(content) > MAX_POLICY_BYTES:
            raise PrivateStateError("private policy exceeds the configured byte limit")
        return content
    finally:
        os.close(descriptor)


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

