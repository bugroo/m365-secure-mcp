"""Closed compatibility metadata for control semantics missing from M1.

M1 control definitions do not contain signed evidence-freshness metadata.
This public artifact is therefore a temporary compatibility input: it is
canonically digested, bound to one exact control manifest, and must be pinned
by every Governance v2 policy that enables the Control Library.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contract_manifest import sha256_digest
from .control_manifest import CONTROL_ID_PATTERN, ControlManifest

MAX_CONTROL_COMPATIBILITY_BYTES = 128_000
MAX_CONTROL_EVIDENCE_AGE_SECONDS = 2_592_000


class StrictCompatibilityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ControlCompatibilityEntry(StrictCompatibilityModel):
    """Explicit compatibility semantics for one exact control major."""

    control_id: str = Field(pattern=CONTROL_ID_PATTERN)
    definition_major_version: int = Field(
        strict=True,
        ge=1,
        le=1_000_000,
    )
    maximum_evidence_age_seconds: int = Field(
        strict=True,
        ge=1,
        le=MAX_CONTROL_EVIDENCE_AGE_SECONDS,
    )


class ControlCompatibilityMetadata(StrictCompatibilityModel):
    """Canonical M1 bridge bound to one exact signed control manifest."""

    schema_version: Literal["1.0"]
    control_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    controls: list[ControlCompatibilityEntry] = Field(
        min_length=1,
        max_length=500,
    )

    @field_validator("controls")
    @classmethod
    def controls_are_unique_and_sorted(
        cls,
        value: list[ControlCompatibilityEntry],
    ) -> list[ControlCompatibilityEntry]:
        keys = [
            (entry.control_id, entry.definition_major_version)
            for entry in value
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("control compatibility entries must be unique")
        return sorted(
            value,
            key=lambda entry: (
                entry.control_id,
                entry.definition_major_version,
            ),
        )

    def validate_manifest_binding(
        self,
        manifest: ControlManifest,
    ) -> Self:
        """Require exact manifest and complete control-major coverage."""

        if self.control_manifest_digest != sha256_digest(manifest):
            raise ValueError(
                "control compatibility metadata targets another manifest"
            )
        expected = {
            (control.control_id, int(control.definition_version.split(".", 1)[0]))
            for control in manifest.controls
        }
        actual = {
            (entry.control_id, entry.definition_major_version)
            for entry in self.controls
        }
        if actual != expected:
            raise ValueError(
                "control compatibility metadata must cover the exact manifest"
            )
        return self

    def maximum_age(
        self,
        control_id: str,
        definition_major_version: int,
    ) -> int:
        """Return explicit metadata only; no default or fallback exists."""

        for entry in self.controls:
            if (
                entry.control_id == control_id
                and entry.definition_major_version
                == definition_major_version
            ):
                return entry.maximum_evidence_age_seconds
        raise KeyError("control compatibility metadata is unavailable")


def control_compatibility_digest(
    metadata: ControlCompatibilityMetadata,
) -> str:
    """Return the deterministic content digest pinned by Governance v2."""

    return sha256_digest(metadata)


def _compatibility_bytes() -> bytes:
    return (
        files("m365_secure_mcp.contract_data")
        .joinpath("control-compatibility.json")
        .read_bytes()
    )


def load_control_compatibility_metadata(
    manifest: ControlManifest,
) -> ControlCompatibilityMetadata:
    """Load the package-pinned bridge and fail closed on any incompatibility."""

    try:
        payload = _compatibility_bytes()
        if len(payload) > MAX_CONTROL_COMPATIBILITY_BYTES:
            raise ValueError("control compatibility metadata exceeds the byte limit")
        document = json.loads(payload)
        metadata = ControlCompatibilityMetadata.model_validate(document)
        return metadata.validate_manifest_binding(manifest)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "control compatibility metadata is malformed or incompatible"
        ) from exc
