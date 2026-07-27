"""Pinned public trust metadata for signed build-plane manifests."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import Final

# This public key is intentionally stored in source. The corresponding private
# key is not part of the repository. Rotating it is a reviewed release change,
# not a runtime operation.
CONTRACT_SIGNING_KEY_ID: Final = "profile-debt-2026-07"
CONTRACT_SIGNING_PUBLIC_KEY_B64: Final = (
    "98l4UGNhmkPkAvMq5vm7kwg5j/wGacQ/6X6r0JGf3ZE="
)

# Playbooks have an independent reviewed build authority. The private key used
# for this release is not part of the repository or runtime.
PLAYBOOK_SIGNING_KEY_ID: Final = "workload-readiness-2026-07"
PLAYBOOK_SIGNING_PUBLIC_KEY_B64: Final = (
    "19GYLej7HERyaBmf6I8xFppaqskYumDxoy4M6+c0PGk="
)

# Posture controls have an independent build authority. Runtime never generates
# or rotates this key and never accepts an unsigned control-manifest fallback.
# The public key is replaced below only by a reviewed manifest-signing change.
class SigningKeyState(StrEnum):
    """Lifecycle states for public verification keys."""

    CURRENT = "current"
    RETIRED = "retired"
    COMPROMISED = "compromised"


class SigningAuthorityClass(StrEnum):
    """Separate production trust anchors from ephemeral test authorities."""

    PRODUCTION = "production"
    TEST = "test"


@dataclass(frozen=True, slots=True)
class ControlSigningAuthority:
    """Public-only metadata for one immutable control signing key ID."""

    key_id: str
    public_key_b64: str
    state: SigningKeyState
    authority_class: SigningAuthorityClass
    activated_on: date
    state_changed_on: date | None = None
    historical_manifest_digests: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        production_id = re.fullmatch(
            r"posture-controls-[0-9]{4}-[0-9]{2}(?:-[a-z0-9]+)*",
            self.key_id,
        )
        test_id = re.fullmatch(
            r"test-posture-controls-[a-z0-9-]{3,80}",
            self.key_id,
        )
        if (
            self.authority_class is SigningAuthorityClass.PRODUCTION
            and production_id is None
        ):
            raise ValueError("production control signing key ID is malformed")
        if self.authority_class is SigningAuthorityClass.TEST and test_id is None:
            raise ValueError("test control signing key ID is malformed")
        try:
            public_key = base64.b64decode(self.public_key_b64, validate=True)
        except ValueError as exc:
            raise ValueError("control signing public key is malformed") from exc
        if len(public_key) != 32:
            raise ValueError("control signing public key must be Ed25519")
        if self.state is SigningKeyState.CURRENT:
            if self.state_changed_on is not None:
                raise ValueError("current signing keys cannot have a state-change date")
        elif self.state_changed_on is None:
            raise ValueError("retired or compromised keys require a state-change date")
        if self.state_changed_on is not None and self.state_changed_on < self.activated_on:
            raise ValueError("signing key state cannot change before activation")
        if len(self.historical_manifest_digests) != len(
            set(self.historical_manifest_digests)
        ):
            raise ValueError("historical manifest digests must be unique")
        if any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
            for item in self.historical_manifest_digests
        ):
            raise ValueError("historical manifest digest is malformed")
        if (
            self.state is SigningKeyState.RETIRED
            and not self.historical_manifest_digests
        ):
            raise ValueError("retired keys require a closed historical digest set")


CONTROL_SIGNING_AUTHORITIES: Final = (
    ControlSigningAuthority(
        key_id="posture-controls-2026-07",
        public_key_b64="9HQCBdQYp6PDU9XGT+ennCBzqtqj6ivXXvCsFbjzN1E=",
        state=SigningKeyState.CURRENT,
        authority_class=SigningAuthorityClass.PRODUCTION,
        activated_on=date(2026, 7, 27),
    ),
)

# Compatibility aliases point only to the reviewed current authority. Rotation
# is an explicit source change to CONTROL_SIGNING_AUTHORITIES.
_CURRENT_CONTROL_SIGNING_AUTHORITY: Final = next(
    authority
    for authority in CONTROL_SIGNING_AUTHORITIES
    if authority.state is SigningKeyState.CURRENT
)
CONTROL_SIGNING_KEY_ID: Final = _CURRENT_CONTROL_SIGNING_AUTHORITY.key_id
CONTROL_SIGNING_PUBLIC_KEY_B64: Final = (
    _CURRENT_CONTROL_SIGNING_AUTHORITY.public_key_b64
)
