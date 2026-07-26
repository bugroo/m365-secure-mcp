"""Encrypted tenant-local recovery capsules for bounded write compensation."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import keyring
from cryptography.fernet import Fernet
from keyring.errors import KeyringError

from .config import Settings
from .security import PrivateStateError, open_private_file


class RecoveryCapsuleStore:
    """Append-only encrypted recovery data that is never exposed as an MCP tool."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path = settings.effective_recovery_capsule_path
        self._ephemeral_material: bytes | None = None

    def _cipher(self) -> Fernet:
        if self.settings.token_cache_mode == "memory":  # noqa: S105
            if self._ephemeral_material is None:
                self._ephemeral_material = Fernet.generate_key()
            return Fernet(self._ephemeral_material)

        username = f"recovery-capsule:{self.settings.deployment_namespace}"
        try:
            encoded = keyring.get_password(
                self.settings.keyring_service,
                username,
            )
            if encoded is None:
                encoded = Fernet.generate_key().decode("ascii")
                keyring.set_password(
                    self.settings.keyring_service,
                    username,
                    encoded,
                )
        except KeyringError as exc:
            raise PrivateStateError(
                "OS keychain is unavailable for the recovery capsule"
            ) from exc
        try:
            return Fernet(encoded.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise PrivateStateError(
                "recovery capsule material in OS keychain is invalid"
            ) from exc

    def store(
        self,
        *,
        operation_id: UUID,
        contract_id: str,
        tenant_id: str,
        target_user_id: str,
        previous_profile: dict[str, Any],
        requested_profile: dict[str, Any],
    ) -> str:
        """Encrypt previous/requested values before any Graph mutation is sent."""

        created = datetime.now(UTC)
        expires = created + timedelta(
            seconds=self.settings.recovery_capsule_ttl_seconds
        )
        plaintext = json.dumps(
            {
                "operation_id": str(operation_id),
                "contract_id": contract_id,
                "tenant_id": tenant_id,
                "target_user_id": target_user_id,
                "previous_profile": previous_profile,
                "requested_profile": requested_profile,
                "created_at": created.isoformat(),
                "expires_at": expires.isoformat(),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        ciphertext = self._cipher().encrypt(plaintext).decode("ascii")
        record = {
            "operation_id": str(operation_id),
            "contract_id": contract_id,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
            "ciphertext": ciphertext,
        }
        descriptor = open_private_file(
            self.path,
            os.O_APPEND | os.O_WRONLY,
        )
        try:
            os.write(
                descriptor,
                (json.dumps(record, separators=(",", ":")) + "\n").encode(),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return f"capsule:{operation_id}"
