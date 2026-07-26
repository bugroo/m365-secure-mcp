"""Encrypted, tenant-local Assurance snapshots and keyed drift digests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, TypeVar
from uuid import UUID

import keyring
from cryptography.fernet import Fernet
from keyring.errors import KeyringError

from .config import Settings
from .contract_manifest import canonical_json
from .security import PrivateStateError, open_private_file

DomainT = TypeVar("DomainT", bound=StrEnum)


class AssuranceSnapshotStore:
    """Append-only encrypted posture evidence with no MCP retrieval surface."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path = settings.effective_assurance_snapshot_path
        self._ephemeral_material: bytes | None = None

    def _material(self) -> bytes:
        if self.settings.token_cache_mode == "memory":  # noqa: S105
            if self._ephemeral_material is None:
                self._ephemeral_material = Fernet.generate_key()
            return self._ephemeral_material

        username = f"assurance-snapshot:{self.settings.deployment_namespace}"
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
                "OS keychain is unavailable for Assurance snapshots"
            ) from exc
        try:
            Fernet(encoded.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise PrivateStateError(
                "Assurance snapshot material in OS keychain is invalid"
            ) from exc
        return encoded.encode("ascii")

    def _digest_key(self) -> bytes:
        raw_key = base64.urlsafe_b64decode(self._material())
        return hmac.new(
            raw_key,
            b"m365-secure-mcp:assurance-domain-digest:v1",
            hashlib.sha256,
        ).digest()

    def domain_digest(
        self,
        *,
        tenant_id: str,
        contract_id: str,
        domain: DomainT,
        records: list[dict[str, Any]],
    ) -> str:
        """Create a stable deployment-local digest that is safe to publish."""

        payload = canonical_json(
            {
                "schema_version": "1.0",
                "tenant_id": tenant_id,
                "contract_id": contract_id,
                "domain": domain.value,
                "records": records,
            }
        )
        return (
            "hmac-sha256:"
            + hmac.new(self._digest_key(), payload, hashlib.sha256).hexdigest()
        )

    def resource_reference(
        self,
        *,
        tenant_id: str,
        category: str,
        resource_id: str,
    ) -> str:
        """Return a stable opaque reference without exposing a tenant resource ID."""

        payload = canonical_json(
            {
                "schema_version": "1.0",
                "tenant_id": tenant_id,
                "category": category,
                "resource_id": resource_id,
            }
        )
        fingerprint = hmac.new(
            self._digest_key(),
            payload,
            hashlib.sha256,
        ).hexdigest()[:24]
        return f"{category}:{fingerprint}"

    def store(
        self,
        *,
        snapshot_id: UUID,
        contract_id: str,
        tenant_id: str,
        domains: Mapping[DomainT, list[dict[str, Any]]],
    ) -> str:
        """Encrypt the full normalized snapshot and append metadata-only routing."""

        created = datetime.now(UTC)
        expires = created + timedelta(
            seconds=self.settings.assurance_snapshot_ttl_seconds
        )
        plaintext = canonical_json(
            {
                "schema_version": "1.0",
                "snapshot_id": str(snapshot_id),
                "contract_id": contract_id,
                "tenant_id": tenant_id,
                "domains": {
                    name.value: records
                    for name, records in sorted(
                        domains.items(),
                        key=lambda item: item[0].value,
                    )
                },
                "created_at": created.isoformat(),
                "expires_at": expires.isoformat(),
            }
        )
        if len(plaintext) > self.settings.assurance_max_snapshot_bytes:
            raise PrivateStateError(
                "Assurance snapshot exceeds the encrypted local-storage bound"
            )
        ciphertext = Fernet(self._material()).encrypt(plaintext).decode("ascii")
        record = {
            "schema_version": "1.0",
            "snapshot_id": str(snapshot_id),
            "contract_id": contract_id,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
            "domain_item_counts": {
                name.value: len(records)
                for name, records in sorted(
                    domains.items(),
                    key=lambda item: item[0].value,
                )
            },
            "ciphertext": ciphertext,
        }
        payload = (
            json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        descriptor = open_private_file(
            self.path,
            os.O_APPEND | os.O_WRONLY,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise PrivateStateError(
                        "failed to persist the Assurance snapshot"
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return f"snapshot:{snapshot_id}"
