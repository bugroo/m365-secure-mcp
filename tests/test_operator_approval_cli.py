from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m365_secure_mcp import operator_approval_cli
from m365_secure_mcp.contract_manifest import canonical_json
from m365_secure_mcp.operator_authority import (
    ApprovalAuthorityState,
    ApprovalTrustRegistry,
    OperatorApprovalRequest,
    SignedOperatorApproval,
)
from m365_secure_mcp.security import SecurityError

from .operator_helpers import NOW, authority_record, operator_context

PASSPHRASE = b"test-only-long-passphrase"


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


def _private_root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _write(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _encrypted_signer(path: Path, signer: Ed25519PrivateKey) -> None:
    _write(
        path,
        signer.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                PASSPHRASE
            ),
        ),
    )


def test_operator_approval_cli_signs_exact_external_request(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _private_root(tmp_path)
    signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "operations-approver",
        "person-operations",
        "operations-key-2026",
        "operations",
        signer,
    )
    registry_path = root / "trust.json"
    _write(
        registry_path,
        canonical_json(ApprovalTrustRegistry(authorities=(authority,))),
    )
    _, plan, _, _, _ = operator_context(root)
    request = OperatorApprovalRequest(
        plan=plan,
        plan_digest=plan.digest,
        requested_at=NOW,
    )
    request_path = root / "request.json"
    _write(request_path, canonical_json(request))
    signer_path = root / "signer.pem"
    _encrypted_signer(signer_path, signer)
    output = root / "approval.json"
    monkeypatch.setattr(
        operator_approval_cli.getpass,
        "getpass",
        lambda _: PASSPHRASE.decode(),
    )
    monkeypatch.setattr(operator_approval_cli, "datetime", FrozenDateTime)
    operator_approval_cli._sign(
        argparse.Namespace(
            request=str(request_path),
            trust_registry=str(registry_path),
            authority_id=authority.authority_id,
            signer=str(signer_path),
            output=str(output),
            expected_plan_digest=plan.digest,
            ttl_seconds=60,
        )
    )
    bundle = SignedOperatorApproval.model_validate_json(output.read_bytes())
    assert bundle.grant.plan_digest == plan.digest
    assert bundle.grant.authority_id == authority.authority_id
    assert "PRIVATE KEY" not in json.dumps(
        bundle.model_dump(mode="json")
    )


def test_operator_approval_cli_rejects_unpinned_signer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _private_root(tmp_path)
    signer = Ed25519PrivateKey.generate()
    wrong = Ed25519PrivateKey.generate()
    authority = authority_record(
        "operations-approver",
        "person-operations",
        "operations-key-2026",
        "operations",
        signer,
    )
    registry_path = root / "trust.json"
    _write(
        registry_path,
        canonical_json(ApprovalTrustRegistry(authorities=(authority,))),
    )
    _, plan, _, _, _ = operator_context(root)
    request_path = root / "request.json"
    _write(
        request_path,
        canonical_json(
            OperatorApprovalRequest(
                plan=plan,
                plan_digest=plan.digest,
                requested_at=NOW,
            )
        ),
    )
    signer_path = root / "wrong.pem"
    _encrypted_signer(signer_path, wrong)
    monkeypatch.setattr(
        operator_approval_cli.getpass,
        "getpass",
        lambda _: PASSPHRASE.decode(),
    )
    monkeypatch.setattr(operator_approval_cli, "datetime", FrozenDateTime)
    with pytest.raises(SecurityError, match="pinned"):
        operator_approval_cli._sign(
            argparse.Namespace(
                request=str(request_path),
                trust_registry=str(registry_path),
                authority_id=authority.authority_id,
                signer=str(signer_path),
                output=str(root / "approval.json"),
                expected_plan_digest=plan.digest,
                ttl_seconds=60,
            )
        )


def test_operator_approval_cli_has_no_key_generation_or_passphrase_argument() -> None:
    parser = operator_approval_cli._parser()
    help_text = parser.format_help()
    assert "generate-key" not in help_text
    assert "passphrase" not in help_text


def test_operator_approval_cli_verify_rejects_retired_authority(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _private_root(tmp_path)
    signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "operations-approver",
        "person-operations",
        "operations-key-2026",
        "operations",
        signer,
    )
    registry_path = root / "trust.json"
    _write(
        registry_path,
        canonical_json(ApprovalTrustRegistry(authorities=(authority,))),
    )
    _, plan, _, _, _ = operator_context(root)
    request = OperatorApprovalRequest(
        plan=plan,
        plan_digest=plan.digest,
        requested_at=NOW,
    )
    request_path = root / "request.json"
    _write(request_path, canonical_json(request))
    signer_path = root / "signer.pem"
    _encrypted_signer(signer_path, signer)
    approval_path = root / "approval.json"
    monkeypatch.setattr(
        operator_approval_cli.getpass,
        "getpass",
        lambda _: PASSPHRASE.decode(),
    )
    monkeypatch.setattr(operator_approval_cli, "datetime", FrozenDateTime)
    operator_approval_cli._sign(
        argparse.Namespace(
            request=str(request_path),
            trust_registry=str(registry_path),
            authority_id=authority.authority_id,
            signer=str(signer_path),
            output=str(approval_path),
            expected_plan_digest=plan.digest,
            ttl_seconds=60,
        )
    )
    retired = authority.model_copy(
        update={
            "state": ApprovalAuthorityState.RETIRED,
            "retired_at": NOW + timedelta(seconds=1),
        }
    )
    _write(
        registry_path,
        canonical_json(ApprovalTrustRegistry(authorities=(retired,))),
    )
    with pytest.raises(SecurityError, match="active authorities"):
        operator_approval_cli._verify(
            argparse.Namespace(
                request=str(request_path),
                trust_registry=str(registry_path),
                approval=[str(approval_path)],
                as_of=(NOW + timedelta(seconds=2)).isoformat(),
            )
        )
