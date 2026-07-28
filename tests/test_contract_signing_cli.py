from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import date
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import m365_secure_mcp.contract_signing_cli as signing_cli
from m365_secure_mcp.contract_manifest import (
    ManifestSignature,
    load_global_manifest,
)
from m365_secure_mcp.contract_trust import (
    ContractSigningAuthority,
    SigningAuthorityClass,
    SigningKeyState,
)
from m365_secure_mcp.security import PrivateStateError, SecurityError

ROOT = Path(__file__).resolve().parents[1]
PASSPHRASE = b"ephemeral-test-contract-passphrase"


def _authority(signer: Ed25519PrivateKey) -> ContractSigningAuthority:
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return ContractSigningAuthority(
        key_id="test-m365-contracts-cli",
        public_key_b64=base64.b64encode(public).decode("ascii"),
        state=SigningKeyState.CURRENT,
        authority_class=SigningAuthorityClass.TEST,
        activated_on=date(2026, 7, 28),
    )


def _encrypted_signer(directory: Path) -> tuple[Path, Ed25519PrivateKey]:
    os.chmod(directory, 0o700)
    signer = Ed25519PrivateKey.generate()
    payload = signer.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSPHRASE),
    )
    path = directory / "ephemeral-test-contract-signer.pem"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    return path, signer


def test_missing_external_signer_and_unsigned_manifest_fail_closed(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    with pytest.raises(PrivateStateError, match="could not be opened"):
        signing_cli._load_external_signer(tmp_path / "missing.pem", PASSPHRASE)
    with pytest.raises(SecurityError, match="could not be opened"):
        signing_cli._load_signature(tmp_path / "missing.sig.json")


def test_contract_cli_signs_without_leaking_private_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_path, signer = _encrypted_signer(tmp_path)
    authority = _authority(signer)
    output = tmp_path / "manifest.sig.json"
    monkeypatch.setattr(signing_cli, "_signer_passphrase", lambda: PASSPHRASE)
    signing_cli._sign(
        argparse.Namespace(
            manifest=str(
                ROOT / "src/m365_secure_mcp/contract_data/global-manifest.json"
            ),
            key_file=str(key_path),
            key_id=authority.key_id,
            signature_output=str(output),
        ),
        authorities=(authority,),
        allow_test_authorities=True,
    )
    stdout = capsys.readouterr().out
    document = ManifestSignature.model_validate_json(output.read_bytes())
    assert document.key_id == authority.key_id
    assert PASSPHRASE.decode() not in stdout
    assert key_path.read_text() not in stdout
    assert key_path.read_text() not in output.read_text()
    assert json.loads(stdout)["private_material_printed"] is False
    with pytest.raises(SecurityError, match="already exists"):
        signing_cli._write_public_new(output, b"replacement")


def test_contract_cli_rejects_symlink_and_broad_key_permissions(
    tmp_path: Path,
) -> None:
    key_path, _ = _encrypted_signer(tmp_path)
    symlink = tmp_path / "link.pem"
    symlink.symlink_to(key_path)
    with pytest.raises(PrivateStateError):
        signing_cli._load_external_signer(symlink, PASSPHRASE)
    os.chmod(key_path, 0o644)
    with pytest.raises(PrivateStateError, match="mode-0600"):
        signing_cli._load_external_signer(key_path, PASSPHRASE)


def test_cli_parser_has_no_generate_key_or_passphrase_argument() -> None:
    help_text = signing_cli._parser().format_help()
    assert "generate-key" not in help_text
    assert "--passphrase" not in help_text
    assert load_global_manifest().schema_version == "1.0"
