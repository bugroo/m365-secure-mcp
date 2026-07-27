from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from datetime import date
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import m365_secure_mcp.control_signing_cli as signing_cli
import m365_secure_mcp.governance_cli as governance_cli
from m365_secure_mcp.contract_compiler import compile_outputs
from m365_secure_mcp.contract_manifest import load_global_manifest, sha256_digest
from m365_secure_mcp.contract_trust import (
    CONTROL_SIGNING_AUTHORITIES,
    ControlSigningAuthority,
    SigningAuthorityClass,
    SigningKeyState,
)
from m365_secure_mcp.control_manifest import (
    ControlManifestSignature,
    load_global_control_manifest,
    sign_control_manifest,
    validate_control_signing_authorities,
    verify_control_manifest_signature,
)
from m365_secure_mcp.security import PrivateStateError, SecurityError

ROOT = Path(__file__).resolve().parents[1]
TEST_PASSPHRASE = b"test-only-control-signing-passphrase"


def _test_authority(
    signer: Ed25519PrivateKey,
    *,
    key_id: str,
    state: SigningKeyState = SigningKeyState.CURRENT,
    historical_manifest_digests: tuple[str, ...] = (),
) -> ControlSigningAuthority:
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return ControlSigningAuthority(
        key_id=key_id,
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        state=state,
        authority_class=SigningAuthorityClass.TEST,
        activated_on=date(2026, 7, 27),
        state_changed_on=(
            None if state is SigningKeyState.CURRENT else date(2026, 7, 28)
        ),
        historical_manifest_digests=historical_manifest_digests,
    )


def _write_encrypted_ephemeral_signer(
    directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    os.chmod(directory, 0o700)
    responses = iter(
        (
            TEST_PASSPHRASE.decode(),
            TEST_PASSPHRASE.decode(),
        )
    )
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda _prompt: next(responses),
    )
    key_path = directory / "ephemeral-test-control-signer.pem"
    governance_cli._generate_key(
        argparse.Namespace(
            signer=str(key_path),
            verifier=str(directory / "unused-test-verifier.txt"),
        )
    )
    return key_path


def test_production_and_test_signing_authorities_are_separate() -> None:
    assert all(
        authority.authority_class is SigningAuthorityClass.PRODUCTION
        and not authority.key_id.startswith("test-")
        for authority in CONTROL_SIGNING_AUTHORITIES
    )
    signer = Ed25519PrivateKey.generate()
    test_authority = _test_authority(
        signer,
        key_id="test-posture-controls-separation",
    )
    with pytest.raises(RuntimeError, match="not valid for production"):
        validate_control_signing_authorities((test_authority,))
    assert (
        validate_control_signing_authorities(
            (test_authority,),
            allow_test_authorities=True,
        )
        == test_authority
    )
    with pytest.raises(ValueError, match="test control signing key ID"):
        ControlSigningAuthority(
            key_id="posture-controls-2026-08",
            public_key_b64=test_authority.public_key_b64,
            state=SigningKeyState.CURRENT,
            authority_class=SigningAuthorityClass.TEST,
            activated_on=date(2026, 7, 28),
        )


def test_wrong_key_id_and_wrong_private_key_are_rejected() -> None:
    manifest = load_global_control_manifest()
    signer = Ed25519PrivateKey.generate()
    authority = _test_authority(
        signer,
        key_id="test-posture-controls-current",
    )
    with pytest.raises(RuntimeError, match="signer is not trusted"):
        sign_control_manifest(
            manifest,
            signer,
            key_id="test-posture-controls-unknown",
            authorities=(authority,),
            allow_test_authorities=True,
        )
    with pytest.raises(RuntimeError, match="does not match"):
        sign_control_manifest(
            manifest,
            Ed25519PrivateKey.generate(),
            key_id=authority.key_id,
            authorities=(authority,),
            allow_test_authorities=True,
        )


def test_retired_key_cannot_sign_a_new_manifest() -> None:
    manifest = load_global_control_manifest()
    old_signer = Ed25519PrivateKey.generate()
    new_signer = Ed25519PrivateKey.generate()
    retired = _test_authority(
        old_signer,
        key_id="test-posture-controls-retired",
        state=SigningKeyState.RETIRED,
        historical_manifest_digests=(sha256_digest(manifest),),
    )
    current = _test_authority(
        new_signer,
        key_id="test-posture-controls-replacement",
    )
    with pytest.raises(RuntimeError, match="cannot sign"):
        sign_control_manifest(
            manifest,
            old_signer,
            key_id=retired.key_id,
            authorities=(retired, current),
            allow_test_authorities=True,
        )


def test_compromised_key_is_rejected_for_historical_verification() -> None:
    manifest = load_global_control_manifest()
    old_signer = Ed25519PrivateKey.generate()
    old_current = _test_authority(
        old_signer,
        key_id="test-posture-controls-compromised",
    )
    signature = sign_control_manifest(
        manifest,
        old_signer,
        key_id=old_current.key_id,
        authorities=(old_current,),
        allow_test_authorities=True,
    )
    compromised = _test_authority(
        old_signer,
        key_id=old_current.key_id,
        state=SigningKeyState.COMPROMISED,
        historical_manifest_digests=(sha256_digest(manifest),),
    )
    replacement = _test_authority(
        Ed25519PrivateKey.generate(),
        key_id="test-posture-controls-after-compromise",
    )
    with pytest.raises(RuntimeError, match="compromised"):
        verify_control_manifest_signature(
            manifest,
            signature,
            authorities=(compromised, replacement),
            historical=True,
            allow_test_authorities=True,
        )


def test_direct_cutover_preserves_old_and_verifies_new_manifest() -> None:
    manifest = load_global_control_manifest()
    old_signer = Ed25519PrivateKey.generate()
    old_current = _test_authority(
        old_signer,
        key_id="test-posture-controls-old",
    )
    old_signature = sign_control_manifest(
        manifest,
        old_signer,
        key_id=old_current.key_id,
        authorities=(old_current,),
        allow_test_authorities=True,
    )

    new_signer = Ed25519PrivateKey.generate()
    retired = _test_authority(
        old_signer,
        key_id=old_current.key_id,
        state=SigningKeyState.RETIRED,
        historical_manifest_digests=(sha256_digest(manifest),),
    )
    new_current = _test_authority(
        new_signer,
        key_id="test-posture-controls-new",
    )
    rotated_authorities = (retired, new_current)
    with pytest.raises(RuntimeError, match="not current"):
        verify_control_manifest_signature(
            manifest,
            old_signature,
            authorities=rotated_authorities,
            allow_test_authorities=True,
        )
    assert (
        verify_control_manifest_signature(
            manifest,
            old_signature,
            authorities=rotated_authorities,
            historical=True,
            allow_test_authorities=True,
        )
        == retired
    )

    new_signature = sign_control_manifest(
        manifest,
        new_signer,
        key_id=new_current.key_id,
        authorities=rotated_authorities,
        allow_test_authorities=True,
    )
    assert (
        verify_control_manifest_signature(
            manifest,
            new_signature,
            authorities=rotated_authorities,
            allow_test_authorities=True,
        )
        == new_current
    )


def test_retired_key_is_bound_to_exact_historical_digest() -> None:
    manifest = load_global_control_manifest()
    signer = Ed25519PrivateKey.generate()
    current = _test_authority(
        signer,
        key_id="test-posture-controls-history",
    )
    signature = sign_control_manifest(
        manifest,
        signer,
        key_id=current.key_id,
        authorities=(current,),
        allow_test_authorities=True,
    )
    retired = _test_authority(
        signer,
        key_id=current.key_id,
        state=SigningKeyState.RETIRED,
        historical_manifest_digests=("sha256:" + ("0" * 64),),
    )
    replacement = _test_authority(
        Ed25519PrivateKey.generate(),
        key_id="test-posture-controls-history-replacement",
    )
    with pytest.raises(RuntimeError, match="not pinned"):
        verify_control_manifest_signature(
            manifest,
            signature,
            authorities=(retired, replacement),
            historical=True,
            allow_test_authorities=True,
        )


def test_signing_input_and_ed25519_signature_are_deterministic() -> None:
    manifest = load_global_control_manifest()
    signer = Ed25519PrivateKey.generate()
    authority = _test_authority(
        signer,
        key_id="test-posture-controls-deterministic",
    )
    first = sign_control_manifest(
        manifest,
        signer,
        key_id=authority.key_id,
        authorities=(authority,),
        allow_test_authorities=True,
    )
    second = sign_control_manifest(
        manifest,
        signer,
        key_id=authority.key_id,
        authorities=(authority,),
        allow_test_authorities=True,
    )
    assert first == second
    assert first.control_manifest_digest == sha256_digest(manifest)


def test_unsigned_rotation_and_missing_external_key_fail_closed(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    with pytest.raises(SecurityError, match="could not be opened"):
        signing_cli._load_signature(tmp_path / "missing-signature.json")
    with pytest.raises(PrivateStateError, match="could not be opened"):
        signing_cli._load_external_signer(
            tmp_path / "missing-signer.pem",
            TEST_PASSPHRASE,
        )


def test_local_build_provenance_is_not_a_release_attestation() -> None:
    manifest = load_global_manifest()
    outputs = compile_outputs(manifest, root=ROOT)
    provenance = json.loads(
        outputs[ROOT / "contract-artifacts/provenance.json"]
    )
    assert provenance["source_revision"] == "release-attestation-required"
    assert provenance["build_kind"] == "local-unattested"
    assert provenance["distribution_status"] == "not-a-release"
    assert provenance["release_attestation_status"] == "external-required"
    runbook = (ROOT / "docs/CONTROL_SIGNING_RUNBOOK.md").read_text()
    assert "makes no SLSA or signed-release-provenance claim" in runbook


def test_public_control_artifacts_exclude_secret_signer_fields() -> None:
    public_paths = [
        ROOT / "src/m365_secure_mcp/contract_data/global-controls.json",
        ROOT / "src/m365_secure_mcp/contract_data/global-controls.sig.json",
        ROOT / "src/m365_secure_mcp/_generated_controls.py",
        ROOT / "contract-artifacts/control-digests.json",
        ROOT / "contract-artifacts/control-tests.json",
        ROOT / "docs/CONTROL_MATRIX.md",
    ]
    payload = "\n".join(path.read_text() for path in public_paths)
    assert "test-posture-controls-" not in payload
    assert "CONTROL_SIGNING_PRIVATE" not in payload
    assert "CONTROL_SIGNING_SEED" not in payload
    assert "encrypted_private_key" not in payload


def test_cli_output_excludes_ephemeral_signer_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_path = _write_encrypted_ephemeral_signer(tmp_path, monkeypatch)
    capsys.readouterr()
    signer = signing_cli._load_external_signer(key_path, TEST_PASSPHRASE)
    authority = _test_authority(
        signer,
        key_id="test-posture-controls-cli",
    )
    output = tmp_path / "signature.json"
    monkeypatch.setattr(signing_cli, "_signer_passphrase", lambda: TEST_PASSPHRASE)

    signing_cli._sign(
        argparse.Namespace(
            manifest=str(
                ROOT
                / "src/m365_secure_mcp/contract_data/global-controls.json"
            ),
            key_file=str(key_path),
            key_id=authority.key_id,
            signature_output=str(output),
        ),
        authorities=(authority,),
        allow_test_authorities=True,
    )
    stdout = capsys.readouterr().out
    signature_document = ControlManifestSignature.model_validate_json(
        output.read_bytes()
    )
    signer_payload = key_path.read_text()
    assert TEST_PASSPHRASE.decode() not in stdout
    assert signer_payload not in stdout
    assert signer_payload not in output.read_text()
    assert signature_document.key_id == authority.key_id
    assert json.loads(stdout)["private_material_printed"] is False
