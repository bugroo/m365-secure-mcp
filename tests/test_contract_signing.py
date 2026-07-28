from __future__ import annotations

import base64
import json
from datetime import date
from importlib.resources import files

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m365_secure_mcp.contract_manifest import (
    ManifestSignature,
    load_global_manifest,
    sha256_digest,
    sign_contract_manifest,
    validate_contract_signing_authorities,
    verify_contract_manifest_signature,
)
from m365_secure_mcp.contract_trust import (
    CONTRACT_SIGNING_AUTHORITIES,
    ContractSigningAuthority,
    SigningAuthorityClass,
    SigningKeyState,
)

HISTORICAL_MANIFEST_DIGEST = (
    "sha256:1a33a244371405402df75a125fe6c18a9d6d0af0d2b692f5a831cde82248f5ba"
)


def _authority(
    signer: Ed25519PrivateKey,
    *,
    key_id: str,
    state: SigningKeyState = SigningKeyState.CURRENT,
    historical: tuple[str, ...] = (),
    authority_class: SigningAuthorityClass = SigningAuthorityClass.TEST,
) -> ContractSigningAuthority:
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return ContractSigningAuthority(
        key_id=key_id,
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        state=state,
        authority_class=authority_class,
        activated_on=date(2026, 7, 28),
        state_changed_on=(
            None if state is SigningKeyState.CURRENT else date(2026, 7, 29)
        ),
        historical_manifest_digests=historical,
    )


def test_production_registry_preserves_the_existing_current_authority() -> None:
    current = validate_contract_signing_authorities(
        CONTRACT_SIGNING_AUTHORITIES
    )
    assert current.key_id == "profile-debt-2026-07"
    assert current.state is SigningKeyState.CURRENT
    assert current.authority_class is SigningAuthorityClass.PRODUCTION
    assert sha256_digest(load_global_manifest()) == HISTORICAL_MANIFEST_DIGEST


def test_contract_production_and_test_authorities_cannot_mix() -> None:
    test_authority = _authority(
        Ed25519PrivateKey.generate(),
        key_id="test-m365-contracts-isolation",
    )
    with pytest.raises(RuntimeError, match="not valid for production"):
        validate_contract_signing_authorities((test_authority,))
    with pytest.raises(RuntimeError, match="cannot be mixed"):
        validate_contract_signing_authorities(
            (CONTRACT_SIGNING_AUTHORITIES[0], test_authority),
            allow_test_authorities=True,
        )


def test_retired_or_wrong_contract_key_cannot_sign() -> None:
    manifest = load_global_manifest()
    old_signer = Ed25519PrivateKey.generate()
    new_signer = Ed25519PrivateKey.generate()
    retired = _authority(
        old_signer,
        key_id="test-m365-contracts-retired",
        state=SigningKeyState.RETIRED,
        historical=(sha256_digest(manifest),),
    )
    current = _authority(
        new_signer,
        key_id="test-m365-contracts-current",
    )
    with pytest.raises(RuntimeError, match="cannot sign"):
        sign_contract_manifest(
            manifest,
            old_signer,
            key_id=retired.key_id,
            authorities=(retired, current),
            allow_test_authorities=True,
        )
    with pytest.raises(RuntimeError, match="does not match"):
        sign_contract_manifest(
            manifest,
            Ed25519PrivateKey.generate(),
            key_id=current.key_id,
            authorities=(retired, current),
            allow_test_authorities=True,
        )


def test_direct_cutover_keeps_only_the_exact_old_manifest_historical() -> None:
    manifest = load_global_manifest()
    raw_signature = files("m365_secure_mcp.contract_data").joinpath(
        "global-manifest.sig.json"
    ).read_text()
    signature = ManifestSignature.model_validate(json.loads(raw_signature))
    old = CONTRACT_SIGNING_AUTHORITIES[0]
    retired = ContractSigningAuthority(
        key_id=old.key_id,
        public_key_b64=old.public_key_b64,
        state=SigningKeyState.RETIRED,
        authority_class=SigningAuthorityClass.PRODUCTION,
        activated_on=old.activated_on,
        state_changed_on=date(2026, 7, 29),
        historical_manifest_digests=(HISTORICAL_MANIFEST_DIGEST,),
    )
    replacement = _authority(
        Ed25519PrivateKey.generate(),
        key_id="m365-contracts-2026-07",
        authority_class=SigningAuthorityClass.PRODUCTION,
    )
    registry = (retired, replacement)

    with pytest.raises(RuntimeError, match="not current"):
        verify_contract_manifest_signature(
            manifest,
            signature,
            authorities=registry,
        )
    assert (
        verify_contract_manifest_signature(
            manifest,
            signature,
            authorities=registry,
            historical=True,
        )
        == retired
    )
    changed = manifest.model_copy(
        update={"product": "m365-secure-mcp"},
        deep=True,
    )
    changed.contracts[0].description += " Changed."
    with pytest.raises(RuntimeError, match="digest mismatch"):
        verify_contract_manifest_signature(
            changed,
            signature,
            authorities=registry,
            historical=True,
        )


def test_compromised_contract_key_never_verifies_history() -> None:
    manifest = load_global_manifest()
    signer = Ed25519PrivateKey.generate()
    current = _authority(
        signer,
        key_id="test-m365-contracts-before-compromise",
    )
    signature = sign_contract_manifest(
        manifest,
        signer,
        key_id=current.key_id,
        authorities=(current,),
        allow_test_authorities=True,
    )
    compromised = _authority(
        signer,
        key_id=current.key_id,
        state=SigningKeyState.COMPROMISED,
        historical=(sha256_digest(manifest),),
    )
    replacement = _authority(
        Ed25519PrivateKey.generate(),
        key_id="test-m365-contracts-after-compromise",
    )
    with pytest.raises(RuntimeError, match="compromised"):
        verify_contract_manifest_signature(
            manifest,
            signature,
            authorities=(compromised, replacement),
            historical=True,
            allow_test_authorities=True,
        )


def test_contract_signature_input_is_deterministic() -> None:
    manifest = load_global_manifest()
    signer = Ed25519PrivateKey.generate()
    authority = _authority(
        signer,
        key_id="test-m365-contracts-deterministic",
    )
    first = sign_contract_manifest(
        manifest,
        signer,
        key_id=authority.key_id,
        authorities=(authority,),
        allow_test_authorities=True,
    )
    second = sign_contract_manifest(
        manifest,
        signer,
        key_id=authority.key_id,
        authorities=(authority,),
        allow_test_authorities=True,
    )
    assert first == second
    assert first.manifest_digest == HISTORICAL_MANIFEST_DIGEST
