"""Explicit operator CLI for tenant governance signing and verification."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from .contract_manifest import load_global_manifest, sha256_digest
from .control_manifest import load_global_control_manifest
from .governance import (
    GovernancePolicyError,
    GovernancePolicyV2,
    load_policy_signer,
    load_verified_governance_policy,
    parse_governance_policy,
    public_key_text,
    resolve_control_library_configuration,
    sign_governance_policy,
    validate_policy_against_manifest,
)
from .playbook_manifest import load_global_playbook_manifest
from .security import PrivateStateError, open_private_file, read_private_file

MAX_UNSIGNED_POLICY_BYTES = 512_000
MIN_SIGNER_PASSPHRASE_LENGTH = 14


def _write_new(path: Path, payload: bytes, *, label: str) -> None:
    descriptor = open_private_file(
        path.expanduser(),
        os.O_WRONLY | os.O_EXCL,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    except OSError as exc:
        raise PrivateStateError(f"{label} could not be written safely") from exc
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-governance",
        description=(
            "Create and use tenant governance signing material. This CLI never "
            "calls Microsoft Graph or changes Entra consent."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser(
        "generate-key",
        help="create a new Ed25519 signer and verifier without overwriting files",
    )
    generate.add_argument("--signer", required=True)
    generate.add_argument("--verifier", required=True)

    sign = commands.add_parser(
        "sign",
        help="validate and sign an unsigned governance policy",
    )
    sign.add_argument("--input", required=True)
    sign.add_argument("--signer", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument("--key-id", required=True)

    verify = commands.add_parser(
        "verify",
        help="verify a signed policy against an external trust anchor",
    )
    verify.add_argument("--policy", required=True)
    verify.add_argument("--verifier", required=True)
    return parser


def _generate_key(args: argparse.Namespace) -> None:
    passphrase = getpass.getpass(
        "New governance signer passphrase: "
    ).encode("utf-8")
    confirmation = getpass.getpass(
        "Confirm governance signer passphrase: "
    ).encode("utf-8")
    if (
        passphrase != confirmation
        or len(passphrase) < MIN_SIGNER_PASSPHRASE_LENGTH
        or len(passphrase) > 1_024
    ):
        raise PrivateStateError(
            "signer passphrases must match and contain at least 14 bytes"
        )
    signer = Ed25519PrivateKey.generate()
    signer_payload = signer.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase
        ),
    )
    _write_new(Path(args.signer), signer_payload, label="governance signer")
    _write_new(
        Path(args.verifier),
        public_key_text(signer).encode("ascii"),
        label="governance verifier",
    )
    print(
        json.dumps(
            {
                "status": "created",
                "signer_path": str(Path(args.signer).expanduser()),
                "verifier_path": str(Path(args.verifier).expanduser()),
                "algorithm": "ed25519",
                "secret_material_printed": False,
            },
            indent=2,
        )
    )


def _sign(args: argparse.Namespace) -> None:
    try:
        document = json.loads(
            read_private_file(
                Path(args.input),
                max_bytes=MAX_UNSIGNED_POLICY_BYTES,
                label="unsigned governance policy",
            )
        )
        policy = parse_governance_policy(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise PrivateStateError("unsigned governance policy is invalid") from exc
    manifest = load_global_manifest()
    playbooks = load_global_playbook_manifest(manifest)
    controls = load_global_control_manifest()
    expected_manifest_digest = sha256_digest(manifest)
    if policy.contract_manifest_digest != expected_manifest_digest:
        raise PrivateStateError(
            "governance policy is not bound to the current signed contract manifest"
        )
    validate_policy_against_manifest(policy, manifest, playbooks, controls)
    bundle = sign_governance_policy(
        policy,
        load_policy_signer(
            Path(args.signer),
            passphrase=getpass.getpass(
                "Governance signer passphrase: "
            ).encode("utf-8"),
        ),
        key_id=args.key_id,
    )
    payload = (
        json.dumps(
            bundle.model_dump(mode="json"),
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    _write_new(Path(args.output), payload, label="signed governance policy")
    print(
        json.dumps(
            {
                "status": "signed",
                "output": str(Path(args.output).expanduser()),
                "policy_digest": bundle.signature.policy_digest,
                "key_id": bundle.signature.key_id,
            },
            indent=2,
        )
    )


def _verify(args: argparse.Namespace) -> None:
    verified = load_verified_governance_policy(
        Path(args.policy),
        Path(args.verifier),
    )
    manifest = load_global_manifest()
    playbooks = load_global_playbook_manifest(manifest)
    controls = load_global_control_manifest()
    if verified.policy.contract_manifest_digest != sha256_digest(manifest):
        raise PrivateStateError(
            "governance policy is not bound to the current signed contract manifest"
        )
    validate_policy_against_manifest(
        verified.policy,
        manifest,
        playbooks,
        controls,
    )
    control_configuration = (
        resolve_control_library_configuration(verified.policy, controls)
        if isinstance(verified.policy, GovernancePolicyV2)
        else None
    )
    print(
        json.dumps(
            {
                "status": "verified",
                "policy_digest": verified.policy_digest,
                "key_id": verified.bundle.signature.key_id,
                "tenant_bound": True,
                "active_profile": verified.policy.active_profile.value,
                "policy_version": verified.policy.policy_version,
                "schema_version": verified.policy.schema_version,
                "control_library_configured": (
                    control_configuration is not None
                ),
                "enabled_control_count": (
                    len(control_configuration.settings)
                    if control_configuration is not None
                    else 0
                ),
                "control_exception_count": (
                    len(control_configuration.exceptions)
                    if control_configuration is not None
                    else 0
                ),
                "control_compatibility_digest": (
                    control_configuration.compatibility_digest
                    if control_configuration is not None
                    else None
                ),
            },
            indent=2,
        )
    )


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "generate-key":
            _generate_key(args)
        elif args.command == "sign":
            _sign(args)
        else:
            _verify(args)
    except GovernancePolicyError as exc:
        raise SystemExit(
            "Governance error "
            f"[{exc.reason_code}]:\n{exc}\n"
            f"Operator action: {exc.operator_action}"
        ) from None
    except (PrivateStateError, ValidationError) as exc:
        raise SystemExit(f"Governance error:\n{exc}") from None


if __name__ == "__main__":
    main()
