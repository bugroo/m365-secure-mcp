"""Offline CLI for the independent contract-manifest signing authority."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from .contract_manifest import (
    ContractManifestDocument,
    ManifestSignature,
    canonical_json,
    parse_contract_manifest,
    sha256_digest,
    sign_contract_manifest,
    verify_contract_manifest_signature,
)
from .contract_trust import (
    CONTRACT_SIGNING_AUTHORITIES,
    ContractSigningAuthority,
)
from .security import PrivateStateError, SecurityError, read_private_file

MAX_MANIFEST_BYTES = 1_048_576
MAX_SIGNATURE_BYTES = 16_384
MAX_SIGNER_BYTES = 16_384
MAX_PASSPHRASE_BYTES = 1_024


def _read_public_regular_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    expanded = path.expanduser()
    try:
        descriptor = os.open(expanded, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise SecurityError(f"{label} could not be opened") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SecurityError(f"{label} must be a regular file")
        if file_stat.st_size > max_bytes:
            raise SecurityError(f"{label} exceeds the byte limit")
        payload = os.read(descriptor, max_bytes + 1)
        if len(payload) > max_bytes:
            raise SecurityError(f"{label} exceeds the byte limit")
        return payload
    finally:
        os.close(descriptor)


def _write_public_new(path: Path, payload: bytes) -> None:
    expanded = path.expanduser()
    parent = expanded.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        raise SecurityError("signature output parent does not exist") from exc
    if not stat.S_ISDIR(parent_stat.st_mode) or parent.is_symlink():
        raise SecurityError("signature output parent must be a real directory")
    try:
        descriptor = os.open(
            expanded,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
    except OSError as exc:
        raise SecurityError("signature output already exists or is unsafe") from exc
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("signature output write made no progress")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise SecurityError("signature output could not be written") from exc
    finally:
        os.close(descriptor)


def _load_manifest(path: Path) -> ContractManifestDocument:
    try:
        raw = json.loads(
            _read_public_regular_file(
                path,
                max_bytes=MAX_MANIFEST_BYTES,
                label="contract manifest",
            )
        )
        return parse_contract_manifest(raw)
    except (TypeError, ValueError, json.JSONDecodeError, ValidationError) as exc:
        raise SecurityError("contract manifest is invalid") from exc


def _load_signature(path: Path) -> ManifestSignature:
    try:
        return ManifestSignature.model_validate_json(
            _read_public_regular_file(
                path,
                max_bytes=MAX_SIGNATURE_BYTES,
                label="contract manifest signature",
            )
        )
    except ValidationError as exc:
        raise SecurityError("contract manifest signature is invalid") from exc


def _load_external_signer(path: Path, passphrase: bytes) -> Ed25519PrivateKey:
    if not passphrase or len(passphrase) > MAX_PASSPHRASE_BYTES:
        raise PrivateStateError("contract signer passphrase is empty or too long")
    payload = read_private_file(
        path.expanduser(),
        max_bytes=MAX_SIGNER_BYTES,
        label="external contract signing material",
    )
    try:
        signer = serialization.load_pem_private_key(payload, password=passphrase)
    except (TypeError, ValueError) as exc:
        raise PrivateStateError(
            "external contract signing material is invalid or not encrypted"
        ) from exc
    if not isinstance(signer, Ed25519PrivateKey):
        raise PrivateStateError("external contract signer must use Ed25519")
    return signer


def _signer_passphrase() -> bytes:
    return getpass.getpass("External contract signer passphrase: ").encode("utf-8")


def _signature_payload(signature: ManifestSignature) -> bytes:
    return (
        json.dumps(
            signature.model_dump(mode="json"),
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-contract-signing",
        description=(
            "Inspect, sign, and verify contract manifests outside MCP runtime. "
            "This CLI never generates keys or changes trust anchors."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_key = commands.add_parser(
        "inspect-key",
        help="derive public metadata from an encrypted external Ed25519 signer",
    )
    inspect_key.add_argument("--key-file", required=True)
    inspect_key.add_argument("--key-id", required=True)
    sign = commands.add_parser(
        "sign",
        help="sign canonical manifest bytes with the reviewed current authority",
    )
    sign.add_argument("--manifest", required=True)
    sign.add_argument("--key-file", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--signature-output", required=True)
    verify = commands.add_parser(
        "verify",
        help="verify a current or explicitly pinned historical signature",
    )
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--signature", required=True)
    verify.add_argument(
        "--historical",
        action="store_true",
        help="require a retired signer and its exact pinned historical digest",
    )
    return parser


def _inspect_key(args: argparse.Namespace) -> None:
    signer = _load_external_signer(Path(args.key_file), _signer_passphrase())
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print(
        json.dumps(
            {
                "status": "inspected",
                "key_id": args.key_id,
                "algorithm": "ed25519",
                "public_key_b64": base64.b64encode(public_key).decode("ascii"),
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "private_material_printed": False,
                "trust_anchor_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


def _sign(
    args: argparse.Namespace,
    *,
    authorities: Sequence[ContractSigningAuthority] = CONTRACT_SIGNING_AUTHORITIES,
    allow_test_authorities: bool = False,
) -> None:
    manifest = _load_manifest(Path(args.manifest))
    signer = _load_external_signer(Path(args.key_file), _signer_passphrase())
    signature = sign_contract_manifest(
        manifest,
        signer,
        key_id=args.key_id,
        authorities=authorities,
        allow_test_authorities=allow_test_authorities,
    )
    payload = _signature_payload(signature)
    _write_public_new(Path(args.signature_output), payload)
    print(
        json.dumps(
            {
                "status": "signed",
                "key_id": signature.key_id,
                "contract_manifest_digest": signature.manifest_digest,
                "canonical_input_sha256": sha256_digest(manifest),
                "signature_artifact_sha256": (
                    "sha256:" + hashlib.sha256(payload).hexdigest()
                ),
                "private_material_printed": False,
                "trust_anchor_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


def _verify(args: argparse.Namespace) -> None:
    manifest = _load_manifest(Path(args.manifest))
    signature = _load_signature(Path(args.signature))
    authority = verify_contract_manifest_signature(
        manifest,
        signature,
        historical=args.historical,
    )
    print(
        json.dumps(
            {
                "status": "verified",
                "key_id": authority.key_id,
                "key_state": authority.state.value,
                "historical_mode": bool(args.historical),
                "contract_manifest_digest": sha256_digest(manifest),
                "canonical_input_bytes": len(canonical_json(manifest)),
            },
            indent=2,
            sort_keys=True,
        )
    )


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "inspect-key":
            _inspect_key(args)
        elif args.command == "sign":
            _sign(args)
        else:
            _verify(args)
    except (RuntimeError, SecurityError, ValidationError) as exc:
        raise SystemExit(f"Contract signing error:\n{exc}") from None


if __name__ == "__main__":
    main()
