"""Explicit external-host CLI for exact-plan approval artifacts."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from pydantic import ValidationError

from .change_safe import (
    MAX_APPROVAL_DOCUMENT_BYTES,
    ApprovalGrant,
    ApprovalRequest,
    SignedApprovalGrant,
    _load_approval_verifier,
    sign_approval_grant,
    verify_approval_grant,
)
from .security import PrivateStateError, SecurityError, open_private_file, read_private_file

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


def _public_key_text(signer: Ed25519PrivateKey) -> str:
    raw = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii") + "\n"


def _load_signer(path: Path, passphrase: bytes) -> Ed25519PrivateKey:
    payload = read_private_file(
        path,
        max_bytes=16_384,
        label="approval signing material",
    )
    try:
        signer = serialization.load_pem_private_key(
            payload,
            password=passphrase,
        )
    except (TypeError, ValueError) as exc:
        raise PrivateStateError("approval signing material is invalid") from exc
    if not isinstance(signer, Ed25519PrivateKey):
        raise PrivateStateError("approval signer must use Ed25519")
    return signer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-approval",
        description=(
            "Sign an exact private change plan outside MCP runtime. This CLI "
            "never calls Microsoft Graph, changes policy, or grants consent."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser(
        "generate-key",
        help="create a separate encrypted Ed25519 approval authority",
    )
    generate.add_argument("--signer", required=True)
    generate.add_argument("--verifier", required=True)

    sign = commands.add_parser(
        "sign",
        help="sign one unexpired exact plan request",
    )
    sign.add_argument("--request", required=True)
    sign.add_argument("--signer", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument(
        "--expected-plan-digest",
        required=True,
        help="operator-reviewed sha256 plan digest from the MCP result/request",
    )
    sign.add_argument("--ttl-seconds", type=int, default=60)

    verify = commands.add_parser(
        "verify",
        help="verify one signed approval against an external trust anchor",
    )
    verify.add_argument("--approval", required=True)
    verify.add_argument("--verifier", required=True)
    return parser


def _generate_key(args: argparse.Namespace) -> None:
    passphrase = getpass.getpass("New approval signer passphrase: ").encode(
        "utf-8"
    )
    confirmation = getpass.getpass(
        "Confirm approval signer passphrase: "
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
    _write_new(Path(args.signer), signer_payload, label="approval signer")
    _write_new(
        Path(args.verifier),
        _public_key_text(signer).encode("ascii"),
        label="approval verifier",
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


def _load_request(path: Path) -> ApprovalRequest:
    try:
        return ApprovalRequest.model_validate_json(
            read_private_file(
                path,
                max_bytes=MAX_APPROVAL_DOCUMENT_BYTES,
                label="approval request",
            )
        )
    except ValueError as exc:
        raise PrivateStateError("approval request is malformed") from exc


def _load_approval(path: Path) -> SignedApprovalGrant:
    try:
        return SignedApprovalGrant.model_validate_json(
            read_private_file(
                path,
                max_bytes=MAX_APPROVAL_DOCUMENT_BYTES,
                label="signed approval",
            )
        )
    except ValueError as exc:
        raise PrivateStateError("signed approval is malformed") from exc


def _sign(args: argparse.Namespace) -> None:
    request = _load_request(Path(args.request))
    if args.expected_plan_digest != request.plan_digest:
        raise PrivateStateError(
            "operator-reviewed plan digest does not match the approval request"
        )
    now = datetime.now(UTC)
    if request.plan.expires_at <= now:
        raise PrivateStateError("exact plan expired before approval")
    if args.ttl_seconds < 15 or args.ttl_seconds > 300:
        raise PrivateStateError("approval TTL must be between 15 and 300 seconds")
    expires_at = min(
        now + timedelta(seconds=args.ttl_seconds),
        request.plan.expires_at,
    )
    if expires_at <= now:
        raise PrivateStateError("approval lifetime is empty")
    grant = ApprovalGrant(
        approval_id=uuid4(),
        plan=request.plan,
        plan_digest=request.plan_digest,
        issued_at=now,
        expires_at=expires_at,
    )
    bundle = sign_approval_grant(
        grant,
        _load_signer(
            Path(args.signer),
            getpass.getpass("Approval signer passphrase: ").encode("utf-8"),
        ),
        key_id=args.key_id,
    )
    payload = (
        json.dumps(
            bundle.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    _write_new(Path(args.output), payload, label="signed approval")
    print(
        json.dumps(
            {
                "status": "signed",
                "approval_id": str(grant.approval_id),
                "plan_id": str(grant.plan.plan_id),
                "plan_digest": grant.plan_digest,
                "contract_id": grant.plan.contract_id,
                "authorization_mode": grant.plan.authorization_mode,
                "changed_fields": grant.plan.changed_fields,
                "target_fingerprint": grant.plan.target_fingerprint,
                "delegated_scopes": request.permission_impact.delegated_scopes,
                "operator_roles": request.permission_impact.operator_roles,
                "resource_fences": request.permission_impact.fences,
                "expires_at": grant.expires_at.isoformat(),
                "output": str(Path(args.output).expanduser()),
            },
            indent=2,
        )
    )


def _verify(args: argparse.Namespace) -> None:
    bundle = _load_approval(Path(args.approval))
    verify_approval_grant(
        bundle,
        _load_approval_verifier(Path(args.verifier)),
    )
    print(
        json.dumps(
            {
                "status": "verified",
                "approval_id": str(bundle.grant.approval_id),
                "plan_id": str(bundle.grant.plan.plan_id),
                "plan_digest": bundle.grant.plan_digest,
                "expires_at": bundle.grant.expires_at.isoformat(),
                "single_use_enforced_by_runtime": True,
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
    except (PrivateStateError, SecurityError, ValidationError) as exc:
        raise SystemExit(f"Approval error:\n{exc}") from None


if __name__ == "__main__":
    main()
