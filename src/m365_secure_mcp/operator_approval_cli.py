"""External signing and verification CLI for immutable T2/T3 plans."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contract_manifest import canonical_json
from .operator_authority import (
    MAX_APPROVAL_LIFETIME_SECONDS,
    MAX_OPERATOR_APPROVAL_DOCUMENT_BYTES,
    ApprovalAuthorityState,
    OperatorApprovalGrant,
    OperatorApprovalRequest,
    OperatorApprovalSignature,
    SignedOperatorApproval,
    load_approval_trust_registry,
)
from .security import PrivateStateError, SecurityError, open_private_file, read_private_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-operator-approval",
        description=(
            "Sign or verify one exact T2/T3 plan outside the MCP runtime. "
            "This command never calls Graph and never generates an authority."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect-key")
    inspect.add_argument("--signer", required=True)

    sign = commands.add_parser("sign")
    sign.add_argument("--request", required=True)
    sign.add_argument("--trust-registry", required=True)
    sign.add_argument("--authority-id", required=True)
    sign.add_argument("--signer", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument("--expected-plan-digest", required=True)
    sign.add_argument("--ttl-seconds", type=int, default=300)

    verify = commands.add_parser("verify")
    verify.add_argument("--request", required=True)
    verify.add_argument("--trust-registry", required=True)
    verify.add_argument("--approval", action="append", required=True)
    verify.add_argument("--as-of", required=True)
    return parser


def _read_request(path: Path) -> OperatorApprovalRequest:
    try:
        return OperatorApprovalRequest.model_validate_json(
            read_private_file(
                path.expanduser(),
                max_bytes=MAX_OPERATOR_APPROVAL_DOCUMENT_BYTES,
                label="operator approval request",
            )
        )
    except ValueError as exc:
        raise PrivateStateError("operator approval request is malformed") from exc


def _read_approval(path: Path) -> SignedOperatorApproval:
    try:
        return SignedOperatorApproval.model_validate_json(
            read_private_file(
                path.expanduser(),
                max_bytes=MAX_OPERATOR_APPROVAL_DOCUMENT_BYTES,
                label="signed operator approval",
            )
        )
    except ValueError as exc:
        raise PrivateStateError("signed operator approval is malformed") from exc


def _load_signer(path: Path) -> Ed25519PrivateKey:
    payload = read_private_file(
        path.expanduser(),
        max_bytes=16_384,
        label="operator approval signing material",
    )
    passphrase = getpass.getpass("Operator approval signer passphrase: ").encode(
        "utf-8"
    )
    try:
        signer = serialization.load_pem_private_key(payload, password=passphrase)
    except (TypeError, ValueError) as exc:
        raise PrivateStateError(
            "operator approval signing material is invalid"
        ) from exc
    if not isinstance(signer, Ed25519PrivateKey):
        raise PrivateStateError("operator approval signer must use Ed25519")
    return signer


def _public_key(signer: Ed25519PrivateKey) -> tuple[str, str]:
    raw = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(raw).decode("ascii"),
        f"sha256:{hashlib.sha256(raw).hexdigest()}",
    )


def _write_new(path: Path, value: SignedOperatorApproval) -> None:
    payload = (
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    descriptor = open_private_file(
        path.expanduser(),
        os.O_WRONLY | os.O_EXCL,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _inspect_key(args: argparse.Namespace) -> None:
    _, fingerprint = _public_key(_load_signer(Path(args.signer)))
    print(
        json.dumps(
            {
                "algorithm": "ed25519",
                "public_key_sha256": fingerprint,
                "secret_material_printed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


def _sign(args: argparse.Namespace) -> None:
    request = _read_request(Path(args.request))
    if args.expected_plan_digest != request.plan_digest:
        raise SecurityError("reviewed plan digest does not match the request")
    now = datetime.now(UTC)
    if request.plan.expires_at <= now:
        raise SecurityError("operator plan expired before approval")
    if not 15 <= args.ttl_seconds <= MAX_APPROVAL_LIFETIME_SECONDS:
        raise SecurityError("operator approval TTL is outside the hard bounds")
    registry = load_approval_trust_registry(Path(args.trust_registry))
    authority = registry.authority(args.authority_id)
    if authority.state is not ApprovalAuthorityState.ACTIVE:
        raise SecurityError("only an active authority may sign execution approval")
    signer = _load_signer(Path(args.signer))
    public_key_b64, fingerprint = _public_key(signer)
    if (
        public_key_b64 != authority.public_key_b64
        or fingerprint != authority.public_key_sha256
    ):
        raise SecurityError("signer does not match the pinned approval authority")
    expires_at = min(
        request.plan.expires_at,
        now + timedelta(seconds=args.ttl_seconds),
    )
    grant = OperatorApprovalGrant(
        approval_id=uuid4(),
        plan_digest=request.plan_digest,
        authority_id=authority.authority_id,
        tenant_id=request.plan.tenant_id,
        profile=request.plan.profile,
        intended_operator_id=request.plan.intended_operator_id,
        issued_at=now,
        expires_at=expires_at,
    )
    bundle = SignedOperatorApproval(
        grant=grant,
        signature=OperatorApprovalSignature(
            key_id=authority.key_id,
            grant_digest=f"sha256:{hashlib.sha256(canonical_json(grant)).hexdigest()}",
            signature=base64.b64encode(
                signer.sign(canonical_json(grant))
            ).decode("ascii"),
        ),
    )
    _write_new(Path(args.output), bundle)
    print(
        json.dumps(
            {
                "status": "signed",
                "authority_id": authority.authority_id,
                "approval_id": str(grant.approval_id),
                "plan_digest": request.plan_digest,
                "secret_material_printed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


def _verify(args: argparse.Namespace) -> None:
    request = _read_request(Path(args.request))
    approvals = tuple(_read_approval(Path(path)) for path in args.approval)
    approval_ids = [item.grant.approval_id for item in approvals]
    authority_ids = [item.grant.authority_id for item in approvals]
    if (
        len(approval_ids) != len(set(approval_ids))
        or len(authority_ids) != len(set(authority_ids))
    ):
        raise SecurityError("approval set contains a repeated authority or grant")
    as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise SecurityError("--as-of must include a UTC offset")
    registry = load_approval_trust_registry(Path(args.trust_registry))
    # Exact Governance is rebound by runtime. This offline command checks the
    # cryptographic plan, subject and lifetime fields without consuming replay
    # state or inventing a policy.
    for approval in approvals:
        authority = registry.authority(approval.grant.authority_id)
        if authority.state is not ApprovalAuthorityState.ACTIVE:
            raise SecurityError("only active authorities verify execution approval")
        if approval.signature.key_id != authority.key_id:
            raise SecurityError("approval key ID differs from trust")
        if (
            approval.signature.grant_digest
            != f"sha256:{hashlib.sha256(canonical_json(approval.grant)).hexdigest()}"
            or
            approval.grant.plan_digest != request.plan_digest
            or approval.grant.tenant_id != request.plan.tenant_id
            or approval.grant.profile is not request.plan.profile
            or approval.grant.intended_operator_id
            != request.plan.intended_operator_id
            or approval.grant.issued_at < request.requested_at
            or approval.grant.issued_at > as_of
            or approval.grant.expires_at <= as_of
            or approval.grant.expires_at > request.plan.expires_at
        ):
            raise SecurityError("approval is not valid for the exact plan and time")
        authority.verifier.verify(
            base64.b64decode(approval.signature.signature, validate=True),
            canonical_json(approval.grant),
        )
    print(
        json.dumps(
            {
                "status": "verified",
                "approval_count": len(approvals),
                "plan_digest": request.plan_digest,
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
    except Exception as exc:
        raise SystemExit(f"operator approval command failed: {exc}") from exc


if __name__ == "__main__":
    main()
