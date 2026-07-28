from __future__ import annotations

import json
from argparse import Namespace
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    load_global_manifest,
    sha256_digest,
)
from m365_secure_mcp.control_compatibility import (
    ControlCompatibilityEntry,
    ControlCompatibilityMetadata,
    control_compatibility_digest,
    load_control_compatibility_metadata,
)
from m365_secure_mcp.control_manifest import (
    ControlLifecycle,
    ControlManifest,
    load_global_control_manifest,
)
from m365_secure_mcp.diagnostics import _profile_isolation_check
from m365_secure_mcp.governance import (
    ControlException,
    ControlGovernanceSetting,
    ControlLibraryGovernance,
    DirectoryObjectSubjectSelector,
    GovernancePolicyError,
    GovernancePolicyV2,
    GovernanceProfileName,
    load_verified_governance_policy,
    matching_control_exception,
    parse_governance_policy,
    public_key_text,
    resolve_control_library_configuration,
    validate_policy_against_manifest,
)
from m365_secure_mcp.governance_cli import _sign, _verify
from m365_secure_mcp.security import PrivateStateError

from .conftest import CLIENT_ID, TENANT_ID, USER_ID
from .governance_helpers import write_signed_governance

CA_CONTROL = "entra.conditional_access.mfa_policy_coverage"
APP_CONTROL = "entra.applications.owner_coverage"
PROFILE_CONTROL = "entra.profiles.scope_closure"
OTHER_USER_ID = "88888888-8888-4888-8888-888888888888"
ROOT = Path(__file__).resolve().parents[1]


def _setting(
    *,
    severity: str = "high",
    maximum_age: int | None = None,
    allow_control_wide: bool = False,
) -> dict[str, Any]:
    return {
        "definition_major_version": 1,
        "severity": severity,
        "maximum_evidence_age_seconds": maximum_age,
        "allow_control_wide_exception": allow_control_wide,
    }


def _exception(
    *,
    exception_id: str = "exception.synthetic-1",
    control_id: str = CA_CONTROL,
    subject: dict[str, Any] | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    definition_major_version: int = 1,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "exception_id": exception_id,
        "control_id": control_id,
        "definition_major_version": definition_major_version,
        "subject": subject or {"kind": "user", "object_id": USER_ID},
        "applies_to_status": "not_aligned",
        "rationale": "Synthetic customer-approved test exception.",
        "approving_party_reference": "approver:synthetic-security-owner",
        "issued_at": (issued_at or now - timedelta(hours=1)).isoformat(),
        "expires_at": (expires_at or now + timedelta(hours=1)).isoformat(),
    }


def _control_library(
    *,
    control_ids: list[str] | None = None,
    settings: dict[str, dict[str, Any]] | None = None,
    exceptions: list[dict[str, Any]] | None = None,
    manifest_digest: str | None = None,
    library_version: str | None = None,
    compatibility_digest: str | None = None,
) -> ControlLibraryGovernance:
    manifest = load_global_control_manifest()
    compatibility = load_control_compatibility_metadata(manifest)
    selected = control_ids or [CA_CONTROL]
    return ControlLibraryGovernance.model_validate(
        {
            "control_manifest_digest": manifest_digest or sha256_digest(manifest),
            "control_manifest_schema_version": "1.0",
            "control_library_version": library_version or manifest.library_version,
            "control_compatibility_digest": (
                compatibility_digest
                or control_compatibility_digest(compatibility)
            ),
            "enabled_control_ids": selected,
            "controls": settings or {item: _setting() for item in selected},
            "exceptions": exceptions or [],
        }
    )


def _write_v2(
    root: Path,
    *,
    control_library: ControlLibraryGovernance | None = None,
    active_profile: GovernanceProfileName = GovernanceProfileName.PRIVILEGED_READ,
) -> tuple[Path, Path]:
    return write_signed_governance(
        root,
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        active_profile=active_profile,
        control_library=control_library or _control_library(),
    )


def _loaded_v2(
    root: Path,
    *,
    control_library: ControlLibraryGovernance | None = None,
) -> GovernancePolicyV2:
    policy_path, verifier_path = _write_v2(
        root,
        control_library=control_library,
    )
    policy = load_verified_governance_policy(policy_path, verifier_path).policy
    assert isinstance(policy, GovernancePolicyV2)
    return policy


def _policy_v2(
    control_library: ControlLibraryGovernance,
) -> GovernancePolicyV2:
    return GovernancePolicyV2.model_validate(
        {
            **_loaded_policy_document(),
            "control_library": control_library.model_dump(mode="json"),
        }
    )


def test_governance_v1_continues_authorizing_existing_contracts(tmp_path: Path) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=USER_ID,
    )
    verified = load_verified_governance_policy(policy_path, verifier_path)
    assert verified.policy.schema_version == "1.0"
    contract = load_global_manifest().contract(
        "entra.user.operational_profile.update"
    )
    decision = verified.authorize(
        contract,
        tenant_id=TENANT_ID,
        target_user_id=USER_ID,
        local_target_user_ids=frozenset({USER_ID}),
    )
    assert decision.mode is AuthorizationMode.STANDING_POLICY


def test_governance_v1_cannot_enable_control_library() -> None:
    document = {
        "schema_version": "1.0",
        "control_library": {},
    }
    with pytest.raises(GovernancePolicyError) as exc_info:
        parse_governance_policy(document)
    assert exc_info.value.reason_code == "CONTROL_LIBRARY_REQUIRES_GOVERNANCE_V2"
    assert exc_info.value.operator_action == (
        "Create and sign a Governance v2 policy; keep the v1 policy unchanged."
    )


def test_valid_governance_v2_loads_verifies_and_authorizes_existing_read(
    tmp_path: Path,
) -> None:
    policy_path, verifier_path = _write_v2(tmp_path)
    verified = load_verified_governance_policy(policy_path, verifier_path)
    assert isinstance(verified.policy, GovernancePolicyV2)
    validate_policy_against_manifest(
        verified.policy,
        load_global_manifest(),
        control_manifest=load_global_control_manifest(),
    )
    contract = load_global_manifest().contract(
        "entra.identity_governance.posture.snapshot"
    )
    assert verified.authorize_read(contract, tenant_id=TENANT_ID).mode == "automatic_read"


def test_public_governance_v2_template_matches_the_closed_schema() -> None:
    document = json.loads(
        (ROOT / "examples/governance-policy-v2.template.json").read_text()
    )
    document["tenant_id"] = TENANT_ID
    document["resources"]["tenants"] = [TENANT_ID]
    document["resources"]["users"] = [USER_ID]
    document["contract_manifest_digest"] = sha256_digest(load_global_manifest())
    policy = GovernancePolicyV2.model_validate(document)
    validate_policy_against_manifest(
        policy,
        load_global_manifest(),
        control_manifest=load_global_control_manifest(),
    )


def test_governance_cli_signs_valid_v2_with_ephemeral_external_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    unsigned_path = private_root / "governance-v2.unsigned.json"
    unsigned_path.write_text(
        json.dumps(
            {
                **_loaded_policy_document(),
                "control_library": _control_library().model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    unsigned_path.chmod(0o600)
    signer = Ed25519PrivateKey.generate()
    passphrase = b"synthetic-test-passphrase"
    signer_path = private_root / "governance-test.pem"
    signer_path.write_bytes(
        signer.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )
    )
    signer_path.chmod(0o600)
    verifier_path = private_root / "governance-test.pub"
    verifier_path.write_text(public_key_text(signer), encoding="ascii")
    verifier_path.chmod(0o600)
    output_path = private_root / "governance-v2.signed.json"
    monkeypatch.setattr(
        "m365_secure_mcp.governance_cli.getpass.getpass",
        lambda _prompt: passphrase.decode(),
    )

    _sign(
        Namespace(
            input=str(unsigned_path),
            signer=str(signer_path),
            output=str(output_path),
            key_id="test-governance-v2",
        )
    )

    verified = load_verified_governance_policy(output_path, verifier_path)
    assert isinstance(verified.policy, GovernancePolicyV2)


def test_governance_cli_verify_output_is_minimized(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy_path, verifier_path = _write_v2(tmp_path)
    _verify(
        Namespace(
            policy=str(policy_path),
            verifier=str(verifier_path),
        )
    )
    output = capsys.readouterr().out
    document = json.loads(output)
    assert document["schema_version"] == "2.0"
    assert document["control_library_configured"] is True
    assert document["enabled_control_count"] == 1
    assert document["control_compatibility_digest"] == (
        control_compatibility_digest(
            load_control_compatibility_metadata(
                load_global_control_manifest()
            )
        )
    )
    assert TENANT_ID not in output
    assert USER_ID not in output


def test_unsigned_governance_v2_is_rejected(tmp_path: Path) -> None:
    policy_path, verifier_path = _write_v2(tmp_path)
    document = json.loads(policy_path.read_text())
    policy_path.write_text(json.dumps(document["policy"]), encoding="utf-8")
    policy_path.chmod(0o600)
    with pytest.raises(PrivateStateError, match="malformed"):
        load_verified_governance_policy(policy_path, verifier_path)


def test_tampered_governance_v2_is_rejected(tmp_path: Path) -> None:
    policy_path, verifier_path = _write_v2(tmp_path)
    document = json.loads(policy_path.read_text())
    document["policy"]["control_library"]["controls"][CA_CONTROL][
        "severity"
    ] = "critical"
    policy_path.write_text(json.dumps(document), encoding="utf-8")
    policy_path.chmod(0o600)
    with pytest.raises(GovernancePolicyError, match="digest mismatch"):
        load_verified_governance_policy(policy_path, verifier_path)


def test_unknown_governance_schema_version_is_rejected() -> None:
    with pytest.raises(GovernancePolicyError) as exc_info:
        parse_governance_policy({"schema_version": "4.0"})
    assert exc_info.value.reason_code == "GOVERNANCE_SCHEMA_UNSUPPORTED"


def test_invalid_governance_v2_never_falls_back_to_v1() -> None:
    document = {
        **_loaded_policy_document(),
        "control_library": _control_library().model_dump(mode="json"),
    }
    document["control_library"].pop("control_compatibility_digest")
    with pytest.raises(ValidationError, match="control_compatibility_digest"):
        parse_governance_policy(document)


def test_unknown_control_id_is_rejected(tmp_path: Path) -> None:
    library = _control_library(
        control_ids=["entra.synthetic.unknown_control"],
    )
    policy = _policy_v2(library)
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(policy)
    assert exc_info.value.reason_code == "UNKNOWN_CONTROL"


def test_retired_control_is_rejected(tmp_path: Path) -> None:
    manifest = load_global_control_manifest()
    controls = []
    for definition in manifest.controls:
        if definition.control_id != CA_CONTROL:
            controls.append(definition)
            continue
        document = definition.model_dump(mode="json")
        document["lifecycle"] = ControlLifecycle(
            state="retired",
            introduced_in_library_version="1.0.0",
            deprecated_at="2026-07-01",
            retired_at="2026-07-02",
        ).model_dump(mode="json")
        controls.append(type(definition).model_validate(document))
    retired_manifest = ControlManifest.model_validate(
        {
            **manifest.model_dump(mode="json"),
            "controls": [item.model_dump(mode="json") for item in controls],
        }
    )
    policy = _policy_v2(
        _control_library(manifest_digest=sha256_digest(retired_manifest))
    )
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(policy, retired_manifest)
    assert exc_info.value.reason_code == "CONTROL_RETIRED"


def test_manifest_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    library = _control_library(manifest_digest="sha256:" + ("0" * 64))
    policy = _policy_v2(library)
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(policy)
    assert exc_info.value.reason_code == "CONTROL_MANIFEST_CHANGED"


def test_future_or_mismatched_library_version_is_rejected(tmp_path: Path) -> None:
    library = _control_library(library_version="99.0.0")
    policy = _policy_v2(library)
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(policy)
    assert exc_info.value.reason_code == "CONTROL_LIBRARY_VERSION_INCOMPATIBLE"


def test_incompatible_definition_major_is_rejected(tmp_path: Path) -> None:
    library = _control_library(settings={CA_CONTROL: {**_setting(), "definition_major_version": 2}})
    policy = _policy_v2(library)
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(policy)
    assert exc_info.value.reason_code == "CONTROL_DEFINITION_INCOMPATIBLE"


def test_missing_or_invalid_severity_is_rejected() -> None:
    missing = _setting()
    missing.pop("severity")
    with pytest.raises(ValidationError, match="severity"):
        _control_library(settings={CA_CONTROL: missing})
    with pytest.raises(ValidationError, match="severity"):
        _control_library(settings={CA_CONTROL: _setting(severity="urgent")})


def test_customer_freshness_may_tighten_but_not_loosen(tmp_path: Path) -> None:
    tightened = _control_library(
        settings={CA_CONTROL: _setting(maximum_age=3_600)}
    )
    policy = _loaded_v2(tmp_path / "tightened", control_library=tightened)
    configuration = resolve_control_library_configuration(policy)
    assert configuration.setting(CA_CONTROL).maximum_evidence_age_seconds == 3_600

    loosened = _control_library(
        settings={CA_CONTROL: _setting(maximum_age=86_401)}
    )
    policy = _policy_v2(loosened)
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(policy)
    assert exc_info.value.reason_code == "CONTROL_FRESHNESS_LOOSENED"


def test_governance_v2_requires_exact_control_compatibility_digest() -> None:
    document = _control_library().model_dump(mode="json")
    document.pop("control_compatibility_digest")
    with pytest.raises(
        ValidationError,
        match="control_compatibility_digest",
    ):
        ControlLibraryGovernance.model_validate(document)

    policy = _policy_v2(
        _control_library(compatibility_digest="sha256:" + ("0" * 64))
    )
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(policy)
    assert exc_info.value.reason_code == "CONTROL_COMPATIBILITY_CHANGED"


def test_changed_bridge_is_rejected_by_the_same_signed_policy() -> None:
    manifest = load_global_control_manifest()
    original = load_control_compatibility_metadata(manifest)
    document = original.model_dump(mode="json")
    document["controls"][0]["maximum_evidence_age_seconds"] = 3_600
    changed = ControlCompatibilityMetadata.model_validate(document)
    assert control_compatibility_digest(changed) != control_compatibility_digest(
        original
    )

    policy = _policy_v2(_control_library())
    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(
            policy,
            manifest,
            changed,
        )
    assert exc_info.value.reason_code == "CONTROL_COMPATIBILITY_CHANGED"


def test_compatibility_metadata_for_another_manifest_is_rejected() -> None:
    manifest = load_global_control_manifest()
    document = load_control_compatibility_metadata(manifest).model_dump(
        mode="json"
    )
    document["control_manifest_digest"] = "sha256:" + ("0" * 64)
    wrong_manifest = ControlCompatibilityMetadata.model_validate(document)

    with pytest.raises(GovernancePolicyError) as exc_info:
        resolve_control_library_configuration(
            _policy_v2(_control_library()),
            manifest,
            wrong_manifest,
        )
    assert exc_info.value.reason_code == "CONTROL_COMPATIBILITY_UNAVAILABLE"


def test_compatibility_metadata_requires_exact_control_coverage() -> None:
    manifest = load_global_control_manifest()
    document = load_control_compatibility_metadata(manifest).model_dump(
        mode="json"
    )

    missing = deepcopy(document)
    missing["controls"].pop()
    with pytest.raises(ValueError, match="exact manifest"):
        ControlCompatibilityMetadata.model_validate(
            missing
        ).validate_manifest_binding(manifest)

    additional = deepcopy(document)
    additional["controls"].append(
        {
            "control_id": "entra.synthetic.unknown_control",
            "definition_major_version": 1,
            "maximum_evidence_age_seconds": 86_400,
        }
    )
    with pytest.raises(ValueError, match="exact manifest"):
        ControlCompatibilityMetadata.model_validate(
            additional
        ).validate_manifest_binding(manifest)


def test_compatibility_metadata_is_canonical_and_has_no_freshness_default() -> None:
    manifest = load_global_control_manifest()
    original = load_control_compatibility_metadata(manifest)
    document = original.model_dump(mode="json")
    permuted = deepcopy(document)
    permuted["controls"].reverse()
    reordered = ControlCompatibilityMetadata.model_validate(permuted)
    assert reordered == original
    assert control_compatibility_digest(reordered) == (
        control_compatibility_digest(original)
    )

    changed_document = deepcopy(document)
    changed_document["controls"][0]["maximum_evidence_age_seconds"] = 3_600
    changed = ControlCompatibilityMetadata.model_validate(changed_document)
    assert control_compatibility_digest(changed) != (
        control_compatibility_digest(original)
    )

    no_freshness = deepcopy(document["controls"][0])
    no_freshness.pop("maximum_evidence_age_seconds")
    with pytest.raises(
        ValidationError,
        match="maximum_evidence_age_seconds",
    ):
        ControlCompatibilityEntry.model_validate(no_freshness)


def test_unsupported_compatibility_schema_and_duplicate_entries_fail() -> None:
    manifest = load_global_control_manifest()
    document = load_control_compatibility_metadata(manifest).model_dump(
        mode="json"
    )
    unsupported = deepcopy(document)
    unsupported["schema_version"] = "2.0"
    with pytest.raises(ValidationError, match="schema_version"):
        ControlCompatibilityMetadata.model_validate(unsupported)

    duplicated = deepcopy(document)
    duplicated["controls"].append(deepcopy(duplicated["controls"][0]))
    with pytest.raises(ValidationError, match="must be unique"):
        ControlCompatibilityMetadata.model_validate(duplicated)


@pytest.mark.parametrize("maximum_age", [0, -1, 2_592_001])
def test_zero_negative_or_excessive_freshness_is_rejected(
    maximum_age: int,
) -> None:
    with pytest.raises(ValidationError, match="maximum_evidence_age_seconds"):
        _control_library(
            settings={CA_CONTROL: _setting(maximum_age=maximum_age)}
        )


def test_expired_exception_is_parseable_but_ineffective(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    library = _control_library(
        exceptions=[
            _exception(
                issued_at=now - timedelta(days=2),
                expires_at=now - timedelta(days=1),
            )
        ]
    )
    policy = _loaded_v2(tmp_path, control_library=library)
    configuration = resolve_control_library_configuration(policy)
    match = matching_control_exception(
        configuration,
        control_id=CA_CONTROL,
        definition_major_version=1,
        subject=DirectoryObjectSubjectSelector(kind="user", object_id=USER_ID),
        status="not_aligned",
        evaluated_at=now,
        tenant_id=TENANT_ID,
        profile=GovernanceProfileName.PRIVILEGED_READ,
    )
    assert match is None


def test_explicit_evaluation_time_controls_exception_boundaries(
    tmp_path: Path,
) -> None:
    issued_at = datetime(2026, 7, 26, 10, 0, tzinfo=UTC)
    expires_at = issued_at + timedelta(hours=1)
    library = _control_library(
        exceptions=[
            _exception(
                issued_at=issued_at,
                expires_at=expires_at,
            )
        ]
    )
    configuration = resolve_control_library_configuration(
        _loaded_v2(tmp_path, control_library=library)
    )
    subject = DirectoryObjectSubjectSelector(kind="user", object_id=USER_ID)

    def match(as_of: datetime) -> object:
        return matching_control_exception(
            configuration,
            control_id=CA_CONTROL,
            definition_major_version=1,
            subject=subject,
            status="not_aligned",
            evaluated_at=as_of,
            tenant_id=TENANT_ID,
            profile=GovernanceProfileName.PRIVILEGED_READ,
        )

    assert match(issued_at - timedelta(microseconds=1)) is None
    assert match(issued_at) is not None
    assert match(expires_at - timedelta(microseconds=1)) is not None
    assert match(expires_at) is None
    assert match(expires_at) is None


def test_future_issued_exception_is_rejected(tmp_path: Path) -> None:
    future = datetime.now(UTC) + timedelta(days=1)
    library = _control_library(
        exceptions=[
            _exception(
                issued_at=future,
                expires_at=future + timedelta(days=1),
            )
        ]
    )
    with pytest.raises(ValidationError, match="cannot be issued after"):
        _write_v2(tmp_path, control_library=library)


def test_wrong_control_or_definition_major_exception_does_not_match(
    tmp_path: Path,
) -> None:
    library = _control_library(
        control_ids=[APP_CONTROL, CA_CONTROL],
        settings={
            APP_CONTROL: _setting(severity="medium"),
            CA_CONTROL: _setting(),
        },
        exceptions=[_exception()],
    )
    policy = _loaded_v2(tmp_path, control_library=library)
    configuration = resolve_control_library_configuration(policy)
    subject = DirectoryObjectSubjectSelector(kind="user", object_id=USER_ID)
    assert (
        matching_control_exception(
            configuration,
            control_id=APP_CONTROL,
            definition_major_version=1,
            subject=subject,
            status="not_aligned",
            evaluated_at=datetime.now(UTC),
            tenant_id=TENANT_ID,
            profile=GovernanceProfileName.PRIVILEGED_READ,
        )
        is None
    )
    assert (
        matching_control_exception(
            configuration,
            control_id=CA_CONTROL,
            definition_major_version=2,
            subject=subject,
            status="not_aligned",
            evaluated_at=datetime.now(UTC),
            tenant_id=TENANT_ID,
            profile=GovernanceProfileName.PRIVILEGED_READ,
        )
        is None
    )


@pytest.mark.parametrize(
    "tenant_id,profile,reason_code",
    [
        (
            "99999999-9999-4999-8999-999999999999",
            GovernanceProfileName.PRIVILEGED_READ,
            "TENANT_FENCE_MISMATCH",
        ),
        (
            TENANT_ID,
            GovernanceProfileName.ROUTINE_READ,
            "PROFILE_CONTRACT_MISMATCH",
        ),
    ],
)
def test_exception_matching_rejects_cross_tenant_or_profile(
    tmp_path: Path,
    tenant_id: str,
    profile: GovernanceProfileName,
    reason_code: str,
) -> None:
    library = _control_library(exceptions=[_exception()])
    configuration = resolve_control_library_configuration(
        _loaded_v2(tmp_path, control_library=library)
    )
    with pytest.raises(GovernancePolicyError) as exc_info:
        matching_control_exception(
            configuration,
            control_id=CA_CONTROL,
            definition_major_version=1,
            subject=DirectoryObjectSubjectSelector(
                kind="user",
                object_id=USER_ID,
            ),
            status="not_aligned",
            evaluated_at=datetime.now(UTC),
            tenant_id=tenant_id,
            profile=profile,
        )
    assert exc_info.value.reason_code == reason_code


@pytest.mark.parametrize(
    "subject",
    [
        {"kind": "user", "object_id": OTHER_USER_ID},
        {"kind": "profile", "profile": "routine-write"},
    ],
)
def test_cross_fence_or_cross_profile_exception_is_rejected(
    tmp_path: Path,
    subject: dict[str, Any],
) -> None:
    control_id = PROFILE_CONTROL if subject["kind"] == "profile" else CA_CONTROL
    library = _control_library(
        control_ids=[control_id],
        settings={control_id: _setting()},
        exceptions=[_exception(control_id=control_id, subject=subject)],
    )
    with pytest.raises(ValidationError, match="outside tenant|another profile"):
        _write_v2(tmp_path, control_library=library)


def test_duplicate_exception_id_is_rejected() -> None:
    with pytest.raises(ValidationError, match="IDs must be unique"):
        _control_library(
            exceptions=[
                _exception(),
                _exception(subject={"kind": "group", "object_id": OTHER_USER_ID}),
            ]
        )


def test_ambiguous_overlapping_exception_is_rejected() -> None:
    with pytest.raises(ValidationError, match="cannot overlap"):
        _control_library(
            settings={CA_CONTROL: _setting(allow_control_wide=True)},
            exceptions=[
                _exception(
                    exception_id="exception.synthetic-1",
                    subject={"kind": "control_wide"},
                ),
                _exception(exception_id="exception.synthetic-2"),
            ],
        )


def test_control_wide_exception_requires_and_honors_explicit_opt_in(
    tmp_path: Path,
) -> None:
    library = _control_library(
        settings={CA_CONTROL: _setting(allow_control_wide=True)},
        exceptions=[_exception(subject={"kind": "control_wide"})],
    )
    configuration = resolve_control_library_configuration(
        _loaded_v2(tmp_path, control_library=library)
    )
    match = matching_control_exception(
        configuration,
        control_id=CA_CONTROL,
        definition_major_version=1,
        subject=DirectoryObjectSubjectSelector(kind="user", object_id=USER_ID),
        status="not_aligned",
        evaluated_at=datetime.now(UTC),
        tenant_id=TENANT_ID,
        profile=GovernanceProfileName.PRIVILEGED_READ,
    )
    assert match is not None
    assert match.exception_id == "exception.synthetic-1"
    assert "Synthetic customer-approved" not in repr(match)
    assert "synthetic-security-owner" not in repr(match)


@pytest.mark.parametrize(
    "subject",
    [
        {"kind": "regex", "pattern": ".*"},
        {"kind": "user", "display_name": "Synthetic Person"},
        {"kind": "user", "upn": "synthetic@example.invalid"},
    ],
)
def test_regex_display_name_and_upn_selectors_are_rejected(
    subject: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        ControlException.model_validate(_exception(subject=subject))


def test_exception_cannot_target_not_evaluated_or_alter_severity() -> None:
    not_evaluated = _exception()
    not_evaluated["applies_to_status"] = "not_evaluated"
    with pytest.raises(ValidationError, match="applies_to_status"):
        ControlException.model_validate(not_evaluated)

    with_severity = _exception()
    with_severity["severity"] = "low"
    with pytest.raises(ValidationError, match="severity"):
        ControlException.model_validate(with_severity)


def test_unknown_fields_and_dynamic_evaluator_selection_are_rejected() -> None:
    for field in ("evaluator_id", "evidence_contract_id", "graph_path", "expression"):
        setting = _setting()
        setting[field] = "untrusted"
        with pytest.raises(ValidationError, match=field):
            ControlGovernanceSetting.model_validate(setting)

    document = _control_library().model_dump(mode="json")
    document["dynamic_rule"] = "allow"
    with pytest.raises(ValidationError, match="dynamic_rule"):
        ControlLibraryGovernance.model_validate(document)


def test_control_governance_canonical_serialization_is_deterministic() -> None:
    first = _control_library(
        control_ids=[APP_CONTROL, CA_CONTROL],
        settings={
            APP_CONTROL: _setting(severity="medium"),
            CA_CONTROL: _setting(),
        },
        exceptions=[
            _exception(exception_id="exception.synthetic-1"),
            _exception(
                exception_id="exception.synthetic-2",
                control_id=APP_CONTROL,
                subject={"kind": "application", "object_id": USER_ID},
            ),
        ],
    )
    document = first.model_dump(mode="json")
    document["enabled_control_ids"].reverse()
    document["exceptions"].reverse()
    document["controls"] = {
        key: document["controls"][key]
        for key in reversed(list(document["controls"]))
    }
    second = ControlLibraryGovernance.model_validate(document)
    assert first == second
    assert sha256_digest(first) == sha256_digest(second)


def test_no_raw_private_values_appear_in_diagnostics_or_errors(
    tmp_path: Path,
) -> None:
    policy_path, verifier_path = _write_v2(
        tmp_path,
        control_library=_control_library(exceptions=[_exception()]),
    )
    settings = Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        allowed_user_object_ids=USER_ID,
        allowed_upn_domains="example.invalid",
        governance_policy_path=policy_path,
        governance_public_key_path=verifier_path,
        audit_log_path=tmp_path / "state" / "audit.jsonl",
        idempotency_db_path=tmp_path / "state" / "writes.sqlite3",
    )
    check = _profile_isolation_check(settings)
    rendered = json.dumps(check, sort_keys=True)
    assert TENANT_ID not in rendered
    assert USER_ID not in rendered
    assert "Synthetic customer-approved" not in rendered
    assert "synthetic-security-owner" not in rendered
    assert check["evidence"]["control_library_configured"] is True
    assert check["evidence"]["enabled_control_count"] == 1
    assert check["evidence"]["control_compatibility_digest"] == (
        control_compatibility_digest(
            load_control_compatibility_metadata(
                load_global_control_manifest()
            )
        )
    )

    document = json.loads(policy_path.read_text())
    document["policy"]["control_library"]["exceptions"] = [
        _exception(subject={"kind": "user", "object_id": OTHER_USER_ID})
    ]
    policy_path.write_text(json.dumps(document), encoding="utf-8")
    policy_path.chmod(0o600)
    with pytest.raises(PrivateStateError) as exc_info:
        load_verified_governance_policy(policy_path, verifier_path)
    assert OTHER_USER_ID not in str(exc_info.value)
    assert "Synthetic customer-approved" not in str(exc_info.value)
    assert "synthetic-security-owner" not in str(exc_info.value)


def test_control_wide_exception_requires_explicit_signed_opt_in() -> None:
    with pytest.raises(ValidationError, match="not explicitly allowed"):
        GovernancePolicyV2.model_validate(
            {
                **_loaded_policy_document(),
                "control_library": _control_library(
                    exceptions=[
                        _exception(subject={"kind": "control_wide"})
                    ]
                ).model_dump(mode="json"),
            }
        )


def _loaded_policy_document() -> dict[str, Any]:
    """Build one synthetic v2 body without creating signing material."""

    from m365_secure_mcp.governance import (  # local to keep test imports focused
        GovernancePolicy,
    )

    base = GovernancePolicy.model_validate(
        {
            "schema_version": "1.0",
            "policy_version": 1,
            "tenant_id": TENANT_ID,
            "active_profile": "privileged-read",
            "profiles": {
                "routine-read": {
                    "enabled_contracts": [],
                    "enabled_playbooks": [],
                },
                "routine-write": {
                    "enabled_contracts": [],
                    "enabled_playbooks": [],
                },
                "privileged-read": {
                    "enabled_contracts": [],
                    "enabled_playbooks": [],
                },
                "selected-write": {
                    "enabled_contracts": [],
                    "enabled_playbooks": [],
                },
                "break-glass": {
                    "enabled_contracts": [],
                    "enabled_playbooks": [],
                    "break_glass_ttl_seconds": 900,
                },
            },
            "resources": {
                "tenants": [TENANT_ID],
                "users": [USER_ID],
            },
            "contract_manifest_digest": sha256_digest(load_global_manifest()),
            "issued_at": datetime.now(UTC).isoformat(),
        }
    ).model_dump(mode="json")
    base["schema_version"] = "2.0"
    return base
