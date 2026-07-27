# ruff: noqa: S105
"""Strict, signed build-plane definitions for deterministic posture controls.

Control definitions are tenant-neutral metadata. They select only evaluator
identifiers compiled into the package; JSON cannot contain executable rules,
Graph operations, customer severity, tenant selectors, or runtime policy.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import re
from collections.abc import Sequence
from datetime import date
from enum import StrEnum
from importlib.resources import files
from typing import Literal
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_manifest import canonical_json, sha256_digest
from .contract_trust import (
    CONTROL_SIGNING_AUTHORITIES,
    CONTROL_SIGNING_KEY_ID,
    ControlSigningAuthority,
    SigningAuthorityClass,
    SigningKeyState,
)

CONTROL_ID_PATTERN = r"^entra\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,5}$"
SOURCE_ID_PATTERN = r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+){2,12}$"
MAPPING_ID_PATTERN = r"^[a-z][a-z0-9]*(?:[.:_-][a-z0-9]+){2,16}$"
SEMVER_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
UUID_PATTERN = re.compile(
    r"(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b"
)
UPN_PATTERN = re.compile(
    r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b"
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ControlLifecycleState(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class EvaluatorId(StrEnum):
    """Closed runtime implementation identifiers; never expressions."""

    ENTRA_CA_MFA_POLICY_COVERAGE_V1 = "ENTRA_CA_MFA_POLICY_COVERAGE_V1"
    ENTRA_DIRECTORY_ROLE_PERMANENT_ACTIVE_ASSIGNMENT_V1 = (
        "ENTRA_DIRECTORY_ROLE_PERMANENT_ACTIVE_ASSIGNMENT_V1"
    )
    ENTRA_APPLICATION_PERMISSION_CONTRACT_CLOSURE_V1 = (
        "ENTRA_APPLICATION_PERMISSION_CONTRACT_CLOSURE_V1"
    )
    ENTRA_APPLICATION_CREDENTIAL_EXPIRY_POSTURE_V1 = (
        "ENTRA_APPLICATION_CREDENTIAL_EXPIRY_POSTURE_V1"
    )
    ENTRA_APPLICATION_PASSWORD_CREDENTIAL_POLICY_V1 = (
        "ENTRA_APPLICATION_PASSWORD_CREDENTIAL_POLICY_V1"
    )
    ENTRA_APPLICATION_ACTIVE_CREDENTIAL_COUNT_V1 = (
        "ENTRA_APPLICATION_ACTIVE_CREDENTIAL_COUNT_V1"
    )
    ENTRA_APPLICATION_OWNER_COVERAGE_V1 = (
        "ENTRA_APPLICATION_OWNER_COVERAGE_V1"
    )
    ENTRA_PROFILE_SCOPE_CLOSURE_V1 = "ENTRA_PROFILE_SCOPE_CLOSURE_V1"
    ENTRA_PROFILE_CONTRACT_CLOSURE_V1 = "ENTRA_PROFILE_CONTRACT_CLOSURE_V1"
    ENTRA_PROFILE_RESOURCE_FENCE_CLOSURE_V1 = (
        "ENTRA_PROFILE_RESOURCE_FENCE_CLOSURE_V1"
    )


class ExpectedCondition(StrEnum):
    MFA_POLICY_COVERS_REQUIRED_IDENTITIES_AND_RESOURCES = (
        "mfa_policy_covers_required_identities_and_resources"
    )
    NO_UNEXCEPTED_PERMANENT_ACTIVE_ROLE_ASSIGNMENT = (
        "no_unexcepted_permanent_active_role_assignment"
    )
    APPLICATION_PERMISSIONS_MATCH_COMPILED_CONTRACTS = (
        "application_permissions_match_compiled_contracts"
    )
    APPLICATION_CREDENTIALS_MEET_EXPIRY_POLICY = (
        "application_credentials_meet_expiry_policy"
    )
    APPLICATION_PASSWORD_CREDENTIALS_MATCH_POLICY = (
        "application_password_credentials_match_policy"
    )
    APPLICATION_ACTIVE_CREDENTIAL_COUNTS_MATCH_POLICY = (
        "application_active_credential_counts_match_policy"
    )
    APPLICATION_OWNER_COUNT_MEETS_POLICY = (
        "application_owner_count_meets_policy"
    )
    ACTIVE_PROFILE_SCOPES_MATCH_CONTRACT_CLOSURE = (
        "active_profile_scopes_match_contract_closure"
    )
    ACTIVE_PROFILE_CONTRACTS_HAVE_CURRENT_EVIDENCE = (
        "active_profile_contracts_have_current_evidence"
    )
    ACTIVE_PROFILE_RESOURCE_FENCES_ARE_CLOSED = (
        "active_profile_resource_fences_are_closed"
    )


class EvidenceCompleteness(StrEnum):
    COMPLETE = "complete"
    COMPLETE_FOR_SIGNED_TARGETS = "complete_for_signed_targets"
    COMPLETE_FOR_ACTIVE_PROFILE = "complete_for_active_profile"


class SourceKind(StrEnum):
    MICROSOFT_SECURITY_GUIDANCE = "microsoft_security_guidance"
    EU_LEGISLATION = "eu_legislation"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"


class MappingRelationship(StrEnum):
    DIRECT = "direct"
    SUPPORTING = "supporting"


class TechnicalCoverage(StrEnum):
    DIRECT = "direct"
    PARTIAL = "partial"
    NONE = "none"


class OrganizationalCoverage(StrEnum):
    SUPPORTING = "supporting"
    NONE = "none"


class ControlLimitationId(StrEnum):
    DOES_NOT_PROVE_LEGAL_COMPLIANCE = "does_not_prove_legal_compliance"
    ORGANIZATIONAL_PROCESS_NOT_EVALUATED = (
        "organizational_process_not_evaluated"
    )
    REQUIRES_COMPLETE_CONDITIONAL_ACCESS_EVIDENCE = (
        "requires_complete_conditional_access_evidence"
    )
    PIM_CONFIGURATION_NOT_EVALUATED = "pim_configuration_not_evaluated"
    SIGNED_TARGET_SET_ONLY = "signed_target_set_only"
    CREDENTIAL_AVAILABILITY_NOT_INFERRED = (
        "credential_availability_not_inferred"
    )
    ACTIVE_PROFILE_ONLY = "active_profile_only"
    HISTORICAL_USAGE_NOT_EVALUATED = "historical_usage_not_evaluated"


class OperatorActionId(StrEnum):
    REVIEW_MFA_COVERAGE = "review_mfa_coverage"
    REVIEW_PERMANENT_ROLE_ASSIGNMENTS = "review_permanent_role_assignments"
    REVIEW_APPLICATION_PERMISSIONS = "review_application_permissions"
    REVIEW_APPLICATION_CREDENTIAL_EXPIRY = (
        "review_application_credential_expiry"
    )
    REVIEW_APPLICATION_PASSWORD_CREDENTIALS = (
        "review_application_password_credentials"
    )
    REVIEW_APPLICATION_CREDENTIAL_COUNTS = (
        "review_application_credential_counts"
    )
    REVIEW_APPLICATION_OWNERS = "review_application_owners"
    REVIEW_PROFILE_SCOPE_CLOSURE = "review_profile_scope_closure"
    REVIEW_PROFILE_CONTRACT_CLOSURE = "review_profile_contract_closure"
    REVIEW_PROFILE_RESOURCE_FENCES = "review_profile_resource_fences"


def _ensure_public_text(value: str) -> str:
    """Reject identifier-shaped customer material from public definitions."""

    if UUID_PATTERN.search(value) or UPN_PATTERN.search(value):
        raise ValueError("public control text cannot contain private identifiers")
    for token in re.findall(
        r"(?<![0-9A-Za-z])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9A-Za-z])",
        value,
    ):
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        raise ValueError("public control text cannot contain IP addresses")
    return value


def _semver(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(SEMVER_PATTERN, value)
    if match is None:
        raise ValueError("version must use canonical semantic versioning")
    return tuple(int(item) for item in match.groups())  # type: ignore[return-value]


class ControlLifecycle(StrictModel):
    state: ControlLifecycleState
    introduced_in_library_version: str = Field(pattern=SEMVER_PATTERN)
    deprecated_at: date | None = None
    retired_at: date | None = None
    successor_control_id: str | None = Field(
        default=None,
        pattern=CONTROL_ID_PATTERN,
    )

    @model_validator(mode="after")
    def lifecycle_fields_match_state(self) -> ControlLifecycle:
        if self.state is ControlLifecycleState.ACTIVE:
            if any(
                item is not None
                for item in (
                    self.deprecated_at,
                    self.retired_at,
                    self.successor_control_id,
                )
            ):
                raise ValueError("active controls cannot declare retirement metadata")
        elif self.state is ControlLifecycleState.DEPRECATED:
            if self.deprecated_at is None or self.retired_at is not None:
                raise ValueError(
                    "deprecated controls require deprecated_at and cannot be retired"
                )
        else:
            if self.deprecated_at is None or self.retired_at is None:
                raise ValueError(
                    "retired controls require deprecation and retirement dates"
                )
            if self.retired_at < self.deprecated_at:
                raise ValueError("control retirement cannot precede deprecation")
        return self


class EvidenceRequirement(StrictModel):
    requirement_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,80}$")
    source_contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    evidence_domains: list[str] = Field(min_length=1, max_length=12)
    completeness_required: EvidenceCompleteness

    @field_validator("evidence_domains")
    @classmethod
    def normalized_domains(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", item) for item in value):
            raise ValueError("evidence domains must use closed identifier syntax")
        if len(value) != len(set(value)):
            raise ValueError("evidence domains must be unique")
        return sorted(value)


class FrameworkSource(StrictModel):
    source_id: str = Field(pattern=SOURCE_ID_PATTERN)
    source_kind: SourceKind
    publisher: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=10, max_length=240)
    source_version: str = Field(min_length=4, max_length=64)
    url: str = Field(min_length=12, max_length=500)
    verified_at: date
    verification_status: VerificationStatus

    @field_validator("publisher", "title", "source_version")
    @classmethod
    def public_source_text(cls, value: str) -> str:
        return _ensure_public_text(value)

    @field_validator("url")
    @classmethod
    def authoritative_https_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or parsed.query
            or parsed.fragment
            or parsed.hostname
            not in {"learn.microsoft.com", "eur-lex.europa.eu"}
        ):
            raise ValueError("framework sources require an approved authoritative URL")
        return value


class FrameworkMapping(StrictModel):
    mapping_id: str = Field(pattern=MAPPING_ID_PATTERN)
    source_id: str = Field(pattern=SOURCE_ID_PATTERN)
    reference: str = Field(min_length=2, max_length=160)
    relationship: MappingRelationship
    technical_coverage: TechnicalCoverage
    organizational_coverage: OrganizationalCoverage
    verification_status: VerificationStatus
    published: bool
    limitation_codes: list[ControlLimitationId] = Field(
        min_length=1,
        max_length=8,
    )

    @field_validator("reference")
    @classmethod
    def public_reference(cls, value: str) -> str:
        return _ensure_public_text(value)

    @field_validator("limitation_codes")
    @classmethod
    def normalized_limitations(
        cls,
        value: list[ControlLimitationId],
    ) -> list[ControlLimitationId]:
        return sorted(set(value), key=str)

    @model_validator(mode="after")
    def publication_requires_verification(self) -> FrameworkMapping:
        if self.published and self.verification_status is not VerificationStatus.VERIFIED:
            raise ValueError("unverified framework mappings cannot be published")
        return self


class ControlDefinition(StrictModel):
    control_id: str = Field(pattern=CONTROL_ID_PATTERN)
    definition_version: str = Field(pattern=SEMVER_PATTERN)
    title: str = Field(min_length=8, max_length=120)
    description: str = Field(min_length=20, max_length=500)
    evaluator_id: EvaluatorId
    expected_condition: ExpectedCondition
    lifecycle: ControlLifecycle
    evidence_requirements: list[EvidenceRequirement] = Field(
        min_length=1,
        max_length=8,
    )
    mapping_ids: list[str] = Field(default_factory=list, max_length=16)
    limitation_codes: list[ControlLimitationId] = Field(
        min_length=1,
        max_length=12,
    )
    operator_action_id: OperatorActionId

    @field_validator("title", "description")
    @classmethod
    def public_definition_text(cls, value: str) -> str:
        return _ensure_public_text(value)

    @field_validator("evidence_requirements")
    @classmethod
    def normalized_requirements(
        cls,
        value: list[EvidenceRequirement],
    ) -> list[EvidenceRequirement]:
        ids = [item.requirement_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence requirement IDs must be unique")
        return sorted(value, key=lambda item: item.requirement_id)

    @field_validator("mapping_ids")
    @classmethod
    def normalized_mapping_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("control mapping IDs must be unique")
        for item in value:
            if re.fullmatch(MAPPING_ID_PATTERN, item) is None:
                raise ValueError("control mapping ID is malformed")
        return sorted(value)

    @field_validator("limitation_codes")
    @classmethod
    def normalized_control_limitations(
        cls,
        value: list[ControlLimitationId],
    ) -> list[ControlLimitationId]:
        return sorted(set(value), key=str)


class ControlManifest(StrictModel):
    schema_version: Literal["1.0"]
    product: Literal["m365-secure-mcp"]
    library_version: str = Field(pattern=SEMVER_PATTERN)
    sources: list[FrameworkSource] = Field(min_length=1, max_length=50)
    mappings: list[FrameworkMapping] = Field(min_length=1, max_length=200)
    controls: list[ControlDefinition] = Field(min_length=1, max_length=500)

    @field_validator("sources")
    @classmethod
    def normalized_sources(
        cls,
        value: list[FrameworkSource],
    ) -> list[FrameworkSource]:
        ids = [item.source_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("framework source IDs must be unique")
        return sorted(value, key=lambda item: item.source_id)

    @field_validator("mappings")
    @classmethod
    def normalized_mappings(
        cls,
        value: list[FrameworkMapping],
    ) -> list[FrameworkMapping]:
        ids = [item.mapping_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("framework mapping IDs must be unique")
        return sorted(value, key=lambda item: item.mapping_id)

    @field_validator("controls")
    @classmethod
    def normalized_controls(
        cls,
        value: list[ControlDefinition],
    ) -> list[ControlDefinition]:
        ids = [item.control_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("control IDs must be unique")
        return sorted(value, key=lambda item: item.control_id)

    @model_validator(mode="after")
    def references_are_closed(self) -> ControlManifest:
        source_by_id = {item.source_id: item for item in self.sources}
        mapping_by_id = {item.mapping_id: item for item in self.mappings}
        control_ids = {item.control_id for item in self.controls}
        for mapping in self.mappings:
            source = source_by_id.get(mapping.source_id)
            if source is None:
                raise ValueError("framework mapping references an unknown source")
            if (
                mapping.published
                and source.verification_status is not VerificationStatus.VERIFIED
            ):
                raise ValueError(
                    "published mapping cannot use an unverified framework source"
                )
        for control in self.controls:
            if (
                control.lifecycle.successor_control_id is not None
                and control.lifecycle.successor_control_id not in control_ids
            ):
                raise ValueError("control successor is not present in the manifest")
            for mapping_id in control.mapping_ids:
                selected_mapping = mapping_by_id.get(mapping_id)
                if selected_mapping is None:
                    raise ValueError("control references an unknown framework mapping")
                if not selected_mapping.published:
                    raise ValueError("control cannot publish an unpublished mapping")
        return self

    def control(self, control_id: str) -> ControlDefinition:
        for control in self.controls:
            if control.control_id == control_id:
                return control
        raise KeyError(f"unknown compiled control: {control_id}")

    def validate_successor(self, previous: ControlManifest) -> None:
        """Enforce monotonic lifecycle and permanent retirement reservations."""

        previous_by_id = {item.control_id: item for item in previous.controls}
        current_by_id = {item.control_id: item for item in self.controls}
        for control_id, old in previous_by_id.items():
            new = current_by_id.get(control_id)
            if new is None:
                raise ValueError("control IDs cannot be removed from the registry")
            validate_lifecycle_transition(old, new)


class ControlManifestSignature(StrictModel):
    schema_version: Literal["1.0"]
    algorithm: Literal["ed25519"]
    key_id: str = Field(min_length=3, max_length=100)
    control_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(min_length=80, max_length=128)


def validate_control_signing_authorities(
    authorities: Sequence[ControlSigningAuthority],
    *,
    allow_test_authorities: bool = False,
) -> ControlSigningAuthority:
    """Validate one closed trust ring and return its sole current authority."""

    if not authorities:
        raise RuntimeError("control signing trust ring is empty")
    key_ids = [authority.key_id for authority in authorities]
    if len(key_ids) != len(set(key_ids)):
        raise RuntimeError("control signing key IDs must be immutable and unique")
    authority_classes = {authority.authority_class for authority in authorities}
    if len(authority_classes) != 1:
        raise RuntimeError("production and test signing authorities cannot be mixed")
    if (
        SigningAuthorityClass.TEST in authority_classes
        and not allow_test_authorities
    ):
        raise RuntimeError("test signing authority is not valid for production")
    current = [
        authority
        for authority in authorities
        if authority.state is SigningKeyState.CURRENT
    ]
    if len(current) != 1:
        raise RuntimeError("control signing trust ring requires exactly one current key")
    return current[0]


def _control_signing_authority(
    key_id: str,
    authorities: Sequence[ControlSigningAuthority],
) -> ControlSigningAuthority:
    matches = [authority for authority in authorities if authority.key_id == key_id]
    if len(matches) != 1:
        raise RuntimeError("global control manifest signer is not trusted")
    return matches[0]


def sign_control_manifest(
    manifest: ControlManifest,
    signer: Ed25519PrivateKey,
    *,
    key_id: str,
    authorities: Sequence[ControlSigningAuthority] | None = None,
    allow_test_authorities: bool = False,
) -> ControlManifestSignature:
    """Sign canonical bytes only with the exact reviewed current authority."""

    selected_authorities = (
        CONTROL_SIGNING_AUTHORITIES if authorities is None else authorities
    )
    current = validate_control_signing_authorities(
        selected_authorities,
        allow_test_authorities=allow_test_authorities,
    )
    authority = _control_signing_authority(key_id, selected_authorities)
    if authority is not current or authority.state is not SigningKeyState.CURRENT:
        raise RuntimeError("retired or compromised control keys cannot sign manifests")
    signer_public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expected_public_key = base64.b64decode(
        authority.public_key_b64,
        validate=True,
    )
    if not hmac.compare_digest(signer_public_key, expected_public_key):
        raise RuntimeError("external signing key does not match the reviewed trust anchor")
    payload = canonical_json(manifest)
    return ControlManifestSignature(
        schema_version="1.0",
        algorithm="ed25519",
        key_id=authority.key_id,
        control_manifest_digest=sha256_digest(manifest),
        signature=base64.b64encode(signer.sign(payload)).decode("ascii"),
    )


def verify_control_manifest_signature(
    manifest: ControlManifest,
    signature: ControlManifestSignature,
    *,
    authorities: Sequence[ControlSigningAuthority] | None = None,
    historical: bool = False,
    allow_test_authorities: bool = False,
) -> ControlSigningAuthority:
    """Verify current or explicitly pinned historical control signatures."""

    selected_authorities = (
        CONTROL_SIGNING_AUTHORITIES if authorities is None else authorities
    )
    current = validate_control_signing_authorities(
        selected_authorities,
        allow_test_authorities=allow_test_authorities,
    )
    authority = _control_signing_authority(
        signature.key_id,
        selected_authorities,
    )
    digest = sha256_digest(manifest)
    if signature.control_manifest_digest != digest:
        raise RuntimeError("global control manifest digest mismatch")
    if authority.state is SigningKeyState.COMPROMISED:
        raise RuntimeError("control manifest signer is compromised")
    if historical:
        if (
            authority.state is SigningKeyState.RETIRED
            and digest not in authority.historical_manifest_digests
        ):
            raise RuntimeError("retired signer is not pinned to this historical manifest")
    elif authority is not current or authority.state is not SigningKeyState.CURRENT:
        raise RuntimeError("global control manifest signer is not current")
    try:
        public_key = base64.b64decode(authority.public_key_b64, validate=True)
        signature_bytes = base64.b64decode(signature.signature, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes,
            canonical_json(manifest),
        )
    except (ValueError, InvalidSignature) as exc:
        raise RuntimeError("global control manifest signature is invalid") from exc
    return authority


def validate_lifecycle_transition(
    previous: ControlDefinition,
    current: ControlDefinition,
) -> None:
    """Reject lifecycle rollback, direct retirement, and retired-ID reuse."""

    if previous.control_id != current.control_id:
        raise ValueError("lifecycle transition must preserve the control ID")
    if _semver(current.definition_version) < _semver(previous.definition_version):
        raise ValueError("control definition version cannot decrease")
    old_state = previous.lifecycle.state
    new_state = current.lifecycle.state
    allowed = {
        ControlLifecycleState.ACTIVE: {
            ControlLifecycleState.ACTIVE,
            ControlLifecycleState.DEPRECATED,
        },
        ControlLifecycleState.DEPRECATED: {
            ControlLifecycleState.DEPRECATED,
            ControlLifecycleState.RETIRED,
        },
        ControlLifecycleState.RETIRED: {ControlLifecycleState.RETIRED},
    }
    if new_state not in allowed[old_state]:
        raise ValueError("invalid control lifecycle transition")
    if old_state is ControlLifecycleState.RETIRED and current != previous:
        raise ValueError("retired control IDs are permanently reserved")


def _data_bytes(name: str) -> bytes:
    return files("m365_secure_mcp.contract_data").joinpath(name).read_bytes()


def load_global_control_manifest() -> ControlManifest:
    """Load the package-pinned control manifest and fail closed on any drift."""

    try:
        raw_manifest = json.loads(_data_bytes("global-controls.json"))
        raw_signature = json.loads(_data_bytes("global-controls.sig.json"))
        manifest = ControlManifest.model_validate(raw_manifest)
        signature = ControlManifestSignature.model_validate(raw_signature)
    except (ValueError, TypeError, json.JSONDecodeError, OSError) as exc:
        raise RuntimeError("global control manifest is malformed or unsigned") from exc

    if signature.key_id != CONTROL_SIGNING_KEY_ID:
        raise RuntimeError("global control manifest signer is not trusted")
    verify_control_manifest_signature(manifest, signature)
    return manifest
