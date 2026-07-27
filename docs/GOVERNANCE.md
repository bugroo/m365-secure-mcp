# Signed tenant Governance

Governance is the tenant-private authority that selects profiles, resources,
contracts and, beginning with schema `2.0`, Posture Control Library settings.
The policy is signed by the tenant administrator's external Ed25519 authority.
The MCP can verify and enforce it, but cannot create, migrate, sign, approve or
modify it.

## Schema compatibility

| Schema | Existing contracts and playbooks | Posture Control Library |
|---|---|---|
| `1.0` | supported without behavior or tool-surface changes | unavailable |
| `2.0` | supported with the same authorization floors and fences | signed configuration validation only |

A v1 policy remains valid and is never migrated or re-signed automatically. A
v1 document containing `control_library` fails with
`CONTROL_LIBRARY_REQUIRES_GOVERNANCE_V2` and one action: create and sign a
separate v2 policy while leaving the v1 policy unchanged. A malformed v2
policy never falls back to v1.

M2 does not execute a control, inspect evidence timestamps, change an
assessment status or produce an assessment result. Those deterministic
ControlEngine responsibilities are postponed until after the Secure Operations
identity, endpoint, Defender and effectful-playbook slices. The reduced
Posture runtime may produce only deterministic findings and non-authorizing
proposal candidates; Governance and a compiled operational contract remain
required for any effect.

## Governance v2 control section

`control_library` is part of the existing signed policy body:

```json
{
  "control_manifest_digest": "sha256:<exact-installed-control-manifest>",
  "control_manifest_schema_version": "1.0",
  "control_library_version": "1.0.0",
  "control_compatibility_digest": "sha256:<exact-installed-compatibility-metadata>",
  "enabled_control_ids": [
    "entra.conditional_access.mfa_policy_coverage"
  ],
  "controls": {
    "entra.conditional_access.mfa_policy_coverage": {
      "definition_major_version": 1,
      "severity": "high",
      "maximum_evidence_age_seconds": 3600,
      "allow_control_wide_exception": false
    }
  },
  "exceptions": []
}
```

The enabled ID list and settings map must contain exactly the same IDs. Every
enabled control has an explicit customer severity: `info`, `low`, `medium`,
`high` or `critical`. Severity is absent from the public control manifest and
cannot come from a tool argument, Graph content, evaluator or code default.
Legacy Assurance severities continue to serve legacy reports during M2; they
are not authoritative for future Posture Control Library assessments.

The v2 policy binds the exact installed signed control-manifest digest, schema
and library version, plus the exact canonical digest of the M1 compatibility
metadata. It also pins each control's definition major. Unknown, retired,
future, mismatched or unreviewed versions fail closed. There is no network
discovery and no “select newest” behavior.

## Evidence freshness

Governance may omit a customer override and accept the public maximum, or set
a smaller positive value:

```text
effective_maximum_age =
min(public_control_maximum_age, signed_customer_maximum_age)
```

It cannot make evidence older than the public limit acceptable and cannot
disable freshness. M1 definitions do not contain signed per-requirement
freshness metadata. M2.1 therefore packages a closed public compatibility
artifact for the exact M1 manifest digest, with an explicit interim maximum of
86,400 seconds for every supported M1 control. That artifact is not part of,
and is not equivalent to, the signed M1 definitions. Its canonical digest is
an independent semantic input that every Governance v2 policy must pin.
Missing, incomplete, changed, unsupported or differently bound compatibility
metadata fails closed.

The compiler binds the compatibility digest into generated control artifacts,
local provenance and the local CycloneDX SBOM metadata. Offline diagnostics
report the digest without revealing private policy fields. These local build
records remain `local-unattested`, `not-a-release` and `external-required`;
they are not release attestations.

A future reviewed and signed control-manifest revision will move freshness into
the control definitions through the documented offline control-signing
lifecycle. That rotation requires an explicit source review, new manifest
signature, regenerated artifacts and reissued tenant policies; the runtime
will not infer or migrate the binding.

M2 computes configuration only. The reduced Posture runtime planned after the
Secure Operations slices will compare timezone-aware evidence timestamps.
Missing required evidence will remain `not_evaluated`; Governance cannot turn
it into a pass.

## Exceptions

Every exception is private, signed with the policy and contains:

- an immutable unique exception ID;
- one exact enabled control ID and definition major;
- one exact tenant-fenced subject, or an explicitly enabled control-wide
  selector;
- the fixed status `not_aligned`;
- a private rationale and opaque approving-party reference;
- timezone-aware issuance and mandatory expiry.

Selectors accept only UUIDs already present in the same policy's user, group,
application or service-principal fences, or the active profile. Regex,
display-name and UPN selectors are not fields in the schema. Control-wide
exceptions require `allow_control_wide_exception: true` in that exact
control's signed setting. Duplicate IDs, duplicate selectors and overlap
between a control-wide and an exact selector are rejected.

Expired exceptions remain parseable for audit but are ineffective.
Future-issued exceptions, automatic renewal and exceptions for
`not_evaluated` are prohibited. M2 exposes deterministic matching primitives
that require a caller-supplied timezone-aware evaluation timestamp. Issuance
is inclusive and expiry is exclusive. The primitive returns only minimized
match metadata and does not expose the private rationale or approver, convert
assessment statuses or produce public output.

## Operator workflow

Use the existing offline Governance CLI and external owner-only key files:

```bash
uv run m365-governance sign \
  --input /private/m365/governance-v2.unsigned.json \
  --signer /secure-governance-signing/governance.pem \
  --output /private/m365/governance-v2.signed.json \
  --key-id tenant-governance-2026

uv run m365-governance verify \
  --policy /private/m365/governance-v2.signed.json \
  --verifier /private/m365/governance.pub
```

Signing and verification do not call Microsoft Graph or request consent.
Private tenant IDs, resource IDs, rationales and approver references must
remain outside Git. See
[`governance-policy-v2.template.json`](../examples/governance-policy-v2.template.json)
for a fabricated unsigned template.

## No-go boundary

Governance cannot select an evaluator, evidence contract, Graph path, method,
permission, expression or executable rule. It cannot weaken existing
authorization floors, cross a tenant/profile boundary or authorize an inbound
external integration. M2 produces no legal, regulatory, GDPR, NIS2 or ISO
compliance conclusion.
