# ExecPlan: Contract Authority Lifecycle and Identity Slice

Status: in progress

Branch: `feat/secure-operations-identity-slice`

Baseline: `51d8469c96120ac4614f5a76c6994087799114e3`

## Purpose

Deliver an independently governed contract-signing lifecycle and five
production-quality Identity contracts as inactive schema-2.0 candidates. The
candidate artifacts, runtime, tests, recordings, evaluations, documentation,
and signing request will be complete before an external signing ceremony.

## Scope

1. Replace the single contract trust constant with a closed lifecycle registry.
2. Add an offline contract-signing CLI and custody/rotation runbook.
3. Compile five fixed Microsoft Graph v1.0 candidate contracts.
4. Extend Governance v3 and `ChangeSafeOperator` without a parallel engine.
5. Add closed Graph providers, protected-object evidence and privacy-safe
   receipts for synthetic and recorded playback.
6. Generate candidate matrices, provenance, SBOM binding and signing request.
7. Update the canonical roadmap and leave one reviewable PR with green CI.

## Non-goals

- no production key generation, custody, passphrase handling or signing;
- no candidate tool registration or Graph execution before a valid current
  production signature;
- no Identity workflow, Intune, Defender, Conditional Access or Posture runtime;
- no customer policy, credential, tenant data, private integration or release.

## Milestones

- M1 — Contract trust registry and historical direct-cutover semantics.
- M2 — External signing CLI and runbook.
- M3 — Schema-2.0 Identity candidate contracts and generated artifacts.
- M4 — Governance, protected-object and operator/provider integration.
- M5 — Recorded playback, live-lab harness and deterministic evaluations.
- M6 — Product documentation, roadmap and candidate signing request.
- M7 — Full validation, push, PR and remote CI.

## Acceptance

- existing active manifest and signature continue to verify;
- retired keys verify only explicitly pinned historical digests;
- candidate contracts cannot register or execute without a current production
  signature;
- all five providers use fixed endpoints, methods and bodies;
- incomplete protection evidence, digest drift, TOCTOU or uncertainty fail
  closed;
- Governance v1/v2 and all existing tools retain their behavior;
- no private signing material, customer data, Graph beta or object deletion;
- all repository validation gates and remote CI pass.

## Validation

```bash
uv run pytest -q
uv run m365-compile-contracts --check
uv run ruff check .
uv run mypy src
uv run pip-audit
uv build
git diff --check
```

Additional gates verify current/historical signatures, test-authority
isolation, candidate activation denial, recording sanitization, privacy,
package contents and exact candidate digests.

## Recovery and rollback

Before merge, delete the feature branch. After merge, revert the complete merge
commit. Candidate artifacts are inactive and do not require tenant-policy or
Graph rollback. A failed signing ceremony leaves the existing v1 manifest and
authority unchanged.

## Risks

- the final activation needs externally generated encrypted Ed25519 material
  and human passphrase entry;
- Microsoft Graph behavior is proven with sanitized playback until an explicit
  lab execution is reviewed;
- the lifecycle store is local to one tenant/profile process boundary.

## Decisions

- Preserve the signed v1 manifest as the legacy active/historical manifest.
- Stage the Identity manifest separately and never load its candidate path at
  runtime.
- Direct cutover retires `profile-debt-2026-07` only in the same reviewed
  change that adds the new public key, signature and generated active artifacts.
- Use one independent `m365-contracts-*` authority namespace.
