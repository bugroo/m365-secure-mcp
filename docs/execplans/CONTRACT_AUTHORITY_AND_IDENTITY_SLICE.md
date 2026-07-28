# ExecPlan: Contract Authority Lifecycle and Identity Slice

Status: candidate implementation merged; live lab tracked in successor ExecPlan

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
8. Merge candidates inactive, run and review all five live-lab operations,
   regenerate after any correction, then sign the final digest and activate in
   a separate PR.

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

## Validation evidence

- 435 tests collected: 434 passed and one live-lab test skipped by default.
- compiler/check: 27 deterministic artifacts verified.
- Ruff and strict mypy: clean.
- dependency audit: no known third-party vulnerabilities; the local package is
  intentionally not available on PyPI.
- wheel and sdist: no private-key material; candidate source/recordings are in
  the source distribution and remain absent from runtime package data.
- active contract, playbook and control manifests/signatures are unchanged.

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

- activation needs reviewed live-lab execution for all five operations,
  externally generated encrypted Ed25519 material and human passphrase entry;
- Microsoft Graph behavior is proven with sanitized playback in this candidate
  PR; the post-lab digest is the only digest eligible for production signing;
- the lifecycle store is local to one tenant/profile process boundary.

## Decisions

- Preserve the signed v1 manifest as the legacy active/historical manifest.
- Stage the Identity manifest separately and never load its candidate path at
  runtime.
- Direct cutover retires `profile-debt-2026-07` only in the same reviewed
  change that adds the new public key, signature and generated active artifacts.
- Use one independent `m365-contracts-*` authority namespace.
- Keep the candidate manifest outside package runtime data; its generated
  artifacts participate in compiler `--check` but not tool registration.
- Provider code is complete and tested through synthetic playback, while the
  active catalog loader returns no Identity manifest until a current
  production signature is packaged.
- Session revocation records provider acceptance and bounded observation; it
  never claims immediate token invalidation as a verified postcondition.
- Microsoft supports scoped Group owners for membership operations. This
  candidate deliberately requires Groups Administrator until the runtime can
  bind the authenticated token subject to exact group ownership, revalidate
  that ownership at TOCTOU and prove the path in reviewed live-lab tests.

## Discoveries

- The existing active contract signer private key is unavailable, so the
  historical v1 signature must be preserved through direct cutover rather than
  re-signing.
- Graph group-member removal is safe only through the dedicated exact method
  ending in `/$ref`; it is not added to the generic JSON request method.
- Complete protected-user evidence requires active, scheduled, eligible and
  group-derived role checks. Missing or paginated/incomplete evidence blocks
  execution.
- Microsoft session revocation can take several minutes; acceptance is
  intentionally distinct from verification.
- Direct-license desired state includes the exact disabled service-plan set.
  Group-inherited assignment never satisfies a direct-assignment request and
  never becomes a removal target when no direct assignment exists.

## Successor boundary

PR #5 merged with candidates inactive. Live-lab provisioning, reviewed
execution, final-digest freeze, external signing and the separate activation
PR are tracked in
[Identity Live-Lab and Activation](IDENTITY_LIVE_LAB_AND_ACTIVATION.md).
