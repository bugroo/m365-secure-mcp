# ExecPlan: Secure Operations 1 — Operator Foundation

Status: implementation complete; pull-request review pending
Branch: `feat/secure-operations-operator-foundation`  
Baseline: `b3c28ea925bd9de7797d755dcabb5a4ae8d0b6fe`

## Purpose and user-visible outcome

Implement one reusable, policy-bound foundation for future T2/T3 Microsoft 365
operations. The repository will be able to compile, authorize, execute,
observe, verify, pause, and resume synthetic effectful contracts and signed
test playbooks without activating a new production Graph operation.

Pillar impact:

- Observe: typed preflight, observation, and verification boundaries.
- Operate: immutable T2 plans, real T3 dual control, durable async state.
- Assure: replay evidence, checkpoints, receipts, and deterministic outcomes.
- Experience: stable machine-readable metadata and adversarial fixtures.
- Community: documented integration contract and reviewable acceptance gates.

## Scope

1. Preserve the north star and persistent program state.
2. Add a backward-compatible Governance schema for exact operational bindings.
3. Generalize external approvals to T2 and distinct-signer T3.
4. Extend `ChangeSafeOperator` with a provider-neutral durable lifecycle.
5. Add a closed, signed-test-fixture effectful playbook schema and runner.
6. Add stable metadata, adversarial evaluation fixtures, documentation, and
   full validation.

## Non-goals

- no new production Graph endpoint, permission, scope, write tool, or workload
  contract;
- no production Identity, Intune, Defender, or Conditional Access operation;
- no production effectful playbook manifest or signing-key rotation;
- no Posture ControlEngine;
- no release, tag, deployment, registry publication, or private integration.

## Milestones and acceptance criteria

### M1 — Durable mission and plan

- canonical north star and repository agent rules exist;
- roadmap and contribution guidance reference the north star;
- this ExecPlan and progress log can resume work without chat history.

### M2 — Governance and approval authority

- Governance v1/v2 still parse, verify, and authorize existing capabilities;
- Governance v3 operational bindings pin manifest/effect-model/schema/operation
  semantics and may only raise authorization;
- T2 approval is exact, external, expiring, signed, and single-use;
- T3 requires two trusted, cryptographically distinct signers and separation
  rules; retired/compromised authorities fail closed.

### M3 — Durable operator lifecycle

- provider-neutral sync/async fixture operations traverse the closed lifecycle;
- SQLite state is tenant/profile-bound, restart-safe, and duplicate-safe;
- acceptance is not verification; uncertainty never retries automatically;
- public projections contain only statuses and opaque references.

### M4 — Effectful playbook foundation

- closed typed DAG nodes use registered executor IDs only;
- fixture signatures use isolated test trust, never production anchors;
- T2/T3 pause/resume, restart, digest drift, uncertainty, and manual handoff
  are demonstrated deterministically.

### M5 — Experience, evaluation, and documentation

- stable operator metadata and MCP annotations derive from canonical contract
  semantics;
- adversarial fixtures cover bypass, replay, signer reuse, expiry, drift,
  false async verification, retry, injection, and privacy leakage;
- operation Definition of Done includes all T2/T3 requirements.

### M6 — Final validation and publication

- all local gates pass;
- production manifests, endpoints, permissions, package version, and public
  privacy boundary remain unchanged;
- one reviewable PR is open and remote CI is green.

## Validation commands

Targeted tests run after each milestone. Final gates:

```bash
uv run pytest -q
uv run m365-compile-contracts --check
uv run ruff check .
uv run mypy src
uv run pip-audit
uv build
git diff --check
```

Additional final checks cover signed manifests, package contents, secret
patterns, privacy leakage, replay/restart behavior, and exact baseline hashes.

## Recovery and rollback

Each architectural milestone is a separate commit. Before merge, rollback is
branch deletion. After merge, revert commits in reverse order. Governance v1/v2
remain supported, no policy is auto-migrated, and no production Graph or
manifest artifact needs restoration.

## Remaining risks

- file-system approval brokers require operator-controlled key custody and
  permissions outside this repository;
- SQLite durability protects a single tenant/profile runtime boundary, not a
  distributed cluster;
- synthetic provider fixtures prove semantics but do not replace future
  recorded and live lab tests for workload operations;
- effectful production playbooks require a later reviewed manifest and signer.

## Decision log

- Use Governance v3 for operational binding instead of overloading v2, whose
  signed semantics are Posture Control configuration.
- Keep production contract/playbook manifests byte-for-byte unchanged.
- Extend `ChangeSafeOperator`; do not create a second Graph write engine.
- Use a closed provider-neutral execution adapter only for synthetic fixtures.
- Treat approval-authority trust and playbook-fixture trust as separate domains.
- End an authorized plan after write-window expiry or TOCTOU drift without a
  provider effect; a consumed approval cannot be reused after either outcome.
