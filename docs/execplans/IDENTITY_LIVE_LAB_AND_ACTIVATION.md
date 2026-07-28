# ExecPlan: Identity Live-Lab Validation and Activation

Status: blocked only at the consolidated external Identity activation boundary

Branch: `feat/identity-activation-program`

Baseline: `9b7489ad67b637065bd38b47deeeef771a379b33`

## Purpose and outcome

Validate the five inactive Identity candidates against a dedicated synthetic
Microsoft 365 tenant, freeze the post-lab digest and prepare a separate
externally signed activation PR. Until a lab exists, deliver the complete
fail-closed inventory, process gate, privacy schema, scanner and provisioning
requirements without authenticating or writing to Graph.

## North Star contribution

- **Observe and diagnose:** verifies the exact tenant, operator, scopes, roles,
  marker and synthetic resource topology before writes.
- **Operate and automate:** exercises only the five fixed candidates through
  the common operator path; no Graph router or new operation.
- **Assure and provide evidence:** produces minimized, deterministic,
  privacy-scanned live evidence.
- **Experience and evaluation:** provides a stable boundary CLI, external
  inventory template and reproducible cases.
- **Community and verifiable distribution:** keeps the generic harness,
  schemas and tests public while excluding tenant data and credentials.

## Scope

1. Merge PR #5 with candidates inactive and verify protected `main`.
2. Define an owner-only external lab inventory and explicit process gate with
   five isolated operator profiles.
3. Split the synthetic topology into mandatory Core and promotion-only
   Extended labs.
4. Add minimized evidence schemas and a deterministic leak scanner.
5. Run the five candidates and negative cases only when the dedicated lab,
   credentials, Governance and approval authority are mounted.
6. After reviewed live evidence, regenerate/freeze the candidate digest.
7. Stop for the external production-signing ceremony.
8. Deliver activation separately with public trust metadata and no private key.

## Non-goals

- no customer or WERIXO production tenant;
- no automated role assignment, consent, account creation or credential
  creation;
- no candidate activation before reviewed live evidence and external signing;
- no Operational Playbooks, Intune, Defender, Conditional Access or Posture
  runtime;
- no release, tag, deployment or private integration.

## Milestones

- M1 — Merge inactive candidate PR and verify main.
- M2 — External inventory schema, dedicated-lab gate and provisioning template.
- M3 — Tenant inspection and complete live execution of five candidates.
- M4 — Sanitized evidence, corrections, regression and final digest freeze.
- M5 — External signing ceremony.
- M6 — Separate activation PR and active `preview` contractual exposure.

M1 and M2 are complete. The provider implementations, Operator Foundation,
Governance v3 bindings, recorded playback, deterministic evaluations,
candidate compiler, trust lifecycle and fail-closed lab boundary are present.
M3 is blocked by the absence of the consolidated external lab input bundle,
not by a code or architectural defect.

## Acceptance

- no lab write is possible without exact enable flag, profile, acknowledgement,
  tenant/client match, owner-only inventory and external authority files;
- inventory and errors never enter MCP output;
- all five candidates, isolated operators and required Core negative fixtures
  are represented;
- Extended gaps remain `not_executed` and prevent `stable`, not `preview`;
- public evidence rejects raw identifiers, UPNs, IPs, request IDs and secrets;
- no production candidate is signed or activated before reviewed live tests;
- active historical manifests and Graph surfaces remain unchanged;
- local and remote validation pass.

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

Additional validation checks the inventory topology, file permissions,
symlink rejection, process binding, candidate/effect digests, redacted errors,
public evidence privacy and disabled-by-default network boundary.

## Recovery and rollback

Before merge, delete the feature branch. After merge, revert the complete merge
commit. The changes add only a disabled lab boundary and documentation; they
activate no Graph operation and migrate no policy. An uncertain live write
halts the target and requires manual review rather than retry.

## Decisions

- The live-lab candidate is intentionally unsigned; live evidence determines
  the final digest that becomes eligible for external signing.
- Tenant and resource IDs live only in an external owner-only inventory.
- A marker group with an externally pinned description digest independently
  marks the tenant as a lab but never authorizes a write.
- The dedicated single-tenant public-client App Registration uses the exact
  aggregate candidate scope closure, system-browser PKCE (device code only as
  explicit fallback), no secret, no ROPC and no automatic consent.
- Five separate token-cache namespaces, signed policies and token subjects
  bind session, account, group, license and negative authority. One person may
  operate several profiles, but one token/profile cannot impersonate another.
- Effect authorization and protected-object evidence roles are represented
  separately. Every operation requires `Global Reader` in addition to its
  effect-specific role because that is the least common supported role across
  the three fixed directory-role evidence calls.
- Groups Administrator remains required during this phase.
- Public evidence uses approximate duration buckets and stable error codes, not
  raw Graph responses.

## Remaining risks

- Actual Graph response, replication, throttling and ambiguous-transport
  behavior remain unverified until the dedicated lab exists.
- Dynamic and role-assignable groups, real synchronization, PIM,
  group-based licensing and advanced concurrency form the Extended gate.
  Unavailable cases remain `not_executed`; operations cannot become `stable`.
- The signing authority remains an intentionally external human boundary after
  the lab passes.
- The merged PR #5 candidate digest is invalidated by the reviewed role-metadata
  correction. The current unsigned digest remains ineligible until live
  evidence exists and may change again after observed Graph behavior.

## Consolidated external input boundary

The program resumes only when all of the following are externally available:

1. a dedicated, non-production Microsoft 365 tenant carrying the independent
   lab marker;
2. one single-tenant public-client App Registration with the exact reviewed
   delegated scope closure and manual administrator consent;
3. five isolated delegated operator sessions (session, account, group,
   license and negative) with their exact roles and distinct owner-only
   keychain namespaces;
4. the Core synthetic users, groups, membership relationships, subscribed
   SKUs, capacity, `usageLocation` and service-plan fixtures;
5. four signed Governance v3 effect policies, one signed negative deny policy,
   their verification keys, and four externally held T2 approval authorities;
6. an externally rendered owner-only inventory matching the committed schema;
7. after Core evidence passes and the final digest is frozen, the independent
   encrypted production contract signer and its externally reviewed custody
   procedure.

These inputs are indispensable: without them the project cannot prove real
Graph permissions, roles, replication, acceptance/verification semantics,
protected-object rejection or ambiguous-transport handling. Without reviewed
Core evidence the signing request must remain ineligible; without the
independent signer the trust registry cannot cut over; without both, exposing
the tools would violate the signed-manifest boundary.

No customer or WERIXO production tenant may substitute for this bundle. The
repository must not generate consent, roles, production approval authorities
or the contract signer.
