# Official implementation roadmap

## Product direction

`m365-secure-mcp` is a **policy-bound Microsoft 365 Operations Control Plane
that observes, diagnoses, plans, executes, verifies and documents bounded
administrative operations through fixed Microsoft Graph contracts**.

Five pillars have permanent and equal roadmap weight:

1. **Observe and diagnose.**
2. **Operate and automate.**
3. **Assure and provide evidence.**
4. **Experience and evaluation.**
5. **Community and verifiable distribution.**

The first three are the core operational functions. The last two make those
functions usable, testable, reviewable and adoptable; they are not optional
afterthoughts and cannot be displaced by catalog growth.

The project is not a generic Graph proxy, an autonomous tenant administrator,
a primarily read-only product or a compliance summarizer. The administrator,
signed build artifacts, signed tenant Governance and the MCP host remain
authoritative. Runtime cannot grant consent, widen policy, register a tool,
approve its own plan or update itself.

The permanent product constraints live in the
[project north star](PROJECT_NORTH_STAR.md). This file is authoritative for
planned work under those constraints. The
[tool catalog](TOOL_CATALOG.md) and generated
[contract matrix](CONTRACT_MATRIX.md) remain authoritative for the active
runtime surface. The binding legacy-write freeze, semantic effect rules and
operation dispositions live in [Secure Operations](SECURE_OPERATIONS.md).

## Current baseline

| Plane | Implemented baseline |
|---|---|
| Build | independently signed contract, playbook and posture-control manifests; closed compiler; per-artifact digests; provenance and CycloneDX SBOM |
| Governance | backward-compatible signed schemas v1/v2/v3, profiles, resource allowlists, authorization hardening, private Posture Control configuration and inactive Identity operation bindings |
| Runtime | 27 fixed opt-in write registrations, eight compiled T0 reads, one compiled Change-safe T1 write, bounded retries, receipts and change records; five Identity providers remain candidate-only |
| Assurance | Entra posture/drift/debt evidence, credential posture, signed T0 readiness playbook, encrypted tenant-local snapshots and external read-only MSP radar |

The compiled write `entra.user.operational_profile.update` is the reference
vertical. It changes only `department`, `jobTitle` and `officeLocation` for an
allowlisted, cloud-managed, non-privileged Member. It uses `standing_policy`
by default and signed external `explicit_plan` approval when Governance raises
the floor.

Governance v2 validates signed Posture Control configuration, including exact
control-manifest and compatibility-metadata digests. It does not evaluate
evidence or produce assessments. Posture runtime is intentionally postponed
until the first Secure Operations slices provide a useful operational plane.

## Risk and authorization matrix

Governance may strengthen but never weaken a contract's authorization floor.

| Tier | Meaning | Default authorization | Expected friction |
|---|---|---|---|
| T0 | bounded read, diagnostic or preflight | `automatic_read` | none after signed profile/policy selection |
| T1 | bounded, routine and reversible effect | `standing_policy` | no per-call prompt under exact standing authority |
| T2 | disruptive identity, relationship or endpoint effect | `explicit_plan` | one external approval bound to a single immutable plan |
| T3 | privileged policy or cross-domain effect | `dual_control` or `break_glass_only` | deliberate hard gate with independent authority |
| T4 | prohibited effect | `prohibited` | unavailable |

The host always retains monitor, override and halt capability. Oversight does
not require repetitive confirmation for already governed T0/T1 operations.

## Completed foundations

Completed and retained:

- signed contract and playbook compiler;
- eight Entra T0 contracts and the T1 operational-profile contract;
- signed Workload Identity Readiness T0 playbook;
- common result, finding, receipt, change-record and playbook state schemas;
- Change-safe T1 plan/preflight/fence/TOCTOU/verify flow;
- signed write windows and external single-use approval;
- profile debt, application permission drift and credential posture;
- bounded runtime/release doctor checks;
- isolated external multi-tenant Assurance radar;
- Posture Control Library M1/M1.1 build/signing foundation;
- Governance v2 and M2.1 freshness-compatibility binding.

These foundations do not imply T2 support, real dual control, effectful
playbooks or runtime Posture assessment.

## Canonical program order

This sequence supersedes the earlier Secure Operations numbering below, which
is retained as architectural history and detailed acceptance context.

1. **Contract Signing Lifecycle and Identity Slice** — implemented as five
   schema-2.0 `candidate`/`preview` contracts plus an independent trust
   lifecycle. PR #5 merged the candidates inactive. Reviewed live-lab
   execution of the mandatory Core cases with isolated operators must precede
   the external signature and a separate `preview` activation PR. Extended
   cases are mandatory before `stable`; unavailable cases remain
   `not_executed`. The current provisioning gate is recorded in the
   [live-lab progress log](execplans/IDENTITY_LIVE_LAB_AND_ACTIVATION_PROGRESS.md).
2. **Operational Playbooks v1** — Compromised Account Containment, Bounded
   Employee Onboarding and Preserve-Data Employee Offboarding. Unsupported
   capabilities remain explicit manual handoffs.
3. **Evaluation and Release Readiness** — consolidate recorded tests, execute
   reviewed live-lab scenarios, publish a reproducible Evaluation Suite,
   compatibility matrix and scorecard.
4. **Community Adoption Program** — validated quickstart and demo, contributor
   experience, first verifiable release, future `server.json`, MCP Registry
   submission and OpenSSF Baseline/Best Practices assessment. The release
   prerequisites are frozen in
   [Community adoption gates](COMMUNITY_ADOPTION_GATES.md).
5. **Endpoint/Intune.**
6. **Defender.**
7. **Conditional Access.**
8. **Reduced Posture Runtime.**
9. **Progressive Legacy Catalog Migration.**

Recorded and live-lab harnesses begin with each operation; the evaluation
program later consolidates and publishes results. Community adoption precedes
indefinite catalog growth. Tool count is never an acceptance metric.

## Completed Secure Operations foundations

### Secure Operations 0 — Contract Effect Model

Status: merged and canonical. It changed compiler semantics but added no
production Graph operation, permission or runtime tool.

Introduce a closed semantic vocabulary:

`read`, `create_object`, `update_properties`, `state_transition`,
`relationship_add`, `relationship_remove`, `invoke_action`, `object_delete`.

Acceptance:

- `object_delete` is always T4/prohibited;
- only `relationship_remove` may use `DELETE`;
- every such endpoint ends literally in `/$ref`;
- path normalization, encoding, traversal or placeholder substitution cannot
  remove or alter the suffix;
- caller-controlled Graph URL, method, query, body, scope, headers and suffix
  remain impossible;
- Graph beta remains prohibited;
- unknown effects and invalid effect/method combinations fail closed;
- existing signed endpoints, permissions, manifest digests and runtime tools
  remain unchanged;
- the canonical effect-model digest is bound into generated artifacts,
  provenance and SBOM.

This milestone does not add a Graph operation, T2 execution, dual control or
effectful playbook.

### Secure Operations 1 — Operator Foundation

Status: implemented as an inactive, synthetic-fixture-tested foundation. No
new production Graph contract, permission, tool, or effectful playbook is
activated.

The common infrastructure for higher-impact writes includes:

- T2 `explicit_plan` execution independent of any one domain handler;
- real dual control using two distinct trusted authorities;
- async operation handles that distinguish provider acceptance from
  verification;
- resumable execution checkpoints bound to manifest, policy and plan digests;
- signed effectful playbooks with explicit halt and compensation ownership.

Acceptance:

- approvals are external, signed, single-use and bound to the exact private
  plan;
- the same signer cannot satisfy both dual-control authorities;
- TOCTOU revalidates identity, policy, resources, preconditions and write
  window immediately before effect;
- `EXECUTED_UNCERTAIN` never retries or advances a DAG automatically;
- an async `202`/`204` remains `EXECUTED_ACCEPTED` until its contract-specific
  observation rule succeeds;
- no v1/v2 Governance policy is auto-migrated or re-signed.

Implementation and integration requirements are documented in
[Operator Foundation](OPERATOR_FOUNDATION.md).

### Secure Operations 2 — Identity Slice candidate

Five separately reviewed operations now compile as unsigned candidates:

1. `entra.user.sessions.revoke`
2. `entra.user.account_state.set`
3. `entra.group.user_membership.add`
4. `entra.group.user_membership.remove`
5. `entra.user.direct_license.set`

All are T2/`explicit_plan`. Exact endpoints, categorized permissions,
Microsoft-supported roles, the project's operational role, fences, exclusions,
verification and compensation are recorded from current Microsoft Graph
v1.0 documentation. They remain unavailable through this candidate PR.
Activation requires reviewed live-lab execution of all five operations, any
Core negative cases with isolated operator profiles, any resulting corrections
and digest regeneration, an external signature over that final digest, and a
separate small activation PR. Promotion beyond `preview` additionally requires
the Extended Identity Lab.

Acceptance:

- exact tenant/profile/resource fences;
- protected, emergency and privileged identities fail closed;
- role-assignable, dynamic, protected or unclassified groups fail closed;
- license changes target one allowlisted directly assigned SKU state;
- relationship removal uses only the literal compiled `/$ref` endpoint;
- postconditions are observed without exposing raw private identifiers;
- the equivalent legacy effect cannot be active in the same profile.

### Secure Operations 3 — Endpoint/Intune Slice

Prioritize fixed managed-device actions:

- device sync;
- Defender scan;
- Defender signature update;
- remote lock;
- reboot.

Wipe, retire, fresh start and destructive reset remain prohibited. Platform,
enrollment, licensing and capability checks are preconditions. Provider
acknowledgement is not verification, recovery secrets never enter MCP output,
and non-compensatable/ambiguous actions halt.

### Secure Operations 4 — Defender Slice

Introduce exact contracts for:

- incident assignment;
- incident status;
- incident classification/determination;
- allowlisted tags;
- signed fixed comment templates.

Incident prose, alerts, email and ticket content are untrusted data and never
authorization. Free-form model-generated comments are excluded. Concurrent
collection updates require precondition digests and fail closed on drift.

### Secure Operations 5 — Operational Playbooks

This historical heading is retained for traceability, but the canonical
program **Operational Playbooks v1 starts immediately after Identity Slice**.
It does not wait for Endpoint/Intune or Defender:

1. compromised-account containment;
2. bounded onboarding;
3. preserve-data offboarding.

Each child effect is an independently compiled contract. The parent record
lists completed, pending and ambiguous nodes. An ambiguous effect pauses the
entire DAG. No playbook creates users, passwords, Temporary Access Passes,
roles, consent grants, application credentials, deletes tenant objects or
removes workload data.

Capabilities not yet implemented are explicit manual handoffs. Later
Endpoint/Intune and Defender slices enrich the same workflows; they do not
postpone or displace Evaluation and Release Readiness or Community Adoption.

### Reduced Posture runtime

Implement the smallest deterministic ControlEngine slice after operational
contracts exist:

`evidence → deterministic finding → non-authorizing proposal candidate →
governed operational contract → approval → execution → verification`

Acceptance:

- missing, stale, unlicensed, unscoped or incomplete evidence is
  `not_evaluated`, never aligned;
- severity and exceptions come only from signed Governance v2;
- Assurance cannot call a write or manufacture authorization;
- normalized private detail remains in the encrypted tenant-local capsule;
- output makes no automatic legal or regulatory compliance claim.

### Progressive legacy catalog migration

Migrate useful writes contract by contract under the
[legacy-write freeze](SECURE_OPERATIONS.md#binding-legacy-write-freeze).

Priority:

1. identity operations required by the first three playbooks;
2. Intune/endpoint actions;
3. Defender incident operations;
4. bounded handoff tools such as Planner;
5. remaining useful Exchange/Teams operations.

Office content and Power BI writes remain compatibility surfaces but are
removed from the canonical roadmap. Tool count is not an acceptance metric.

## Supporting work after operational slices

The following remain valuable but cannot displace the canonical order:

- metadata-only failure analytics and deterministic recovery guidance;
- transparent risk rules beginning in audit-only mode;
- optional outbound SIEM metadata sink with no inbound authority;
- SPDX alongside CycloneDX and verifiable release provenance;
- a separate operator-invoked updater with signature verification and
  rollback;
- separately threat-modeled remote multi-user deployment.

## Operator states and next safe action

Every effectful result must explain what happened, who must act and the single
next safe action.

| State | Meaning | Next safe action |
|---|---|---|
| `DENIED_OUT_OF_CONTRACT` | capability absent from the signed contract | select a current contract or review one in Build |
| `DENIED_BY_POLICY` | tenant/profile/resource not authorized | Governance owner reviews the correct profile/policy |
| `BLOCKED_PRECONDITION` | identity, role, scope, fence or state check failed | satisfy the named prerequisite and create a new plan |
| `AWAITING_APPROVAL` | exact plan valid but external authority missing | approve that immutable plan through the host/broker |
| `PLAN_EXPIRED` | plan or evidence no longer fresh | regenerate and review a new plan |
| `EXECUTED_VERIFIED` | contract-specific postcondition is satisfied | retain the receipt; do not retry |
| `EXECUTED_ACCEPTED` | provider accepted an asynchronous action | follow its bounded observation path |
| `EXECUTED_UNCERTAIN` | effect may have committed | halt retries and perform documented verification |
| `FAILED_RETRYABLE` | no effect occurred and bounded retry is permitted | retry only after the stated delay |
| `HALTED_BY_OPERATOR` | host stop control prevented more effects | review evidence; any continuation requires a new plan |
| `CANCELLED_BEFORE_EFFECT` | execution stopped before provider mutation | close or regenerate the plan |

Effectful playbooks additionally use `PLAYBOOK_PARTIALLY_APPLIED` and
`PLAYBOOK_COMPENSATION_REQUIRED`; neither state authorizes automatic
compensation.

## Permanent no-go rules

- no arbitrary Graph URL, method, header, query, raw body or scope;
- no Graph beta;
- no runtime tool generation, discovery or activation;
- no runtime consent grant, OAuth grant, role/PIM assignment or activation;
- no application secret or certificate creation;
- no user, group, policy or other object deletion;
- no routine device wipe;
- no password, Temporary Access Pass, recovery PIN or secret in LLM-visible
  output;
- no model-controlled approval boolean, tool or reusable token;
- no automatic permission widening or in-process auto-update;
- no executable rule language, Python, CEL, JMESPath or dynamic expression;
- no automatic retry after `EXECUTED_UNCERTAIN`;
- no finding, email, ticket, document, incident or Graph text that authorizes
  remediation;
- no inbound webhook authority over policy, contracts, approval or execution;
- no cross-tenant identity, token, policy, evidence or receipt reuse;
- no provider acknowledgement promoted to verified without its contractual
  postcondition;
- no automatic legal/compliance conclusion from technical evidence;
- no private customer identifiers, content, policies or credentials in public
  artifacts.

## Definition of done

A vertical slice is complete only when:

1. a signed tenant-neutral contract defines effect, exact Graph v1.0 call,
   closed fields, scopes, roles, tier, authorization, fences, pre/postconditions,
   expiry, idempotency, retry, verification and compensation;
2. signed private Governance selects exact tenant/profile/resources and can
   only harden authorization;
3. runtime uses a static handler and administrative consent remains manual;
4. tests cover denial classes, TOCTOU, ambiguity, privacy and tenant isolation;
5. generated registry, matrices, digests, provenance and SBOM are current;
6. operator documentation states roles, scopes, friction and recovery;
7. compiler check, tests, Ruff, strict mypy, dependency audit and build pass;
8. public artifacts contain no customer data, private policy or key material.
