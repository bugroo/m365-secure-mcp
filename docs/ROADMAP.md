# Official implementation roadmap

## Product direction

`m365-secure-mcp` is a **Policy-governed Microsoft 365 Operations Control
Plane**. It is not a generic Graph client and it is not an autonomous tenant
administrator.

The product differentiates itself through complete, bounded operations:

- fixed Microsoft Graph contracts instead of caller-selected URLs or methods;
- private, signed Governance policy per tenant and profile;
- low-friction execution for pre-approved T0/T1 operations;
- explicit authorization for higher-impact changes;
- deterministic verification, receipts, change records and Assurance findings;
- one isolated process, identity, token cache and evidence boundary per tenant.

The administrator, signed contracts, signed tenant policy and the MCP host
remain authoritative. Runtime cannot grant consent, change policy, register a
tool, approve its own plan or update itself.

This document is the single source of truth for **planned** product work. The
[tool catalog](TOOL_CATALOG.md) and
[compiled contract matrix](CONTRACT_MATRIX.md) are authoritative for what is
implemented now.

## Current baseline

The following foundations are implemented:

| Plane | Implemented baseline |
|---|---|
| Build | independently signed tenant-neutral contract, playbook and posture-control manifests, strict compiler, closed schemas and evaluator IDs, DAG validation, permission closure, per-artifact digests, evaluation fixtures, provenance and CycloneDX SBOM |
| Governance | signed tenant-private policies, deployment profiles, resource allowlists, contract/playbook selection, authorization overrides that may only tighten the global floor |
| Runtime | static tools, exact Graph v1.0 calls, token/identity checks, reusable T1 planning/preflight, Permission Impact Preview, signed write windows, external single-use approval, TOCTOU revalidation, bounded retries, post-read verification, receipts and change records |
| Assurance | Identity Governance posture, application-permission drift, application-credential posture, signed Workload Identity Readiness, and profile scope/contract/resource debt, with minimized encrypted tenant-local snapshots |

The compiled Entra surface contains eight T0 reads and one T1 write:
`entra.user.operational_profile.update`. The T1 contract changes only
`department`, `jobTitle` and `officeLocation` for an allowlisted,
cloud-managed, non-privileged member. It uses `standing_policy` by default and
can be hardened by Governance to `explicit_plan`.

The first signed playbook,
`entra.workload_identity.readiness.playbook`, composes the permission-grant and
application-credential T0 contracts. It introduces no Graph endpoint or scope,
uses `automatic_read`, correlates both views with opaque tenant-local HMAC
references, and fails closed on incomplete nodes or stale Governance.

The wider fixed catalog remains available under its existing static controls.
It will be migrated to compiled contracts incrementally; migration never
creates a generic Graph escape hatch.

## Risk and authorization matrix

Authorization is an enforceable floor, not a suggestion. Governance may move a
contract to a stronger mode but may never weaken it.

| Tier | Meaning | Default authorization | Per-operation friction |
|---|---|---|---|
| T0 | bounded read-only evidence or inventory | `automatic_read` | none after profile/policy approval |
| T1 | bounded, reversible routine change | `standing_policy` | none when the signed standing policy covers the exact operation |
| T2 | disruptive or materially consequential operation | `explicit_plan` | one host/broker approval bound to the exact plan |
| T3 | privileged, high-impact or cross-domain operation | `dual_control` or `break_glass_only` | deliberate hard gate and independent authority |
| T4 | prohibited capability | `prohibited` | cannot execute |

All calls still pass identity, token, contract, policy, fence, rate-limit and
precondition checks. An in-contract action is not automatically executable.
The host must retain an operator-visible halt/override capability, but that
capability is never exposed as a model-controlled tool argument.

## Completed vertical slice: Workload Identity Readiness

Implemented in `0.9.0`:
`entra.workload_identity.readiness.playbook`, a signed T0 read-only playbook.
It combines existing application-permission drift, application
credential posture and ownership evidence into one operator-focused result.

### Scope

- Define a tenant-neutral, signed playbook manifest whose nodes reference exact
  compiled contract IDs and fixed edges.
- Extend the compiler to validate playbook nodes, authorization floors,
  permission closure, output schemas and manifest digests.
- Add private Governance selection for the exact playbook, applications,
  service principals, contract mappings and baseline version.
- Execute only the fixed T0 DAG. Do not duplicate Graph collection when a
  verified result from the same run can be reused safely.
- Correlate grants, credential lifetime/redundancy and ownership coverage into
  deterministic findings.
- Return a bounded executive summary, findings and opaque evidence references.
  Keep normalized identifiers and detailed evidence in the encrypted
  tenant-local capsule.
- Emit a deterministic playbook record using the existing parent state
  machine. A read-only playbook has no compensation or remediation path.

### Acceptance criteria

- The playbook cannot name an arbitrary tool, URL, method, scope or output
  field.
- Its permission closure is exactly the union of the referenced compiled
  contracts; it introduces no additional Graph scope.
- Runtime rejects an unsigned/stale playbook, a missing tenant policy
  selection, cross-tenant evidence, incomplete pagination or changed contract
  digest.
- One failing node cannot be presented as complete coverage. The result marks
  the affected control `not_evaluated` and identifies the safe operator action.
- No write, consent grant, credential mutation, owner mutation or remediation
  can be reached from this playbook.
- Tests cover success, empty inventory, partial evidence, pagination, policy
  mismatch, contract-digest mismatch, snapshot isolation and output privacy.
- Compiler check, Ruff, strict mypy, tests, dependency audit and package build
  pass.

**Status:** completed in `0.9.0`.

**Dependencies:** existing three Entra Assurance contracts and encrypted
snapshot store.

**Completion evidence:** signed playbook artifact, generated permission
closure, evaluation fixtures and documentation.

## Prioritized backlog

### P0 — Complete the governed workflow foundation

#### 1. Signed playbook compiler and evaluation harness — completed in `0.9.0`

Create the reusable build-time playbook schema/compiler used by the readiness
vertical. Add realistic, sanitized workflow evaluations for authorization,
fences, incomplete evidence, deterministic next actions and context-efficient
outputs.

Acceptance:

- DAGs are acyclic unless a bounded, explicitly declared verification loop is
  supported later.
- Every node resolves to a pinned contract digest at build time.
- Playbook definitions cannot be added or altered by tenant data at runtime.
- Evaluations contain no real tenant IDs, resource IDs, people or content.

Depends on: current contract compiler and operation/playbook schemas.

#### 2. Workload Identity Readiness T0 playbook — completed in `0.9.0`

Implement the vertical slice above. This is the first product workflow that is
more valuable than invoking isolated Graph reads while adding no write scope.

Depends on: item 1.

#### 3. Reusable Change-safe operator engine — completed in `0.10.0`

Extract the existing T1 flow into a contract-independent deterministic engine:

`plan → preflight → Permission Impact Preview → fences → authorize → TOCTOU
revalidation → execute → contract-specific verify → receipt → change record`

Acceptance:

- T0/T1 friction remains unchanged.
- A preflight-only mode can produce the complete plan and impact preview
  without calling a write endpoint; it is never described as a guaranteed
  Microsoft Graph simulation.
- Governance can impose deterministic write windows. The runtime uses a
  trusted local time source, enforces plan expiry and rechecks the window at
  execution.
- Resource fences prefer immutable object IDs and verify any security-relevant
  relationship at preflight and again before execution.
- Host/broker approval is a signed, single-use artifact bound to tenant,
  profile, operator, contract/policy digests, normalized parameters, resources,
  preconditions and expiry.
- Approval is not an MCP tool and `execute` accepts no caller-controlled
  `approved=true` equivalent.
- `EXECUTED_UNCERTAIN` is never retried automatically.
- Verification modes remain explicit:
  `strong_readback`, `async_status`, `resource_observed`,
  `provider_acknowledged` or `not_verifiable`.

Depends on: current T1 Entra implementation.

### P1 — MSP Assurance and the first T2 operation

#### 4. Scope, contract and resource debt for profiles — completed in `0.11.0`

Compare each profile's effective token/grant posture with the exact permission
closure of its enabled contracts. Report unused or unexpected scopes, missing
scopes, stale policy versions, contracts without evidence, unused resource
allowlists and persistently failing or unused tools. Never change a grant,
consent or allowlist.

Acceptance:

- tenant/private identifiers remain encrypted or HMAC-referenced;
- severity comes from the signed customer baseline;
- a finding distinguishes `aligned`, `not_aligned`, `not_applicable`,
  `not_evaluated` and `exception_approved`;
- Assurance proposes a governed contract or admin action but never remediates.

Depends on: playbook compiler and current permission-drift vertical.

Completion evidence:

- fixed signed `entra.profile_debt.posture.snapshot` T0 contract;
- signed customer severity, lifecycle, evidence and exception baseline;
- correlation of validated token claims, current-app grant evidence, active
  profile closure, audit outcomes and private/local resource fences;
- explicit complete versus `not_evaluated` coverage per evidence source;
- encrypted raw IDs/evidence with public counts, contract/scope names and HMAC
  references only;
- no consent, grant, policy, allowlist or baseline mutation path.

#### 5. Runtime self-check expansion — completed in `0.12.0`

Extend `--doctor` and release verification with bounded local checks:
manifest/playbook digests, installed package/provenance/SBOM consistency,
owner/mode/symlink protections, profile isolation and excessive effective
scopes.

Acceptance:

- checks inspect only known configuration and application-owned paths;
- there is no indiscriminate home-directory or secret search;
- checks never print secrets, tokens, tenant IDs or raw private policy;
- the result gives one deterministic operator action for each failure;
- no self-check changes configuration, permissions or the installed release.

Depends on: signed playbook artifacts and stable release metadata.

Completion evidence:

- offline verification of both signed manifests and their packaged digest
  maps;
- compiler-packaged provenance and CycloneDX SBOM checked against the runtime
  version and installed runtime dependencies;
- bounded metadata checks for only configured/application-owned private paths,
  without traversal or secret search;
- tenant/profile cache namespace, state-role separation and Governance/runtime
  profile-class checks;
- exact effective scope closure versus the exposed fixed tool surface;
- one deterministic `operator_action` on every diagnostic check; no check
  mutates files, permissions, configuration or the installed release.

#### 6. Multi-tenant drift radar — completed in `0.13.0`

Provide an external orchestrator pattern for scheduled, read-only Assurance
across MSP customers. Every customer run launches the same single-tenant
runtime boundary already documented.

Acceptance:

- no central token pool, cross-tenant runtime switch or shared policy;
- one process, registration, keychain namespace, snapshot and baseline per
  tenant/profile;
- failures are isolated per tenant and do not expose another tenant's state;
- the aggregate report contains tenant-assigned opaque references and
  minimized status metadata, not raw Graph content;
- no remediation route exists from the radar.

Depends on: item 4 and stable Assurance output schemas.

Completion evidence:

- external `m365-msp-radar` process launches one fixed MCP child per private
  policy rather than switching tenant inside one runtime;
- owner-only configuration accepts only five fixed read-only Assurance tools,
  unique opaque deployment references and unique policy files;
- concurrency is bounded to four and a child failure cannot stop or expose
  another deployment;
- aggregate output retains only status, coverage, severity/alignment counts
  and evidence availability—never Graph content, tenant/resource IDs, paths or
  child errors;
- the report asserts zero writes, no remediation route and no shared token
  pool.

#### 7. Posture control library — 5 points

**M1 build-plane foundation and M2 Governance v2 completed; M3 runtime
evaluation remains planned.**

Generalize deterministic controls and baseline exceptions across Entra first,
then sharing, endpoint and security domains. Map evidence to current Microsoft
guidance and selected public security frameworks.

Acceptance:

- mappings identify source/version and evidence coverage;
- reports say “alignment”, never claim automatic legal or regulatory
  compliance;
- missing license, role, scope or API evidence becomes `not_evaluated`, not a
  pass;
- exceptions are signed, scoped and expiring.

Implemented in M1:

- independently signed public control manifest with ten tenant-neutral Entra
  control IDs and monotonic lifecycle rules;
- closed evaluator identifiers with no rule language or dynamic evaluation;
- verified Microsoft and NIS2 source/mapping registry with explicit technical,
  organizational and legal-claim limitations;
- deterministic generated registry, control matrix, digests, compiler tests,
  diagnostics, provenance and SBOM binding;
- no Governance v2, evaluator runtime, Graph endpoint, permission, write or
  remediation change.

M1.1 hardens only the signing lifecycle: external encrypted signer input,
current/retired/compromised public-key metadata, closed historical verification,
direct-cutover rotation, local-build provenance labels and an explicit future
release gate. It does not begin Governance v2 or runtime control evaluation.

Implemented in M2:

- backward-compatible signed Governance schemas `1.0` and `2.0`, with no
  automatic migration or v2-to-v1 fallback;
- exact control-manifest digest/schema/library and definition-major binding;
- explicit enabled controls and mandatory customer severity;
- deterministic public freshness ceilings that customer policy may only
  tighten, supplied for M1 by canonically digested compatibility metadata
  pinned in the signed Governance v2 policy;
- exact tenant/profile-fenced, signed and expiring exceptions with
  deterministic matching primitives;
- fail-closed CLI and diagnostics validation without private identifier output;
- no ControlEngine, evidence timestamp inspection, assessment output, Graph
  endpoint, permission, write or remediation change.

M2.1 hardens the temporary M1 freshness bridge. M1 itself has no signed
freshness field, so the bridge remains explicitly separate from the signed
definitions. Its schema, exact manifest coverage and content digest are
compiled into diagnostics, generated artifacts, local provenance and SBOM
metadata. A future reviewed control-manifest rotation will move freshness into
the signed definitions; M3 remains unstarted.

Next milestone (M3):

- implement the deterministic ControlEngine over existing bounded Assurance
  evidence;
- preserve `not_evaluated` for missing, stale, unlicensed, unscoped or
  incomplete evidence;
- consume Governance v2 severity, freshness and effective exceptions without
  allowing runtime policy mutation;
- emit bounded assessment results with opaque evidence references and retain
  normalized detail only in the encrypted tenant-local capsule.

Depends on: items 1 and 4.

#### 8. First compiled T2 write: bounded group membership addition — 8 points

Migrate the existing fixed member-add capability to a compiled contract only
after the reusable Change-safe operator exists. Treat membership as T2 because
a group can confer application, workload or administrative access.

Required boundaries:

- exact allowlisted group and member;
- cloud-managed member identity;
- reject role-assignable groups, protected/admin groups and any group whose
  privilege status cannot be proved;
- `explicit_plan` authorization;
- duplicate membership handled idempotently;
- post-read membership verification and deterministic receipt;
- no batch input, group creation, owner change, role assignment or removal.

Compensation must be documented as a separate future contract or manual
runbook. Absence of an agent removal tool must not be described as automatic
rollback.

Depends on: item 3 and dedicated non-production Graph integration tests.

### P2 — Readiness playbooks and operational learning

#### 9. Onboarding readiness T0 playbook — 5 points

Assess identity source, target groups, license prerequisites, mailbox/Teams/
OneDrive readiness and policy fences without changing the tenant. Return
missing prerequisites and the only safe next action for each gap.

Depends on: signed playbooks and compiled read coverage for each included
domain.

#### 10. Bounded onboarding T1/T2 playbook — 13 points, split before work

Build only after every effectful node is an independently compiled contract.
Split the epic into identity metadata, selected group membership and workload
readiness slices. The parent DAG must support resume, partial completion,
explicit compensation requirements and operator halt.

No all-or-nothing guarantee may be claimed across Microsoft 365 workloads.
License assignment, role assignment and destructive cleanup remain excluded
until separate contracts and authorization tiers are approved.

Depends on: items 3, 8 and 9.

#### 11. Failure analytics and deterministic recovery guidance — 5 points

Store metadata-only failure fingerprints and effective recovery guidance in a
tenant-local database.

Acceptance:

- it can recommend a documented precheck or operator action;
- it cannot modify contracts, policy, risk tiers, authorization or retries;
- it never automatically repeats a write;
- documented guidance covers 401/403 identity and scope checks, 412 fresh
  preflight/ETag, 429 `Retry-After`, and manual verification for uncertain
  outcomes;
- message/file content, raw parameters, tokens and Graph error bodies are not
  stored.

Depends on: stable operation/receipt schemas.

#### 12. Deterministic risk rules in audit-only mode — 8 points

Add transparent rules for unusual volume, new contract use, write windows and
privileged profile use. Begin with observation only.

Acceptance:

- no LLM/ML makes authorization decisions;
- every score is reproducible from versioned rules and metadata;
- rules can only add warnings in audit-only mode;
- any future enforcement requires signed Governance opt-in, evaluations and a
  separate review; it can only tighten authorization.

Depends on: evaluation harness, failure analytics and sufficient sanitized
operational evidence.

#### 13. Optional SIEM sink — 5 points

Export structured, redacted audit/Assurance metadata to an operator-configured
sink. The local audit/receipt remains authoritative.

Acceptance:

- no complete parameters, tokens, content or tenant identifiers by default;
- queue bounds, TLS validation, backpressure and sink health are explicit;
- a sink outage is visible but cannot silently discard the local write record;
- inbound SIEM data cannot change MCP policy or trigger a tool.

Depends on: stable event schema and redaction tests.

### P3 — Controlled domain expansion and release assurance

#### 14. Migrate the fixed catalog contract by contract — 3–8 points per vertical

Priority order:

1. Entra users, groups, applications and devices;
2. Teams and SharePoint sharing boundaries;
3. Intune and Defender operations;
4. Exchange-backed administrative workflows.

Each operation receives its own exact schema, least-privilege permission set,
fences, tier, authorization, retry semantics and verification. Coverage count
is not an acceptance criterion. Word, PowerPoint and Power BI expansion is not
a roadmap priority; existing fixed capabilities remain documented but do not
drive the control-plane design.

#### 15. Phishing containment readiness, then containment — 13 points, split

Start with a T0/T1 evidence playbook. Any effectful cross-domain containment
must be split into individually reviewable contracts and treated as T3 unless
the impact analysis proves a lower tier. It requires dual control, halt,
partial-completion evidence and explicit recovery ownership. No bulk delete or
implicit tenant-wide search-and-act loop is allowed.

Depends on: mature Exchange/Defender contracts and the playbook engine.

#### 16. Release assurance and external updater — 8 points

Add SPDX alongside CycloneDX, release signing and verifiable provenance.
Design any updater as a separate operator-invoked component:

`download → verify signature/checksum/provenance → compatibility check → offline
tests → snapshot → promote → smoke test → rollback on failure`

The MCP process itself never downloads, installs or activates an update.

Depends on: stable manifest/playbook schemas and release compatibility rules.

#### 17. Remote multi-user deployment — deferred, estimate after separate approval

The local stdio server must not be exposed through a generic network proxy. A
future remote service would require a separately reviewed OAuth 2.1 resource
server, audience-bound tokens, per-client/session isolation, CSRF/state
protection, tenant routing outside tool arguments, OBO design and independent
threat modeling. Until that project exists, remote multi-user mode is a
documented no-go.

## Operator states and the next safe action

Every effectful result must answer: what happened, who must act and what is the
single next safe action?

| State | Meaning | Next safe action |
|---|---|---|
| `DENIED_OUT_OF_CONTRACT` | the capability does not exist in the signed build contract | select an existing contract or review/add one in the Build plane |
| `DENIED_BY_POLICY` | the contract exists but this tenant/profile/resource is not authorized | Governance owner reviews and signs a tighter-scope policy change or uses the correct profile |
| `BLOCKED_PRECONDITION` | identity, scope, role, fence, ETag or safety evidence failed | satisfy the named precondition, then generate a new plan |
| `AWAITING_APPROVAL` | exact T2/T3 plan is valid but lacks host/broker authority | authorized operator approves that immutable plan; do not alter and reuse it |
| `PLAN_EXPIRED` | approval/preflight evidence is no longer fresh | regenerate and review a new plan |
| `EXECUTED_VERIFIED` | the effect matches the contract's verification rule | retain the receipt; no retry |
| `EXECUTED_ACCEPTED` | the provider accepted an async/non-strongly-verifiable action | follow the contract's status-observation path; do not label it verified |
| `EXECUTED_UNCERTAIN` | the effect may have committed but cannot be established | halt retries and perform the documented read/manual verification |
| `FAILED_RETRYABLE` | no effect occurred and the contract permits a bounded retry | retry only after the stated delay and within the contract limit |
| `HALTED_BY_OPERATOR` | the host/operator stop control prevented further effects | review evidence and create a new plan only if continuation is authorized |
| `CANCELLED_BEFORE_EFFECT` | execution ended before the provider mutation | close the plan or generate a new one; the old authorization is not reusable |

For playbooks, `PLAYBOOK_PARTIALLY_APPLIED` and
`PLAYBOOK_COMPENSATION_REQUIRED` must enumerate completed nodes, unexecuted
nodes and the responsible human owner. The system never invents or silently
executes compensation.

## Permanent no-go rules

The following are architectural restrictions, not backlog items:

- no arbitrary Graph URL, method, headers, query or body exposed to the model;
- no Graph beta endpoint in a production contract;
- no runtime generation, discovery, installation or activation of tools;
- no runtime consent request, API permission grant, OAuth grant, directory-role
  assignment, app-role assignment or PIM activation;
- no model-controlled approval tool, boolean or reusable approval token;
- no in-process auto-update;
- no automatic retry after `EXECUTED_UNCERTAIN`;
- no learned/failure/risk component that changes a contract, policy, tier,
  authorization floor or resource allowlist;
- no Assurance finding that directly triggers remediation;
- no cross-tenant token, policy, baseline, receipt, audit or snapshot reuse;
- no LLM-generated prose as the authoritative receipt or change record;
- no promotion of `202`/`204` or provider acknowledgement to “verified” unless
  the contract's verification rule is satisfied;
- no legal/compliance certification inferred from posture evidence;
- no public fixture, artifact, issue or documentation containing customer
  tenant IDs, resource IDs, users, content, tokens or private policy.

## Definition of done for every vertical slice

A slice is complete only when all applicable gates pass:

1. A tenant-neutral manifest/contract or signed playbook defines exact methods,
   endpoints, fields, scopes, roles, tier, authorization, fences,
   pre/postconditions, expiry, retry, verification and compensation.
2. Private Governance selects exact tenants/profiles/resources and can only
   harden the authorization floor.
3. Runtime uses a static handler and fixed API route; administrative consent
   remains a manual tenant-admin action.
4. Tests cover the happy path, each denial class, pagination/limits, TOCTOU,
   ambiguous outcomes, redaction and tenant isolation as applicable.
5. Compiler output, permission matrix, digests, provenance and SBOM are current.
6. Operator documentation identifies required roles/scopes, friction point,
   result states and recovery.
7. `m365-compile-contracts --check`, Ruff, strict mypy, tests, dependency audit
   and package build pass.
8. A privacy scan confirms that no customer identifiers, content, credentials
   or private policies entered public artifacts.

## Reference boundaries

Implementation should continue to track primary specifications:

- [Model Context Protocol tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [EU AI Act, Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)

Oversight is implemented as understandable evidence, monitoring, host
override/halt and tier-appropriate authorization—not repetitive confirmation
dialogs for already governed routine work. This engineering model supports
governance; it is not by itself a legal conformity assessment.
