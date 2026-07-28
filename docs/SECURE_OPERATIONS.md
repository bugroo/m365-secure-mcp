# Secure Operations

## Product identity

`m365-secure-mcp` is a **policy-bound Microsoft 365 Operations Control Plane
that observes, diagnoses, plans, executes, verifies and documents bounded
administrative operations through fixed Microsoft Graph contracts**.

Five product pillars have permanent and equal roadmap weight:

1. **Observe and diagnose** — bounded inventory, preflight and operational
   evidence.
2. **Operate and automate** — fixed contracts, proportional authorization,
   verified effects and resumable workflows.
3. **Assure and provide evidence** — deterministic findings, receipts, change
   records and drift evidence.
4. **Experience and evaluation** — reliable exposure, diagnostics and
   reproducible agent-facing evaluation.
5. **Community and verifiable distribution** — reviewable contributions,
   installation and attestable public artifacts.

The first three are core operational functions. The last two keep those
functions usable, measurable and adoptable and cannot be displaced by catalog
growth.

The project is neither a generic Microsoft Graph proxy, an autonomous tenant
administrator, a primarily read-only product, nor a compliance summarizer.
Its intended advantage over generic Graph MCP proxies is real administrative
capacity with signed authority, resource fences, risk-proportional approval,
verification and evidence.

## Binding legacy-write freeze

The 27 existing write-tool registrations remain available under their current
controls while migration is reviewed. Effective immediately:

- no new legacy static write may be added;
- an existing legacy write may not gain a new parameter, target or effect;
- no new Graph permission may be added for a legacy write;
- security and regression fixes remain permitted;
- every useful write must migrate to a compiled contract and the common
  `ChangeSafeOperator`;
- a legacy operation and its compiled equivalent must never be enabled
  simultaneously for the same effect;
- legacy receipts must not be presented as governed Change-safe operation
  records.

This freeze does not delete or silently disable a current tool. Removal and
default changes require their own reviewed migration.

## Legacy write inventory

The disposition is architectural, not a claim that migration has already
happened.

<!-- legacy-write-inventory:start -->
| Existing tool | Current model | Disposition | Canonical direction |
|---|---|---|---|
| `m365_create_mail_draft` | legacy static | migrate | compiled bounded draft contract |
| `m365_send_mail_draft` | legacy static | migrate | separate effect contract with proportional authorization |
| `m365_create_calendar_event` | legacy static | migrate | compiled create contract preserving transaction id |
| `m365_update_calendar_event` | legacy static | migrate | compiled update contract preserving ETag checks |
| `m365_create_contact` | legacy static | deprecate | retain for compatibility; not an operations-plane priority |
| `m365_create_todo_task` | legacy static | migrate | compiled handoff-task contract |
| `m365_update_todo_task` | legacy static | migrate | compiled verified update contract |
| `m365_send_channel_message` | legacy static | migrate | bounded external-communication contract |
| `m365_send_chat_message` | legacy static | migrate | bounded external-communication contract |
| `m365_create_planner_task` | legacy static | migrate | compiled operational-task contract |
| `m365_update_planner_task` | legacy static | migrate | compiled ETag-bound task contract |
| `m365_update_planner_task_details` | legacy static | migrate | compiled details/checklist contract |
| `m365_update_entra_user_operational_profile` | compiled Change-safe T1 | compiled and retained | canonical reference implementation |
| `m365_set_directory_user_account_enabled` | legacy static | replace | `entra.user.account_state.set` after Operator Foundation |
| `m365_update_directory_group` | legacy static | split | separate exact metadata/effect contracts only if required |
| `m365_add_user_to_group` | legacy static | replace | exact membership add/remove contract pair |
| `m365_sync_managed_device` | legacy static | migrate | compiled Intune action with async observation |
| `m365_reboot_cloudpc` | legacy static | migrate | compiled Windows 365 action; distinct from Intune reboot |
| `m365_replace_word_text` | legacy static | remove from canonical roadmap | compatibility only; no new investment |
| `m365_replace_powerpoint_text` | legacy static | remove from canonical roadmap | compatibility only; no new investment |
| `m365_update_excel_range` | legacy static | remove from canonical roadmap | compatibility only; no new investment |
| `m365_append_onenote_page_text` | legacy static | remove from canonical roadmap | compatibility only; no new investment |
| `m365_refresh_powerbi_dataset` | legacy static | remove from canonical roadmap | separate product boundary; no new investment |
| `m365_rebind_powerbi_report` | legacy static | remove from canonical roadmap | separate product boundary; no new investment |
| `m365_update_entra_application` | legacy static | split | metadata and security-sensitive state require separate contracts |
| `m365_update_entra_service_principal` | legacy static | split | metadata and access state require separate contracts |
| `m365_update_conditional_access_policy` | legacy static | replace | template/state-specific T3 contracts under dual control |
<!-- legacy-write-inventory:end -->

## Secure Operations 0: semantic effect model

The compiler uses this closed vocabulary:

- `read`
- `create_object`
- `update_properties`
- `state_transition`
- `relationship_add`
- `relationship_remove`
- `invoke_action`
- `object_delete`

The rules are semantic rather than based only on an HTTP verb:

- `object_delete` is T4 and prohibited in every compiled contract;
- `relationship_remove` is the only effect that may use `DELETE`;
- its exact compiled endpoint must end literally in `/$ref`;
- `DELETE` with another effect, and `relationship_remove` with another method,
  fail closed;
- query strings, fragments, percent encoding, backslashes, dot segments,
  unsupported placeholders and Graph beta paths fail schema validation;
- every endpoint placeholder must bind to a UUID field or the compiler's exact
  safe path-segment pattern, so a substituted value cannot inject a slash,
  escape, traversal segment or suffix;
- a tool input cannot expose a Graph URL, endpoint, method, query, raw body,
  scope, API version, header or suffix;
- no generic DELETE or caller-selected request exists.

The active signed contract manifest remains schema `1.0`. Its current effects
are unambiguous and compiler-derived: `GET` is `read`, and `PATCH` is
`update_properties`. Schema `1.0` cannot safely infer a POST effect and rejects
one. A future reviewed schema `2.0` must include an explicit signed effect.
Secure Operations 0 supplies that closed schema but activates no v2 manifest,
endpoint, permission, tool or runtime handler.

The generated effect-model artifact has its own canonical digest and is bound
into compiler output, local provenance and the CycloneDX SBOM. It is not a
substitute for a future signed v2 contract manifest.

## First Identity Slice — implemented as inactive candidates

| Planned operation | Tier / authorization | Endpoint class | Fences and protected exclusions | Verification and compensation | Public privacy boundary |
|---|---|---|---|---|---|
| `entra.user.sessions.revoke` | T2 / `explicit_plan` | fixed user action | exact tenant/profile/user; cloud-managed Member; exclude protected, emergency and privileged identities | provider acceptance plus bounded observation; no compensation and no retry after ambiguity | status, plan/receipt digest and opaque target reference only |
| `entra.user.account_state.set` | T2 / `explicit_plan` | fixed user property transition | exact tenant/profile/user; exclude guest, synchronized, protected, emergency and privileged identities | desired-state readback; conditional inverse transition only after a new plan | changed field and opaque reference; no UPN or display name |
| `entra.group.user_membership.add` | T2 / `explicit_plan` | fixed relationship add | exact allowlisted user and group; reject dynamic, role-assignable, protected or unclassified groups | membership readback; inverse operation is a separate reviewed contract | status and opaque user/group references only |
| `entra.group.user_membership.remove` | T2 / `explicit_plan` | exact relationship removal ending `/$ref` | same immutable fences and exclusions as add | absence readback; inverse add requires a separate plan | status and opaque references only |
| `entra.user.direct_license.set` | T2 / `explicit_plan` | fixed desired-state license action | exact user and allowlisted SKU; direct assignment only; exclude inherited/group assignment | bounded post-read/observation; inverse desired state requires a separate plan | outcome, changed SKU reference and counts; no user identity or license content |

All five schema-2.0 contracts now compile as `candidate`/`preview`, with fixed
Graph v1.0 calls, Governance v3 bindings, closed providers, protected-object
checks, recorded playback and deterministic evaluations. They are not active
MCP tools and cannot execute Graph. The candidate PR may merge inactive.
Reviewed live-lab execution of all five operations must occur before an
independent production contract authority signs the final post-lab manifest
digest. Any correction invalidates the earlier digest. A separate small
activation PR performs the atomic cutover; no candidate registers as a tool
before that PR. Administrator consent remains manual.

## Operational playbook direction

The first effectful playbooks will be:

1. **Compromised-account containment** — observe bounded sign-in/identity
   evidence, plan, revoke sessions, optionally disable an eligible account,
   verify and issue a receipt.
2. **Bounded onboarding** — validate an existing identity, update bounded
   profile fields, assign an allowlisted direct license, add exact group
   memberships, create operational handoff tasks and verify every node.
3. **Preserve-data offboarding** — revoke sessions, disable the account,
   remove selected relationships and direct licenses, preserve workload data,
   record manual ownership-transfer tasks and verify.

Operator Foundation already supplies T2 exact plans, real dual control,
asynchronous result handling and resumable checkpoints. Operational Playbooks
v1 therefore begins after Identity Slice. Capabilities not yet implemented
remain explicit manual handoffs. Intune and Defender later enrich the same
workflows without displacing Evaluation and Release Readiness or Community
Adoption. An ambiguous write pauses the complete DAG. A signed playbook may
define only an explicitly reviewed safe continuation; it can never reinterpret
ambiguity as success.

Email, tickets, documents, incidents, Graph content and findings are untrusted
data. They may contribute evidence but cannot authorize a write. Posture may
produce a non-authorizing proposal candidate; only a compiled operational
contract, signed Governance and the required external authority can make an
operation executable.

## Canonical milestone order

1. **Contract Signing Lifecycle and Identity Slice:** lifecycle and candidate
   implementation complete; external authority custody/signing is the
   activation boundary.
2. **Operational Playbooks v1:** compromised-account containment, bounded
   onboarding and preserve-data offboarding, using manual handoffs for
   capabilities not yet implemented.
3. **Evaluation and Release Readiness:** consolidated recorded tests, lab
   execution, public Evaluation Suite, client compatibility and reproducible
   scorecard.
4. **Community Adoption Program:** validated quickstart, safe demo,
   contributor experience, first verifiable release, future `server.json`,
   MCP Registry submission and OpenSSF assessment.
5. **Endpoint/Intune.**
6. **Defender.**
7. **Conditional Access.**
8. **Reduced Posture Runtime:** evidence → deterministic finding →
   non-authorizing proposal → governed contract → approval → execution and
   verification.
9. **Progressive Legacy Catalog Migration.**

## Permanent prohibitions

The following are architectural restrictions, not backlog:

- arbitrary Graph proxying;
- a model-selected URL, method, body, query, header or scope;
- OAuth consent grants;
- directory-role or PIM assignment/activation;
- application secret or certificate creation;
- user, group, policy or other object deletion;
- routine device wipe;
- passwords, Temporary Access Pass values, recovery PINs or other secrets in
  LLM-visible output;
- Microsoft Graph beta;
- executable rules, Python, CEL, JMESPath or dynamic expression evaluation;
- remediation authorized directly by email, ticket, document, incident,
  finding or other untrusted content;
- inbound webhook authority over policy, contracts, approvals or execution;
- automatic permission widening;
- automatic retry after an uncertain write;
- findings that self-authorize remediation.
