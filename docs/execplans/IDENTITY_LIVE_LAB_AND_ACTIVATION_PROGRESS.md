# Identity Live-Lab and Activation progress

This is the durable resume point for
[the ExecPlan](IDENTITY_LIVE_LAB_AND_ACTIVATION.md).

## Baseline

- PR #6 merge commit:
  `9b7489ad67b637065bd38b47deeeef771a379b33`.
- protected-main CI run `30363478703`: green.
- PR #5 merge commit:
  `4af1f0ce607361925cfe511eb31392afe7c0de52`.
- protected-main CI run `30358999180`: green.
- merged PR #5 candidate digest:
  `sha256:ffb663385285dc44d0756e87e9cc1e4ed72b129637fe6d02337c2244aa540399`.
- current inactive candidate digest:
  `sha256:788bb37c79af5363056d7e8ef661087098c64fb1073b05dfa0cdb177a7e16e65`.
  Earlier unsigned candidate digests are explicitly invalidated. The current
  candidate adds an exact UUID idempotency key to every input schema and makes
  its minimized runtime output fields explicit, so approval pause/resume,
  restart recovery and public projection cannot rely on implicit semantics.
  No scope or endpoint changed.
- active historical contract manifest:
  `sha256:1a33a244371405402df75a125fe6c18a9d6d0af0d2b692f5a831cde82248f5ba`.
- Effect Model:
  `sha256:ab249d54df004a70d5333c39d6894880d67985000b52ad847ddf043a2a7aba60`.

## Progress

- [x] PR #5 merged with all five candidates inactive.
- [x] Local and remote feature branches for PR #5 removed.
- [x] Protected main updated, clean and green.
- [x] New live-lab branch created.
- [x] External owner-only inventory schema and placeholder template.
- [x] Explicit process gate with tenant/client/profile/digest binding.
- [x] Complete users/groups/licenses/relationships fixture topology.
- [x] Tenant-neutral requirements command.
- [x] Effect-role and protected-evidence-role metadata separated and compiled.
- [x] Governance v3 signature, exact resource fences and approval-key
  fingerprint verified by the offline gate rather than inferred from paths.
- [x] Minimized public evidence schema and deterministic privacy scanner.
- [x] Unit and adversarial tests for the offline lab boundary.
- [x] Five isolated operator profiles with separate subject, Governance,
  approval and OS-keychain namespaces.
- [x] Single-tenant public-client authentication contract: browser PKCE
  primary, explicit device-code fallback, no secret and no ROPC.
- [x] Core/Extended inventory, evidence and maturity gates.
- [x] PR #6 merged; local and remote implementation branches removed.
- [x] Protected `main` updated, clean and green.
- [x] Identity Activation Program branch created from exact protected `main`.
- [x] Availability probe completed without reading secret values or
  authenticating: no lab environment, inventory, Azure CLI, repository-local
  private material, contract signer or usable browser session is mounted.
- [x] Dormant runtime wiring resolves only a current production-signed active
  schema-2.0 manifest and signed Governance v3; candidates remain impossible
  to register.
- [x] Five exact MCP facades contain no operation, URL, method, query, body,
  scope, header, API-version or tenant selector.
- [x] External T2 approval request/broker/CLI with pinned authorities,
  single-use replay ledger and owner-only private exchange.
- [x] Durable Identity execution, observation, private receipt/change record
  and no duplicate execution after restart.
- [x] Core live runner covers effect, no-op, negative, TOCTOU and closed
  uncertainty cases without a generic Graph control.
- [x] Evidence assembler requires every final Core result, inserts Extended
  `not_executed` states and content-binds sanitized evidence before signing
  eligibility.
- [ ] Dedicated non-production tenant exists and is explicitly allowlisted.
- [ ] Five external operator token sessions and profile-specific Governance
  material mounted.
- [ ] Mandatory Core operation and negative scenario sets executed.
- [ ] Sanitized live evidence reviewed and regressions passed.
- [ ] Final candidate digest frozen and marked signing eligible.
- [ ] External production signing ceremony.
- [ ] Separate activation PR.
- [ ] Extended Lab executed before any operation is promoted to `stable`.

## Environment discovery

On 2026-07-28, the current process contained none of the dedicated live-lab
environment variable names. The lab opt-in is disabled; no external inventory,
repository-local private directory, Azure CLI session, contract signer
configuration or usable browser session is available. No secret path or value
was inspected. No authentication was attempted and no Graph call or tenant
write occurred.

This is one consolidated external boundary. The current candidate cannot be
made signing-eligible by synthetic or recorded evidence, and a production
contract authority cannot be improvised. No internal implementation change can
safely replace those facts.

## Pushed implementation checkpoint

The program branch `feat/identity-activation-program` contains:

- `5678f68` — dormant signed-manifest runtime, exact tools, external approval
  boundary, durable execution, closed live runner and evidence signing gate;
- `c106c73` — reproducible lab, signing and external-boundary documentation.

The branch is intentionally not a pull request yet: the program requires one
final activation PR, and opening a preparatory PR would create a second review
boundary before the mandatory live evidence and external signature exist.

## Validation checkpoint

- 479 tests collected: 478 passed and the explicit live-lab network boundary
  skipped because the opt-in and external resources are absent.
- compiler check, Ruff, strict mypy, dependency audit and package build pass.
- active contract, Effect Model, playbook, control and compatibility artifacts
  remain unchanged.
- candidate manifest:
  `sha256:788bb37c79af5363056d7e8ef661087098c64fb1073b05dfa0cdb177a7e16e65`.
- candidate registry:
  `sha256:fdb1badcaed9211e20191cf10485e18e1308f61863c536d2c40a4e5e2c88f9b1`.
- candidate Graph-surface diff:
  `sha256:446173fc3076be21bda1e56e10f08a5676bacfbc1d8a26d3cfafde47be04a4d7`.
- candidate provenance:
  `sha256:fe41fe8f755608a1d1ad8c2f5609bcb884c2bbb08134ac31a82851705ff23302`.
- candidate SBOM binding:
  `sha256:15ff24cc447efc21d51ee19ea73e7362e010b7ce4ab4b407dc89a361ac3bc3e3`.
- candidate signing request remains ineligible and now records
  `awaiting_reviewed_core_identity_lab`; the candidate manifest digest and all
  artifact semantic digests above remain unchanged.

## Exact resume action

Mount the complete external input bundle listed in
[`IDENTITY_LIVE_LAB.md`](../IDENTITY_LIVE_LAB.md). Render the committed
schema-2.0 placeholder inventory outside Git, set it to owner-only `0600`,
create one process environment per isolated operator profile, and run for each:

```bash
uv run m365-identity-live-lab validate-inventory \
  --inventory /external-owner-only/identity-live-lab.json
uv run m365-identity-live-lab gate
```

Only after both succeed for all five profiles may the reviewed live runner
authenticate and begin the Core sequence. Do not sign the current candidate
digest. Extended cases may remain `not_executed`, but no operation can become
`stable` until they are reviewed.

For each Core scenario run `m365-identity-live-lab run-core-case`, obtain the
external exact-plan signature when the first result is `AWAITING_APPROVAL`,
and resume with the same UUID. Assemble all final results with
`m365-identity-live-lab assemble-evidence`, review and place only its sanitized
output at `contract-candidates/identity-live-lab-evidence.json`. After Core
passes, regenerate with `uv run m365-compile-contracts`, rerun the full
validation suite, review the now content-bound signing request, and follow
[`CONTRACT_SIGNING_RUNBOOK.md`](../CONTRACT_SIGNING_RUNBOOK.md) against only
the frozen final digest. Activation then occurs in the same program branch as
one small reviewed change and one final pull request.
