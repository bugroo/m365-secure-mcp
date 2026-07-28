# Identity Live-Lab and Activation progress

This is the durable resume point for
[the ExecPlan](IDENTITY_LIVE_LAB_AND_ACTIVATION.md).

## Baseline

- PR #5 merge commit:
  `4af1f0ce607361925cfe511eb31392afe7c0de52`.
- protected-main CI run `30358999180`: green.
- merged PR #5 candidate digest:
  `sha256:ffb663385285dc44d0756e87e9cc1e4ed72b129637fe6d02337c2244aa540399`.
- current inactive candidate digest:
  `sha256:2c084bc85d7cb0fd13d042e503f0465aa21308b4fda40dcf99a48a95330f2ab7`.
  The earlier digest is explicitly invalidated: the candidate now separates
  the effect role from the `Global Reader` role required by the fixed
  protected-object evidence calls. No scope or endpoint changed.
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
- [ ] Dedicated non-production tenant exists and is explicitly allowlisted.
- [ ] External inventory, Governance v3 policy and approval verifier mounted.
- [ ] All five positive and negative live-lab operation sets executed.
- [ ] Sanitized live evidence reviewed and regressions passed.
- [ ] Final candidate digest frozen and marked signing eligible.
- [ ] External production signing ceremony.
- [ ] Separate activation PR.

## Environment discovery

On 2026-07-28, the current process contained none of the dedicated live-lab
environment variable names. No secret path or value was inspected. No
authentication was attempted and no Graph call or tenant write occurred.

## Validation checkpoint

- 454 tests collected: 453 passed and the explicit live-lab network boundary
  skipped because the opt-in is absent.
- compiler check, Ruff, strict mypy, dependency audit and package build pass.
- active contract, Effect Model, playbook, control and compatibility artifacts
  remain unchanged.
- candidate manifest:
  `sha256:2c084bc85d7cb0fd13d042e503f0465aa21308b4fda40dcf99a48a95330f2ab7`.
- candidate registry:
  `sha256:e9456beeaef0c4da6d577eb53f4f65efbfc02144f21c1797326e4b842d11650a`.
- candidate Graph-surface diff:
  `sha256:07dc7a08236fce2f19e22e9c9dd282cacc56a16a22d30558906938554a93d634`.
- candidate provenance:
  `sha256:b27d5a394b9b60242f157b508368cd6cac9ac5420efe42c16252739eb15707a4`.
- candidate SBOM binding:
  `sha256:a18afae05e5c10941ec47e052ff0e617a2f6691000b1662bf60c5caf8b3ded07`.

## Exact resume action

Provision the dedicated tenant and external material listed in
[`IDENTITY_LIVE_LAB.md`](../IDENTITY_LIVE_LAB.md). Render the committed
placeholder inventory outside Git, set it to owner-only `0600`, then run:

```bash
uv run m365-identity-live-lab validate-inventory \
  --inventory /external-owner-only/identity-live-lab.json
uv run m365-identity-live-lab gate
```

Only after both succeed may the reviewed live runner authenticate and begin
the five-operation test sequence. Do not sign the current candidate digest.
