# Identity Slice live-lab boundary

Identity live tests are writes. They run only in a dedicated, non-production
tenant with synthetic resources and isolated operator profiles. Customer
tenants, WERIXO production, everyday administration identities and real
emergency-access accounts are prohibited.

The five schema-2.0 Identity contracts remain inactive candidates. The `gate`
command neither authenticates nor calls Graph. The separate `run-core-case`
command is the reviewed runner: it can proceed only after the same gate,
authenticates one isolated operator and routes one closed scenario through the
candidate contract, Governance v3, external approval broker and
`ChangeSafeOperator`.

## Authentication boundary

The lab uses one single-tenant public-client/native App Registration:

- exact tenant authority `https://login.microsoftonline.com/{lab-tenant-id}`;
  `common`, `organizations` and tenant selection from tool input are forbidden;
- system-browser authorization code with PKCE is the primary flow;
- device code is an explicit, MFA-compatible fallback and requires
  `M365_ALLOW_DEVICE_CODE=true`;
- exact redirect URI `http://localhost`;
- no client secret and no confidential-client flow;
- ROPC/username-password is prohibited;
- each operator uses a distinct external OS-keychain cache namespace;
- tokens, cache files, credentials and identifiers never enter Git, fixtures,
  logs or public evidence.

The process must set:

- `M365_IDENTITY_LIVE_LAB=1`;
- `M365_LAB_PROFILE=live-lab`;
- `M365_LAB_OPERATOR_PROFILE` to exactly one profile below;
- `M365_IDENTITY_LIVE_LAB_WRITE_ACK=DEDICATED_NONPRODUCTION_IDENTITY_LAB`;
- matching `M365_LAB_TENANT_ID` and `M365_TENANT_ID`;
- matching `M365_CLIENT_ID`;
- `M365_TOKEN_CACHE_MODE=keyring`;
- `M365_PROFILE=write`, `M365_WRITE_ENABLED=true` and
  `M365_IDENTITY_OPERATIONS_ENABLED=true`;
- the profile-specific `M365_KEYRING_SERVICE`;
- owner-only Governance policy and public verification-key paths;
- the profile-specific owner-only operator approval trust registry and approval
  exchange directory (`M365_OPERATOR_APPROVAL_TRUST_PATH` and
  `M365_OPERATOR_APPROVAL_DIR`);
- an owner-only regular `0600` external inventory path.

The inventory path and all identifiers stay outside Git. The committed
[`identity-live-lab.inventory.template.json`](../examples/identity-live-lab.inventory.template.json)
contains placeholders and intentionally does not validate before external
substitution.

```bash
uv run m365-identity-live-lab requirements
uv run m365-identity-live-lab validate-inventory \
  --inventory /external-owner-only/identity-live-lab.json
uv run m365-identity-live-lab gate
```

Each effect case uses one externally chosen UUID idempotency key. The first
invocation performs protected-object preflight, freezes the immutable plan and
returns `AWAITING_APPROVAL`; it cannot write. An external approver signs the
owner-only request with the separate T2 authority. Repeating the exact command
with the same UUID consumes the approval once and executes or resumes:

```bash
uv run m365-identity-live-lab run-core-case \
  --scenario account.disable \
  --idempotency-key 00000000-0000-4000-8000-000000000000

uv run m365-operator-approval sign \
  --request /external-owner-only/approvals/<plan-id>.request.json \
  --trust-registry /external-owner-only/account-approval-trust.json \
  --authority-id <reviewed-authority-id> \
  --signer /secure-mounted/account-approval-signer.pem \
  --output /external-owner-only/approvals/<plan-id>.<authority-id>.approval.json \
  --expected-plan-digest sha256:<reviewed-plan-digest>

uv run m365-identity-live-lab run-core-case \
  --scenario account.disable \
  --idempotency-key 00000000-0000-4000-8000-000000000000
```

The example UUID and placeholders are not valid lab values. The signing CLI
prompts interactively for an encrypted PKCS#8 key passphrase, never accepts it
through arguments or environment, never generates an authority and never
prints private material.

`run-core-case` returns a private operator envelope. Before approval it
contains the opaque approval-request reference and reviewed plan digest but no
public evidence. A final successful or expected fail-closed invocation
contains a nested `evidence` object. Store each final envelope in an
owner-controlled result file; never commit the envelope itself.

Four Core checks never send a Graph write. Cross-tenant binding, missing
effect role, missing evidence role and profile isolation authenticate or
validate only the exact negative boundary and emit a sanitized blocked result.
The evidence-role case is run while the account test token intentionally lacks
Global Reader; restore the canonical account operator role closure before any
effect case. The `account.toctou_rejected` case requires changing the
synthetic account state after plan creation but before approved resumption.
The `session.uncertain_no_retry` case uses a closed lab-only backend that first
receives Graph acceptance and then deliberately removes local transport
certainty; durable state must become uncertain and a repeat must not issue a
second revoke.

## Isolated operator profiles

The App Registration retains only the aggregate delegated scopes fixed by the
five contracts. Effect authorization is separated by token subject, signed
Governance policy, approval authority and token-cache namespace:

| Profile | Directory roles | Closed effect surface |
|---|---|---|
| `session-operator` | Global Reader; Helpdesk Administrator | `entra.user.sessions.revoke` |
| `account-operator` | Global Reader; User Administrator | `entra.user.account_state.set` |
| `group-operator` | Global Reader; Groups Administrator | membership add and remove |
| `license-operator` | Global Reader; License Administrator | `entra.user.direct_license.set` |
| `negative-operator` | Global Reader only | none |

One person may perform more than one test profile, but every profile requires a
separate delegated token session and authority namespace. A plan binds the
tenant, profile, token subject, policy digest and intended operator. Its
single-use approval binds the same tenant/profile/subject and exact plan
digest. A token from another profile cannot reuse it.

The gate fails closed when the effect role or evidence role is missing. The
negative operator proves that delegated scopes alone cannot authorize an
effect. Its signed deny policy enables no Identity candidate and has no
approval authority.

## Permission categories

Administrator consent remains manual. The exact aggregate delegated closure is:

- `GroupMember.ReadWrite.All`
- `LicenseAssignment.Read.All`
- `LicenseAssignment.ReadWrite.All`
- `RoleManagement.Read.Directory`
- `User.EnableDisableAccount.All`
- `User.Read.All`
- `User.RevokeSessions.All`

The generated matrix keeps four categories distinct:

1. effect permissions;
2. preflight permissions;
3. readback permissions;
4. protected-object evidence permissions.

It also distinguishes Microsoft-supported least-privileged roles from the
project-required effect role and the project-required evidence role.
`RoleManagement.Read.Directory` is required for permanent role assignments and
also satisfies the active and eligible assignment-schedule reads. Those
schedule APIs document narrower scopes, but adding them would not reduce the
effective privilege while the permanent-assignment call remains required, so
the lab does not add them.

Groups Administrator remains the project requirement for this phase.
Microsoft also supports Group owner for some membership effects, but owner
mode is excluded until the token subject is cryptographically bound to
ownership of the exact group and that relationship is revalidated at TOCTOU.

## Core Identity Lab

Core is mandatory before production signing and `preview` activation. It
contains the safety evidence needed to prevent dangerous execution:

- all five operations;
- normal cloud-managed Member users in enabled and disabled states;
- static membership add/remove and already-satisfied no-ops;
- direct license assignment/removal, capacity, `usageLocation` and bounded
  service plans;
- five isolated operator profiles, including the negative operator;
- TOCTOU rejection;
- accepted, verified and uncertain classifications;
- administrator, synthetic break-glass and protected-object rejection with
  complete role evidence;
- tenant and allowlist isolation;
- no automatic retry after uncertainty.

Core external inventory requires:

- enabled and disabled cloud-managed users;
- direct-license user, Guest, administrator, synthetic break-glass fixture,
  user without `usageLocation`, and a user outside allowlists;
- allowed static group, protected static group, group outside allowlists, and
  an independent marker group;
- one existing and one absent membership relationship;
- allowed SKU with capacity, a disallowed SKU, and allowed/disallowed service
  plans.

The synthetic break-glass fixture is an ordinary lab identity classified as
protected by Governance. It is never a real emergency-access account.

## Extended Identity Lab

Extended is mandatory before any operation may move from `preview` to
`stable`. It covers infrastructure-dependent cases:

- a genuinely synchronized user;
- active and eligible PIM assignments;
- dynamic and role-assignable groups;
- group-based licensing;
- advanced replication and concurrency behavior.

If an Extended fixture is unavailable, its evidence state is
`not_executed`—never passed. Deterministic and sanitized recorded tests retain
coverage, and maturity remains `preview`. Extended absence cannot weaken Core
protected-object checks.

## Evidence and maturity

Public evidence schema 2.0 requires every Core and Extended scenario exactly
once. It retains only scenario, lab level, synthetic resource class, operation,
expected/observed status, duration bucket, classification, sanitized error,
contract digest and `passed`/`failed`/`not_executed` execution state.

```bash
uv run m365-identity-live-lab assemble-evidence \
  --result /external-owner-only/results/account.disable.final.json \
  --result /external-owner-only/results/<each-other-core-final>.json \
  --output /external-owner-only/sanitized-live-lab.evidence

uv run m365-identity-live-lab scan-evidence \
  --evidence /external-owner-only/sanitized-live-lab.evidence
```

Assembly rejects missing, duplicated, failed, approval-pending or
contract-mismatched Core results and inserts every unavailable Extended case
as `not_executed`. The compiler recognizes only the canonical sanitized
evidence file at
`contract-candidates/identity-live-lab-evidence.json`; it binds that file's
digest into provenance, SBOM metadata and the signing request. The signing
request can become eligible only when all closed Core cases passed. The
scanner rejects tenant/object/device/subscription/request IDs, UPNs, email
addresses, IP addresses, tokens, key material, changed scenario semantics and
unknown fields.

## Activation sequence

1. Merge the inactive candidate and lab-boundary PR.
2. Provision the Core Identity Lab externally.
3. Execute all five operations with isolated operator profiles.
4. Correct any divergence while contracts remain candidates.
5. Regenerate recordings, matrices, artifacts and candidate digest.
6. Freeze the final reviewed candidate.
7. Perform the external contract-signing ceremony.
8. Deliver a small activation PR with initial maturity `preview`.
9. Begin Operational Playbooks v1.
10. Complete Extended Lab before any promotion to `stable`.

Any lab correction invalidates the previous digest. No Identity candidate is
registered as a production MCP tool before the separate activation PR.
