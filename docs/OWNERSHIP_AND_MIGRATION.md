# Ownership and migration from a third-party Graph MCP

## Recommended ownership model

Keep the reusable server code reviewable and keep the deployment private:

```text
public or internally mirrored core
        |
        +-- pinned commit / reviewed release
        |
        +-- private Entra app registrations
        +-- private owner-only policy files
        +-- OS Keychain token caches
        +-- private audit and write-receipt stores
```

This removes runtime dependence on an upstream MCP author without putting
tenant IDs, user IDs, resource IDs, consent decisions, or operational policy
in Git. An organization that does not want a public dependency can mirror the
repository into a private Git host and update only after reviewing the diff,
lock file, tests, and dependency audit.

Do not place a private policy in the code repository, even when the repository
is private. Repository readers and CI do not need tenant access configuration.

## Why not replace Lokka in one step

Lokka's generic Graph request is broad enough to cover endpoints that this
server intentionally does not expose. Removing it before real workflows are
mapped can create an operational gap; keeping it permanently as an always-on
agent tool preserves unnecessary supply-chain and privilege risk.

Use a staged transition:

1. Inventory the Graph operations actually used, including method, endpoint,
   fields, permissions, frequency, reversibility, and human owner.
2. Map each operation to an existing fixed tool.
3. Add missing operations as narrow typed contracts with exact permissions and
   postconditions; never add a generic URL/method/body proxy.
4. Run both systems in a non-production tenant or read-only comparison window.
5. Disable Lokka from routine agent profiles after parity is evidenced.
6. Retain any remaining generic administrator access only as a disabled,
   human-invoked break-glass profile with a pinned version and separate Entra
   registration.
7. Remove the fallback after an agreed observation period shows no unresolved
   workflows.

## Current replacement coverage

| Workload | Read | Write | Boundary |
|---|---:|---:|---|
| Mail, calendar, contacts, To Do | yes | selected frozen legacy effects | principal and recipient domains |
| OneDrive, SharePoint, Office, OneNote | metadata/selected content | bounded Word/PPT/Excel/OneNote edits | drive/item/page allowlists and ETags |
| Planner | yes | create, basic update, details/checklist update | plan and assignee allowlists |
| Teams and groups | yes | messages, group metadata/member add | team/chat/group/user allowlists |
| Entra users and devices | yes | bounded profile/account state | privileged gate and target allowlists |
| Defender, audit, Intune, Windows 365, Service Health | yes | device sync, Cloud PC reboot | privileged gate and device allowlists |
| Power BI | workspace/content inventory | dataset refresh, report rebind | separate OAuth audience and resource allowlists |
| Entra apps and service principals | yes | bounded metadata/control update | privileged gate and object allowlists |
| Conditional Access | yes | state/name update | privileged gate and policy allowlist |
| Directory roles, access reviews, entitlement | yes | no | privileged module and exact tool |
| Licenses and domains | yes | no | privileged module and exact tool |
| Purview eDiscovery and retention labels | allowlisted metadata/definitions | no | privileged module, Purview RBAC and separate UUID allowlists |

Credential rotation, permission-grant mutation, role assignment, license
assignment, Exchange Online PowerShell, and destructive operations are not
agent tools. They remain deliberate gaps until each workflow has a safer
contract, reversible design, evidence check, and approval boundary.

The [official implementation roadmap](ROADMAP.md) defines the migration order
for those fixed contracts and governed playbooks. Endpoint count alone is not a
replacement criterion; operational parity requires policy, verification,
evidence and a documented safe recovery path.

## Four deployment profiles

Use separate Entra registrations and policy files when the capabilities are
needed:

| Profile | Typical scope | Normal availability |
|---|---|---|
| Routine read | user productivity data | enabled |
| Routine write | selected Planner/calendar/mail actions | enabled with prompt |
| Privileged read | Entra/security/Intune/governance inventory | disabled until needed |
| Privileged write | one administrative update action | disabled until an approved change window |

The server derives Graph scopes from the exact effective tools/actions. The
Entra app should be granted only those reported by:

```bash
m365-secure-mcp --policy-file "/private/policy.json" --explain-permissions
```

## Private deployment workflow

1. Configure one profile through environment variables.
2. Run `--doctor`, `--explain-permissions`, and `--list-tools`.
3. Use operator-only `--discover-resources` to find candidate identifiers.
4. Select resources deliberately and configure their allowlists.
5. Export the final configuration to a new owner-only policy file.
6. Point Codex or Claude Code at the policy path, not at inline identifiers.
7. Permit prompt-free calls only for exact compiled T1 tools under a signed
   `standing_policy`; require host approval for higher-risk or legacy writes.
8. Record the reviewed source commit and update it only through a controlled
   dependency review.

For MSP use, repeat these profiles per customer tenant. Tenant IDs are process
configuration, never tool inputs; see
[MSP multi-tenant deployment](MSP_MULTI_TENANT.md).

Discovery never edits a policy or makes a resource available to the model. A
resource becomes reachable only after the operator explicitly places its ID in
the private policy and restarts the corresponding process.

## Acceptance gate before removing a fallback MCP

- all required workflows have a fixed tool or a documented human-only path;
- each tool's Graph permission is explained and consented;
- every tenant-wide resource is allowlisted where technically possible;
- routine read, routine write, privileged read, and privileged write use
  separate processes or registrations;
- writes have idempotency, rate limiting, postcondition evidence, and an
  authorization floor appropriate to their tier;
- timeout/ambiguous-write recovery has been rehearsed;
- tests, lint, strict typecheck, dependency audit, and package build pass from
  the locked dependency graph;
- no tenant identifiers or tokens appear in the repository, CI, issues, or
  generated documentation.
