# Configuration reference

Runtime configuration can come from `M365_`-prefixed environment variables or
one owner-only JSON policy passed with `--policy-file`. The server does not
read `.env` files itself.

Create a private policy once:

```bash
m365-secure-mcp --export-policy "/private/m365/read-policy.json"
m365-secure-mcp --policy-file "/private/m365/read-policy.json" --doctor
```

Export refuses to overwrite an existing path. Loading requires a regular,
current-user-owned mode-`0600` file in a current-user-owned mode-`0700`
directory; symlinks, extra keys, and files larger than 256 KiB fail closed.
The document contains tenant/resource identifiers but never tokens or a client
secret.

## Identity

| Variable | Required | Meaning |
|---|---:|---|
| `M365_TENANT_ID` | yes | Single Microsoft Entra tenant UUID |
| `M365_CLIENT_ID` | yes | Public desktop application UUID |
| `M365_DEPLOYMENT_KIND` | no | `host` (default) or `customer`; customer requires an exact principal |
| `M365_ALLOWED_USER_OBJECT_IDS` | customer: yes | Comma-separated signed-in operator UUIDs |
| `M365_ALLOWED_TARGET_USER_IDS` | by tool | Separate users the MCP may read or edit |
| `M365_ALLOWED_PLANNER_ASSIGNEE_IDS` | by assignment | Separate users Planner tasks may be assigned to; never grants MCP sign-in |
| `M365_ALLOWED_UPN_DOMAINS` | recommended | Lowercase DNS domains accepted for the principal |
| `M365_AUTH_FLOW` | no | `interactive` (default) or `device_code` |
| `M365_ALLOW_DEVICE_CODE` | no | Must be `true` before device code can start |
| `M365_TOKEN_CACHE_MODE` | no | `keyring` (default) or explicitly ephemeral `memory` |
| `M365_PERMISSION_GRANT_MODE` | fixed | Only `admin_preconsented` is accepted |
| `M365_REJECT_UNEXPECTED_TOKEN_SCOPES` | no | Reject token scope drift; default `true` |

The administrator must add and consent every delegated permission before the
profile runs. The server requests each API's preconsented `/.default` set,
checks the returned token against the compiled policy, and has no permission
grant or dynamic-consent path. No value should contain an `api://` audience or
a client secret.

## Signed Governance policy

The global manifest is public, tenant-neutral and signed at build time. The
Governance policy is separate, tenant-private and signed by its administrator.
It defines all five standard profiles:

```text
routine-read
routine-write
privileged-read
selected-write
break-glass
```

It also binds one tenant, enabled contract and playbook IDs, user/group
allowlists, protected users, optional UTC write windows, authorization
overrides and optional Assurance baselines. `contract_manifest_digest` is
always required. `playbook_manifest_digest` is required whenever any profile
enables a playbook. An override can only increase the authorization floor.
Unknown contracts/playbooks, a playbook whose child contracts are not enabled
in the same profile, read-profile writes, T2+ contracts in `routine-write`,
expired policies, invalid signatures, changed digests and cross-tenant use
fail closed.

The MCP runtime can verify this policy but cannot create, edit, activate or
sign it. `m365-governance` is an explicit local operator CLI; it never calls
Graph and never requests Entra consent.

`permission_grant_baseline` is also tenant-private and signed. It maps exact,
allowlisted service principals to exact compiled contract IDs and optional
expiring permission exceptions. Runtime derives expected delegated scopes from
those contracts; it cannot add arbitrary expected scopes or alter Entra grants.

`application_credential_baseline` binds exact application object IDs to
administrator-approved ownership, expiry, password-secret and active-credential
limits. Its targets must also exist under `resources.applications` and in
`M365_ALLOWED_APPLICATION_IDS`. Credential exceptions require an exact
credential kind/key ID; application-level controls use separate exceptions.
All exceptions are signed, justified and expiring. Runtime cannot promote a
baseline, rotate credentials, assign owners or grant consent.

`profile_debt_baseline` governs the read-only comparison of an active profile
with token scopes, current-app grant posture, contract-use evidence, policy
lifecycle and resource fences. It signs severity for every supported control,
the minimum policy version, maximum review age, evidence window, persistent
failure threshold and exact expiring exceptions. `policy_version` is signed
tenant material. Runtime cannot increment it, change severity, add an
exception, edit an allowlist or remediate a finding.

The current
`entra.workload_identity.readiness.playbook` is valid only in
`privileged-read`. Its profile must enable both
`entra.permission_grants.drift.snapshot` and
`entra.app_credentials.posture.snapshot`, and must include:

```json
{
  "playbook_manifest_digest": "sha256:<from playbook-digests.json>",
  "profiles": {
    "privileged-read": {
      "enabled_contracts": [
        "entra.app_credentials.posture.snapshot",
        "entra.permission_grants.drift.snapshot"
      ],
      "enabled_playbooks": [
        "entra.workload_identity.readiness.playbook"
      ]
    }
  }
}
```

The complete profile still needs its other required fields, both private
baselines, and application/service-principal resource fences. Copy the
tenant-neutral template instead of using this excerpt as a full policy.
Governance must sign a new policy version after any selection, fence, baseline
or digest changes.

## External exact-plan approval

`standing_policy` is the default for the compiled T1 operational-profile
contract and requires no per-call dialog. These settings are needed only when
signed Governance tightens that contract to `explicit_plan`:

| Variable | Required together | Meaning |
|---|---:|---|
| `M365_APPROVAL_BROKER_DIR` | yes | Owner-only exchange directory for private plan requests, signed approvals and the replay ledger |
| `M365_APPROVAL_PUBLIC_KEY_PATH` | yes | Owner-only Ed25519 verifier for the external host/broker authority |

The pair is valid only in a write process. A partial pair or use in a read
process stops startup. The approval signing key is not runtime configuration
and must remain separate from the Governance signer.

For an `explicit_plan` operation, runtime writes
`<plan-id>.request.json` under the configured directory. The file binds tenant,
deployment/profile, signed-in operator, contract and policy digests, normalized
parameter digest, target fingerprint, precondition digest, changed field names,
Permission Impact Preview and expiry. It contains neither previous nor
requested Microsoft 365 values.

`m365-approval` is an external operator CLI. It never calls Graph, grants
consent, changes policy or exposes an MCP tool:

```bash
m365-approval generate-key \
  --signer "/private/m365/approval-signing.pem" \
  --verifier "/private/m365/approval-signing.pub"

m365-approval sign \
  --request "/private/m365/approvals/<plan-id>.request.json" \
  --signer "/private/m365/approval-signing.pem" \
  --output "/private/m365/approvals/<plan-id>.approval.json" \
  --key-id "approved-host-authority" \
  --expected-plan-digest "sha256:<reviewed-plan-digest>"
```

Runtime accepts only an unexpired Ed25519 signature over the exact current
plan, consumes the approval once in a tenant/profile-bound SQLite ledger, and
burns it after all TOCTOU checks but before PATCH. A stale, changed, replayed or
cross-deployment artifact fails closed. Approval is never a model-controlled
parameter.

## Surface selection

| Variable | Default | Meaning |
|---|---|---|
| `M365_PROFILE` | `read` | Separate `read` or `write` process |
| `M365_MODULES` | `profile` | Comma-separated read modules |
| `M365_ENABLED_TOOLS` | blank | Exact allowlist within the active profile |
| `M365_DISABLED_TOOLS` | blank | Exact removals within the active profile |
| `M365_PRIVILEGED_MODULES_ENABLED` | `false` | Second gate for tenant-wide/admin modules |
| `M365_PRIVILEGED_WRITES_ENABLED` | `false` | Additional gate for administrative write actions |

Available modules:

```text
profile,mail,calendar,files,sites,contacts,todo,planner,teams,
directory,users_admin,groups,directory_devices,organization,onenote,
onenote_content,excel,excel_workbook,word,powerpoint,powerbi,
people,presence,security,audit,intune,windows365,service_health,
entra_apps,governance,assurance,licensing,compliance
```

Tool filters accept explicit `m365_*` names only. Unknown, conflicting, or
out-of-profile names stop startup.

The `assurance` module is a privileged read module. It requires a signed
Governance policy and external public key even though the Graph operation is
T0 `automatic_read`; that signature authorizes the tenant/profile and any
baseline or exception once, without a prompt on each snapshot.

Workload Identity Readiness additionally requires both
`M365_ALLOWED_APPLICATION_IDS` and
`M365_ALLOWED_SERVICE_PRINCIPAL_IDS`. Each target must also be present in the
corresponding signed baseline and `resources` fence. Runtime does not infer,
discover or add the missing relationship.

## Resource boundaries

| Variable | Used by |
|---|---|
| `M365_ALLOWED_SITE_IDS` | SharePoint |
| `M365_ALLOWED_SHAREPOINT_HOSTS` | SharePoint defense in depth |
| `M365_ALLOWED_TEAM_IDS` | Teams and channel operations |
| `M365_ALLOWED_CHAT_IDS` | Teams chat content |
| `M365_ALLOWED_GROUP_IDS` | Group metadata and membership |
| `M365_ALLOWED_DEVICE_IDS` | Entra directory devices |
| `M365_ALLOWED_MANAGED_DEVICE_IDS` | Intune device actions |
| `M365_ALLOWED_CLOUDPC_IDS` | Windows 365 reads/actions |
| `M365_ALLOWED_PLAN_IDS` | Planner reads/writes |
| `M365_ALLOWED_PLANNER_ASSIGNEE_IDS` | Planner task assignees, separate from operators |
| `M365_ALLOWED_DRIVE_IDS` | Office document libraries/drives |
| `M365_ALLOWED_WORD_ITEM_IDS` | Word reads/writes |
| `M365_ALLOWED_POWERPOINT_ITEM_IDS` | PowerPoint reads/writes |
| `M365_ALLOWED_EXCEL_ITEM_IDS` | Excel range reads/writes |
| `M365_ALLOWED_ONENOTE_PAGE_IDS` | OneNote content reads/writes |
| `M365_ALLOWED_POWERBI_WORKSPACE_IDS` | Power BI workspace boundary |
| `M365_ALLOWED_POWERBI_REPORT_IDS` | Power BI report boundary |
| `M365_ALLOWED_POWERBI_DATASET_IDS` | Power BI dataset boundary |
| `M365_ALLOWED_POWERBI_DASHBOARD_IDS` | Power BI dashboard boundary |
| `M365_ALLOWED_APPLICATION_IDS` | Entra application registration reads/writes and signed credential-posture targets |
| `M365_ALLOWED_SERVICE_PRINCIPAL_IDS` | Entra enterprise application reads/writes and signed permission-drift targets |
| `M365_ALLOWED_CONDITIONAL_ACCESS_POLICY_IDS` | Conditional Access writes |
| `M365_ALLOWED_EDISCOVERY_CASE_IDS` | Purview eDiscovery case metadata |
| `M365_ALLOWED_RETENTION_LABEL_IDS` | Purview retention-label definitions |
| `M365_ALLOWED_RECIPIENT_DOMAINS` | mail/calendar recipients and free/busy |

Sites, Teams, groups, Planner, and selected Entra application tools refuse
startup without their corresponding allowlist. Chat tools return or accept
only allowlisted chat IDs. Entra and Conditional Access identifiers are
validated UUIDs at startup. Purview eDiscovery cases and retention labels are
separate UUID allowlists and remain read-only in the MCP.

## Writes

| Variable | Default | Meaning |
|---|---|---|
| `M365_WRITE_ENABLED` | `false` | Independent write-profile gate |
| `M365_WRITE_ACTIONS` | blank | Exact action allowlist |
| `M365_WRITE_RATE_LIMIT_PER_MINUTE` | `10` | Per-tool local rate limit |
| `M365_IDEMPOTENCY_PENDING_SECONDS` | `86400` | Age at which an orphaned pending reservation is classified as uncertain; neither state auto-retries |
| `M365_IDEMPOTENCY_DB_PATH` | platform path | Optional ledger override |
| `M365_GOVERNANCE_POLICY_PATH` | by compiled write | Owner-only signed tenant Governance policy |
| `M365_GOVERNANCE_PUBLIC_KEY_PATH` | by compiled write | External owner-only Ed25519 trust anchor |
| `M365_RECOVERY_CAPSULE_PATH` | platform path | Encrypted tenant-local compensation capsule |
| `M365_RECOVERY_CAPSULE_TTL_SECONDS` | `604800` | Recovery-capsule retention metadata |

Known write actions:

```text
mail.create_draft
mail.send_draft
calendar.create_event
calendar.update_event
contacts.create
todo.create_task
todo.update_task
teams.send_channel_message
teams.send_chat_message
planner.create_task
planner.update_task
planner.update_task_details
entra.user.operational_profile.update
users.set_account_enabled
groups.update
groups.add_user_member
intune.sync_device
windows365.reboot_cloudpc
word.replace_text
powerpoint.replace_text
excel.update_range
onenote.append_page_text
powerbi.refresh_dataset
powerbi.rebind_report
entra.update_application
entra.update_service_principal
governance.update_conditional_access_policy
```

`planner.update_task_details` uses the same least-privileged delegated
`Tasks.ReadWrite` scope as the other Planner writes. It is a separate local
action so an operator can allow basic task updates without allowing description
or checklist changes, or vice versa.

`entra.user.operational_profile.update` is the first compiled T1 Governance
contract. It uses `standing_policy` by default, so an already signed
`routine-write` policy can authorize routine calls without a per-operation
dialog. A tenant policy may only harden that floor to `explicit_plan`,
`dual_control`, `break_glass_only`, or `prohibited`. The signed policy and
external public key are mandatory at startup.

Administrative actions other than the bounded T1 operational-profile contract
also require `M365_PRIVILEGED_WRITES_ENABLED=true`. They expose only closed
update contracts:

- application: `displayName`, `groupMembershipClaims`;
- service principal: `displayName`, `accountEnabled`,
  `appRoleAssignmentRequired`;
- Conditional Access: `displayName`, `state`;
- T1 user operational profile: `jobTitle`, `department`, `officeLocation`,
  only for one allowlisted, cloud-managed, non-privileged Member user;
- user state: `accountEnabled`, under its own permission/action;
- group: `displayName`, `description`, or add one allowlisted user, but only
  after Graph explicitly confirms the group is not role-assignable;
- Intune: sync one allowlisted managed device;
- Windows 365: reboot one allowlisted Cloud PC;
- Office: exact-run replacement in macro-free DOCX/PPTX, literal Excel values,
  or escaped OneNote append;
- Power BI: refresh an allowlisted dataset or rebind an allowlisted report to
  an allowlisted dataset.

Secrets, certificates, owners, redirect URIs, permission grants, app roles,
policy conditions/controls, role assignments, license assignments, and all
delete operations remain outside the tool surface.

## Bounds and audit

| Variable | Default |
|---|---:|
| `M365_GRAPH_TIMEOUT_SECONDS` | `20` |
| `M365_GRAPH_MAX_RETRIES` | `3` |
| `M365_MAX_ITEMS` | `50` |
| `M365_MAX_RESPONSE_BYTES` | `2000000` |
| `M365_MAX_TOOL_CHARACTERS` | `24000` |
| `M365_MAX_OFFICE_FILE_BYTES` | `8000000` |
| `M365_MAX_OOXML_MEMBERS` | `3000` |
| `M365_MAX_OOXML_EXPANDED_BYTES` | `64000000` |
| `M365_ASSURANCE_SNAPSHOT_PATH` | tenant/profile-specific platform path |
| `M365_ASSURANCE_MAX_PAGES_PER_DOMAIN` | `100` |
| `M365_ASSURANCE_MAX_RECORDS_PER_DOMAIN` | `5000` |
| `M365_ASSURANCE_MAX_SNAPSHOT_BYTES` | `64000000` |
| `M365_ASSURANCE_SNAPSHOT_TTL_SECONDS` | `2592000` |
| `M365_AUDIT_LOG_PATH` | platform log directory |

Audit records contain tool/outcome metadata and keyed parameter fingerprints,
not raw Microsoft 365 content. Each event also includes the public operation ID
and elapsed time so attempts can be correlated with structured MCP results and
write receipts.

Assurance bounds apply independently to each fixed collection in the selected
workflow. The Identity Governance posture contract reads four domains. The
permission-grant drift contract reads only signed, locally allowlisted service
principals and their delegated grants, app-role assignments and resource
catalogs. Any overflow, pagination loop, malformed page, target mismatch or
unknown app-role mapping fails the complete operation.

The normalized snapshot is encrypted before being appended to an owner-only
local file; the MCP exposes only opaque references and tenant-local HMAC
digests. Permission-grant drift additionally requires
`M365_ALLOWED_SERVICE_PRINCIPAL_IDS`, the same IDs under signed
`resources.service_principals`, and a signed `permission_grant_baseline`.
Runtime has no consent, revocation, baseline-promotion or snapshot-read tool.

Profile debt requires the current App Registration's service-principal object
ID in the same local and signed fences, a signed
`permission_grant_baseline`, a signed `profile_debt_baseline`, and both
`entra.permission_grants.drift.snapshot` and
`entra.profile_debt.posture.snapshot` in the active `privileged-read` profile.
It reads only the configured owner-only audit path, bounded to 16 MB and
100,000 records. Missing, malformed, oversized or unsafe audit evidence is
reported as `not_evaluated`; no filesystem search is attempted. Findings
propose an operator/admin/Governance action but never alter grants, consent,
policies or runtime allowlists.

Application credential posture requires `M365_ALLOWED_APPLICATION_IDS`, the
same IDs in signed `resources.applications`, and a signed
`application_credential_baseline`. It reads each exact application and its
complete owner collection with `Application.Read.All`; it never lists all
applications. Names, hints, thumbprints, public keys and secret values are
neither persisted nor returned. An unexpected `key` or `secretText` value from
Graph rejects the operation before an encrypted snapshot is written.

## Diagnostic commands

| Command | Network | Purpose |
|---|---:|---|
| `m365-secure-mcp --doctor` | no | Tool/result surface, delete check, private state, egress, identity, cache, write gates |
| `m365-secure-mcp --doctor live` | read-only Graph | Delegated scope claims plus policy-checked `/me` |
| `m365-secure-mcp --explain-permissions` | no | Tool-by-tool module/action reason for every requested scope |
| `m365-secure-mcp --print-policy` | no | Operator-only effective policy and stable SHA-256 digest |
| `m365-secure-mcp --export-policy PATH` | no | Create a new owner-only private policy; never overwrite |
| `m365-secure-mcp --policy-file PATH` | depends on action | Load all settings from one strictly protected policy |
| `m365-secure-mcp --discover-resources KIND...` | read-only APIs | List candidates for drives, Planner, Teams/chats/groups, users, directory/Intune devices, Cloud PCs, Power BI, Entra apps/service principals, Conditional Access, eDiscovery cases, or retention labels without changing policy |
