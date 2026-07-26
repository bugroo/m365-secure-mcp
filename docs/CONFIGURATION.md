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
entra_apps,governance,licensing,compliance
```

Tool filters accept explicit `m365_*` names only. Unknown, conflicting, or
out-of-profile names stop startup.

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
| `M365_ALLOWED_APPLICATION_IDS` | Entra application registration reads/writes |
| `M365_ALLOWED_SERVICE_PRINCIPAL_IDS` | Entra enterprise application reads/writes |
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
users.update_profile
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

Administrative actions also require
`M365_PRIVILEGED_WRITES_ENABLED=true`. They expose only closed update
contracts:

- application: `displayName`, `groupMembershipClaims`;
- service principal: `displayName`, `accountEnabled`,
  `appRoleAssignmentRequired`;
- Conditional Access: `displayName`, `state`;
- user profile: `displayName`, `jobTitle`, `department`,
  `officeLocation`, `usageLocation`;
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
| `M365_AUDIT_LOG_PATH` | platform log directory |

Audit records contain tool/outcome metadata and keyed parameter fingerprints,
not raw Microsoft 365 content. Each event also includes the public operation ID
and elapsed time so attempts can be correlated with structured MCP results and
write receipts.

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
