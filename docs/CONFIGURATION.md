# Configuration reference

All runtime configuration uses `M365_`-prefixed environment variables. The
server does not read `.env` files itself.

## Identity

| Variable | Required | Meaning |
|---|---:|---|
| `M365_TENANT_ID` | yes | Single Microsoft Entra tenant UUID |
| `M365_CLIENT_ID` | yes | Public desktop application UUID |
| `M365_ALLOWED_USER_OBJECT_IDS` | recommended | Comma-separated signed-in principal/assignee UUIDs |
| `M365_ALLOWED_UPN_DOMAINS` | recommended | Lowercase DNS domains accepted for the principal |
| `M365_AUTH_FLOW` | no | `interactive` (default) or `device_code` |
| `M365_ALLOW_DEVICE_CODE` | no | Must be `true` before device code can start |
| `M365_TOKEN_CACHE_MODE` | no | `keyring` (default) or explicitly ephemeral `memory` |

The server requests Microsoft Graph scopes directly. No value should contain
an `api://` audience or a client secret.

## Surface selection

| Variable | Default | Meaning |
|---|---|---|
| `M365_PROFILE` | `read` | Separate `read` or `write` process |
| `M365_MODULES` | `profile` | Comma-separated read modules |
| `M365_ENABLED_TOOLS` | blank | Exact allowlist within the active profile |
| `M365_DISABLED_TOOLS` | blank | Exact removals within the active profile |
| `M365_PRIVILEGED_MODULES_ENABLED` | `false` | Second gate for tenant-wide/admin modules |

Available modules:

```text
profile,mail,calendar,files,sites,contacts,todo,planner,teams,
directory,groups,organization,onenote,excel,people,presence,
security,audit,intune,service_health
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
| `M365_ALLOWED_PLAN_IDS` | Planner reads/writes |
| `M365_ALLOWED_RECIPIENT_DOMAINS` | mail/calendar recipients and free/busy |

Sites, Teams, groups, and Planner refuse startup without the corresponding
required allowlist. Chat tools return or accept only allowlisted chat IDs.

## Writes

| Variable | Default | Meaning |
|---|---|---|
| `M365_WRITE_ENABLED` | `false` | Independent write-profile gate |
| `M365_WRITE_ACTIONS` | blank | Exact action allowlist |
| `M365_WRITE_RATE_LIMIT_PER_MINUTE` | `10` | Per-tool local rate limit |
| `M365_IDEMPOTENCY_PENDING_SECONDS` | `86400` | Pending-key fail-closed period |
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
```

`planner.update_task_details` uses the same least-privileged delegated
`Tasks.ReadWrite` scope as the other Planner writes. It is a separate local
action so an operator can allow basic task updates without allowing description
or checklist changes, or vice versa.

## Bounds and audit

| Variable | Default |
|---|---:|
| `M365_GRAPH_TIMEOUT_SECONDS` | `20` |
| `M365_GRAPH_MAX_RETRIES` | `3` |
| `M365_MAX_ITEMS` | `50` |
| `M365_MAX_RESPONSE_BYTES` | `2000000` |
| `M365_MAX_TOOL_CHARACTERS` | `24000` |
| `M365_AUDIT_LOG_PATH` | platform log directory |

Audit records contain tool/outcome metadata and keyed parameter fingerprints,
not raw Microsoft 365 content.
