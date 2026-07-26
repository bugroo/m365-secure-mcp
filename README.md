<p align="center">
  <img src="docs/assets/hero.svg" alt="M365 Secure MCP. Policy-bound Microsoft 365 access for local AI clients." width="100%">
</p>

[![CI](https://img.shields.io/github/actions/workflow/status/bugroo/m365-secure-mcp/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/bugroo/m365-secure-mcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-555b61?style=flat-square)](LICENSE)

A local-first MCP server that gives Codex, Claude Code, and compatible clients
controlled access to Microsoft 365 through fixed, reviewable tools.

| Fixed contracts | Read profile | Opt-in writes | Delete tools | Modules |
|---:|---:|---:|---:|---:|
| 125 | 96 max | 27 | 0 | 32 |

[Installation](#installation) | [Security model](#security-model) |
[Evidence](#evidence-contract) | [Diagnostics](#diagnose-before-serving) |
[Capabilities](#capabilities) | [Planner details](#planner-task-details) |
[Private policy](#private-policy-and-resource-discovery) |
[MSP deployment](#host-and-customer-tenants) |
[Tool catalog](docs/TOOL_CATALOG.md) |
[Entra setup](docs/ENTRA_SETUP.md)

## What this server is

`m365-secure-mcp` is not a generic Microsoft Graph proxy. The model cannot
choose a URL, HTTP method, permission scope, or request header.

The operator starts with a broad catalog, then reduces each deployment by
identity, module, tool, resource, and action. Unknown or out-of-policy
configuration fails before the server starts.

```mermaid
flowchart TB
    A["Codex or Claude Code"] -->|"local stdio"| B["M365 Secure MCP"]
    H["OS Keychain"] -->|"token cache"| B
    B --> C["Identity + tool surface + resource + action"]
    C -->|"Graph token"| G["Microsoft Graph v1.0"]
    C -->|"separate audience"| P["Power BI REST v1.0"]
    B --> I["Metadata audit log"]
    B --> J["Write receipt ledger"]
    B --> K["Versioned result envelope"]
```

## Installation

Requirements: Python 3.11+, [`uv`](https://docs.astral.sh/uv/), and a
single-tenant Microsoft Entra public-client registration whose delegated
permissions were added and consented by an administrator.

```bash
git clone https://github.com/bugroo/m365-secure-mcp.git
cd m365-secure-mcp
uv sync --frozen --python python3.13
```

The committed `uv.lock` pins the resolved dependency graph. This project has no
Node.js runtime, postinstall script, client secret, permission-grant tool, or
consent automation.

### Configure and seal the smallest profile

```bash
export M365_TENANT_ID="<tenant-guid>"
export M365_CLIENT_ID="<public-application-guid>"
export M365_ALLOWED_USER_OBJECT_IDS="<user-object-guid>"
export M365_ALLOWED_UPN_DOMAINS="example.com"

uv run m365-secure-mcp --check-config
uv run m365-secure-mcp --explain-permissions
uv run m365-secure-mcp --doctor
uv run m365-secure-mcp --list-tools
uv run m365-secure-mcp --export-policy \
  "$HOME/Library/Application Support/m365-secure-mcp/read-policy.json"
uv run m365-secure-mcp --policy-file \
  "$HOME/Library/Application Support/m365-secure-mcp/read-policy.json"
```

The export is a new owner-only `0600` file inside an owner-only `0700`
directory. Existing paths, symlinks, unknown settings, and broad permissions
are rejected. The private policy contains tenant/resource identifiers but no
token or client secret; keep it out of Git and client configuration.

The default configuration exposes only:

```text
m365_get_security_posture
m365_get_my_profile
```

Enable domains and individual tools deliberately:

```bash
export M365_MODULES="profile,mail,calendar,files"
export M365_ENABLED_TOOLS="m365_search_mail,m365_list_calendar,m365_search_files"
```

## Connect a client

<details>
<summary><strong>Codex</strong></summary>

Merge [examples/codex-read.toml](examples/codex-read.toml) into a trusted
project's `.codex/config.toml`, point it at the private policy file, and keep:

```toml
default_tools_approval_mode = "prompt"
```

Do not combine a write profile with automatic tool approval.

</details>

<details>
<summary><strong>Claude Code</strong></summary>

Use [examples/claude-code-read.mcp.json](examples/claude-code-read.mcp.json) as
the local stdio definition. It references the private policy by path; tenant
and user identifiers stay outside shared repositories.

</details>

<details>
<summary><strong>Enterprise read profile</strong></summary>

[examples/enterprise-read.env.example](examples/enterprise-read.env.example)
contains every domain and resource boundary. Remove anything the deployment
does not need before granting Graph consent.

</details>

## Security model

| Boundary | Operator control | Enforced behavior |
|---|---|---|
| Identity | tenant, user object IDs, UPN domains | `/me` is verified before data access |
| Surface | modules, exact tool allowlist and denylist | unknown or unavailable names stop startup |
| Resources | users, devices, Cloud PCs, files, sites, teams, plans, Office, Power BI, Purview and Entra | non-allowlisted identifiers are rejected locally |
| Writes | individual non-delete actions | separate process, explicit action, approval, receipts |
| Egress | Microsoft APIs | pinned Graph v1.0, Power BI REST and validated Office download hosts |
| Evidence | every tool result | versioned schema, operation ID, explicit retry state |

Additional controls:

- admin-preconsented delegated OAuth authorization code flow with PKCE
- local JWT claim checks for tenant, issuer, audience, principal, lifetime and exact scope set
- OS Keychain token cache, with no plaintext token file
- one process, authority, token cache, audit namespace and receipt ledger per
  tenant/deployment kind/profile
- separate operator-principal, target-user and Planner-assignee allowlists
- a distinct Power BI token and audience; Graph bearer tokens are never reused
- no-follow, owner-only local audit and receipt files
- Graph `v1.0` only; Office redirects are manually validated and never receive the bearer token
- bounded OOXML parsing that rejects encrypted packages, traversal, entities, macros, ActiveX, OLE and ZIP bombs
- signed pagination cursors bound to tool, principal, resource, and query
- M365 content treated as untrusted input and converted to bounded plain text
- separate read and write processes
- SQLite write reservation and durable metadata-only receipt before Graph is called
- resource-specific ETag concurrency on updates and per-tool rate limits
- no automatic retry after an ambiguous write response or transport failure
- post-write reads verify the exact requested fields before success is reported
- metadata-only audit events correlated by operation ID

Read the complete threat model, assumptions, and residual risks in
[SECURITY.md](SECURITY.md).

## Evidence contract

Every tool returns two synchronized representations:

- the existing text content, for MCP clients that consume plain text
- `structuredContent`, validated against the advertised `outputSchema`

Failures are returned with MCP `isError=true`, a stable error code, a recovery
action, and explicit retry guidance. Agents no longer have to infer failure
from a string beginning with `Error:`.

```json
{
  "schema_version": "1.0",
  "ok": false,
  "tool": "m365_update_planner_task_details",
  "operation_id": "9dcf6f91-f3c7-4fbe-9a52-f34fd315a2ea",
  "content_type": "text/plain",
  "error": {
    "code": "GRAPH_CONCURRENCY_CONFLICT",
    "category": "conflict",
    "message": "resource changed since it was read",
    "action": "Re-read the resource and retry with its current ETag."
  },
  "retry": {
    "safe_to_retry": true,
    "reuse_idempotency_key": true
  },
  "evidence": {
    "policy_enforced": true,
    "audit_recorded": true,
    "write_receipt": {
      "operation_id": "9dcf6f91-f3c7-4fbe-9a52-f34fd315a2ea",
      "tool": "m365_update_planner_task_details",
      "idempotency_key": "58e0e271-06ba-4c3a-81e8-b70c1d43dc28",
      "status": "rejected",
      "created_at": "2026-07-26T12:00:00+00:00",
      "updated_at": "2026-07-26T12:00:01+00:00",
      "duplicate_suppressed": false,
      "uncertain_commit": false,
      "last_error_code": "GRAPH_CONCURRENCY_CONFLICT"
    }
  }
}
```

Successful writes additionally carry a metadata-only receipt with the same
operation ID, tool, idempotency key, status, timestamps, duplicate-suppression
flag, and uncertainty state. It contains no M365 body, subject, address,
filename, task text, or token.

## Diagnose before serving

The CLI can explain the effective deployment without starting MCP stdio:

```bash
# Tool/result surface, delete check, private state, cache mode, and egress
uv run m365-secure-mcp --doctor

# Adds delegated-token scope comparison and a read-only Graph /me policy check
uv run m365-secure-mcp --doctor live

# Tool-by-tool reason for every Graph scope
uv run m365-secure-mcp --explain-permissions

# Operator-only policy summary plus a stable sha256 digest
uv run m365-secure-mcp --print-policy

# Read-only candidate discovery; never changes allowlists or exposes an MCP tool
uv run m365-secure-mcp --discover-resources \
  planner applications service_principals conditional_access \
  ediscovery_cases retention_labels
```

The offline doctor never signs in or calls Graph. Live mode may open the normal
interactive Microsoft sign-in, but prints neither the token nor M365 content.
Client-side approval configuration remains an explicit informational check
because a stdio server cannot prove the host's approval policy.

## Capabilities

| Personal work | Collaboration | Content | Security and IT |
|---|---|---|---|
| Mail | Teams | OneDrive | Defender incidents |
| Calendar | Chats | SharePoint | Security alerts |
| Contacts | Channels | Word and PowerPoint | Entra audit |
| To Do | Groups | OneNote metadata | Intune |
| Planner | People and presence | Excel ranges | Windows 365 |
| Entra users/devices/apps | Power BI | OneNote content | CA, RBAC, licenses |
|  |  |  | Purview eDiscovery/retention |

### Read profile

Up to **96 read tools** are selected by module and can be reduced to an exact
allowlist. Content-bearing responses are normalized, bounded, and marked as
untrusted external data.

### Write profile

The write process exposes **27 non-delete actions**, each separately enabled.
They cover routine work, Planner details, bounded Entra user/group controls,
Intune sync, Windows 365 reboot, Office/OneNote/Excel edits, Power BI
refresh/rebind, application metadata, service-principal controls, and
allowlisted Conditional Access state. Exact tool contracts are listed in the
[tool catalog](docs/TOOL_CATALOG.md).

Every write requires a UUID idempotency key. The local ledger commits before
Graph is called and returns a durable operation receipt. An uncertain result
blocks automatic retry indefinitely to avoid duplicate external actions.
`m365_get_write_operation` retrieves one receipt by operation ID or by the
exact tool/idempotency-key pair; it cannot enumerate the ledger and never calls
Graph.

<details>
<summary><strong>Expand the 125-contract capability map</strong></summary>

| Domain | Fixed reads | Opt-in writes |
|---|---:|---:|
| Mail, calendar, contacts | 10 | 5 |
| To Do, Planner, Teams | 14 | 7 |
| OneDrive and selected SharePoint | 11 | 0 |
| Word, PowerPoint, Excel and OneNote | 9 | 4 |
| People, groups, Entra users and devices | 11 | 4 |
| Defender, audit, Intune, Windows 365, health | 12 | 2 |
| Entra apps, governance, licensing, compliance | 19 | 3 |
| Power BI | 8 | 2 |
| Profile and organization | 2 | 0 |

Common/local evidence adds `m365_get_security_posture` and the write-only
receipt query. The full names, input bounds, permissions, and resource gates
are maintained in [docs/TOOL_CATALOG.md](docs/TOOL_CATALOG.md).

</details>

## Host and customer tenants

MSP operation uses one named process per tenant and privilege profile. A tool
call never accepts `tenant_id`; changing customer means changing to a
separately configured MCP entry.

```text
host-routine-read       customer-a-routine-read
host-routine-write      customer-a-privileged-read
host-privileged-read    customer-a-selected-write
```

Each customer profile binds the exact customer tenant, client registration,
signed-in object ID, API audience, scopes, resource allowlists, keychain cache,
audit namespace and idempotency ledger. A ledger opened under a different
tenant/profile namespace is rejected.

The admin must add delegated API permissions, grant admin consent, assign the
enterprise application to approved operators, and assign any required Entra
or workload role. The MCP can inspect grants but cannot create or modify API
permissions, OAuth consent, app-role assignments, directory roles or PIM
assignments. See [MSP multi-tenant deployment](docs/MSP_MULTI_TENANT.md).

### Deliberate exclusions

`Directory.AccessAsUser.All`, `Directory.ReadWrite.All`, RBAC writes,
credential/password operations and application-only mailbox access are not
shortcuts this server takes. [Agent Registry/Agent ID write
APIs](https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-beta)
and `AiEnterpriseInteraction.*` are also quarantined: the relevant Graph
surface is still beta. They will not be advertised as production tools until
stable endpoints, least-privileged permissions and data boundaries can be
tested.

Microsoft Purview is intentionally narrower than the operational modules.
The stable compliance surface can list/read only explicitly allowlisted
eDiscovery case metadata and retention-label definitions. It exposes no case
content, search execution, holds, exports, label assignment, policy mutation,
close, or delete action.

## Private policy and resource discovery

Resource IDs belong in one local owner-only policy, not in a public repository
or repeated across client configs. The operator can discover candidates through
fixed read-only Graph calls:

```bash
uv run m365-secure-mcp --policy-file "/private/read-policy.json" \
  --discover-resources planner teams chats groups

uv run m365-secure-mcp --policy-file "/private/admin-read-policy.json" \
  --discover-resources users directory_devices managed_devices cloudpcs \
  applications service_principals conditional_access \
  ediscovery_cases retention_labels

uv run m365-secure-mcp --policy-file "/private/routine-read-policy.json" \
  --discover-resources drives planner teams chats groups

uv run m365-secure-mcp --policy-file "/private/powerbi-read-policy.json" \
  --discover-resources powerbi_workspaces

# After approved workspace IDs are added to the private policy:
uv run m365-secure-mcp --policy-file "/private/powerbi-read-policy.json" \
  --discover-resources powerbi_content
```

Discovery is deliberately outside the MCP tool surface. It prints untrusted
metadata and whether each ID is already allowed, but it never edits the policy
or selects resources on the operator's behalf.

Use separate private policy files and app registrations for routine read,
routine write, privileged read, and privileged write. See
[Ownership and migration](docs/OWNERSHIP_AND_MIGRATION.md) for the staged
replacement of third-party Graph proxies without losing break-glass coverage.

## Selected administrative writes

Administrative writes remain invisible until every layer agrees:

```bash
export M365_PROFILE=write
export M365_WRITE_ENABLED=true
export M365_PRIVILEGED_WRITES_ENABLED=true
export M365_WRITE_ACTIONS=entra.update_service_principal
export M365_ALLOWED_SERVICE_PRINCIPAL_IDS="<approved-object-guid>"
```

The corresponding Entra registration must also have the delegated Graph
permission and the signed-in operator must hold a supported Entra role.
User writes cannot touch passwords, authentication methods, identities or
licenses. Role-assignable groups, and groups whose role status cannot be
confirmed, are rejected before any metadata or membership write.
Application and service-principal updates cannot touch secrets, certificates,
owners, redirect URIs, app roles, or consent grants. Conditional Access updates
can change only `state` and `displayName`; conditions and controls are
read-only. No delete operation exists.

## Planner task details

`m365_update_planner_task_details` closes the gap between basic Planner task
fields and the separate Graph details resource. It can set a non-empty
description, choose the card preview, add checklist entries, rename existing
entries, and change their checked state.

```bash
export M365_PROFILE="write"
export M365_WRITE_ENABLED="true"
export M365_WRITE_ACTIONS="planner.update_task_details"
export M365_ALLOWED_PLAN_IDS="<approved-plan-id>"
```

The tool requires the `details_etag` returned by `m365_get_planner_task`:

```json
{
  "task_id": "task-id",
  "plan_id": "approved-plan-id",
  "details_etag": "W/\"details-etag\"",
  "description": "Implementation notes",
  "preview_type": "checklist",
  "checklist_additions": [
    {"title": "Validate deployment", "is_checked": false}
  ],
  "checklist_updates": [
    {
      "item_id": "95e27074-6c4a-447a-aa24-9d718a0b86fa",
      "is_checked": true
    }
  ],
  "idempotency_key": "58e0e271-06ba-4c3a-81e8-b70c1d43dc28"
}
```

> [!CAUTION]
> The basic task `etag` and `details_etag` are different concurrency tokens.
> The tool re-reads both the task and its details, verifies the allowlisted
> plan, caps the resulting checklist at 20, and refuses stale ETags or unknown
> item UUIDs. Checklist deletion by `null`, whole-object replacement,
> reference mutation, and description clearing are not exposed.

Checklist additions use deterministic UUIDv5 identifiers derived from the
idempotency key. A `204 No Content` response is followed by a verification
read. The result includes a durable receipt; it can be queried later with
`m365_get_write_operation`. The only required delegated Graph permission is
`Tasks.ReadWrite`.

## Entra registration

Create a **single-tenant public desktop client**, add `http://localhost` as its
redirect URI, then have an administrator add and consent only the delegated
permissions printed by `--explain-permissions`. Runtime token requests use
the preconsented `/.default` set; the MCP never starts a dynamic permission
grant.

> [!IMPORTANT]
> Do not configure an `api://<guid>` scope for this local server. It requests
> Microsoft Graph scopes directly and does not require Expose an API, OBO,
> Dynamic Client Registration, or a client secret.

The full permission matrix and `Sites.Selected` instructions are in
[docs/ENTRA_SETUP.md](docs/ENTRA_SETUP.md).

### AADSTS500011

If Microsoft reports:

```text
The resource principal named api://<guid> was not found in the tenant
```

the client requested a token for a private API that is absent or unconsented in
that tenant. This server does not depend on that private resource principal.

Use the [authentication decision tree](docs/AUTH_TROUBLESHOOTING.md) to verify
the tenant, public-client ID, redirect URI, and delegated permissions.

## Configuration

```text
modules
  -> exact visible tool surface
     -> resource allowlists
        -> exact reachable data
```

Administrative domains such as Defender, Entra audit, Intune, and Service
Health, Entra applications, governance, licensing, domains, and Purview
compliance also require:

```bash
export M365_PRIVILEGED_MODULES_ENABLED=true
```

Privileged write actions additionally require:

```bash
export M365_PRIVILEGED_WRITES_ENABLED=true
```

See the [full configuration reference](docs/CONFIGURATION.md).

## Verification

```bash
uv run pytest -q
uv run ruff check .
uv run mypy src
uv run pip-audit
uv build
```

Current baseline:

| Check | Result |
|---|---|
| Tests | 127 passed |
| Ruff | clean |
| Mypy | strict, clean |
| Dependency audit | no known vulnerabilities |
| Package | wheel and source distribution |
| Full read-profile smoke test | 96 read contracts + security posture |

Live Graph integration tests require a dedicated non-production tenant and
explicit operator consent.

## Documentation

| Document | Purpose |
|---|---|
| [Tool catalog](docs/TOOL_CATALOG.md) | All 125 contracts and their boundaries |
| [Security architecture](SECURITY.md) | Threat model, controls, residual risks |
| [Configuration](docs/CONFIGURATION.md) | Every environment variable and gate |
| [Entra setup](docs/ENTRA_SETUP.md) | Registration, delegated scopes, consent |
| [Authentication troubleshooting](docs/AUTH_TROUBLESHOOTING.md) | AADSTS diagnosis |
| [Reference review](docs/REFERENCE_REVIEW.md) | Comparative engineering decisions |
| [Ownership and migration](docs/OWNERSHIP_AND_MIGRATION.md) | Public core, private deployment, and Lokka transition |
| [MSP multi-tenant deployment](docs/MSP_MULTI_TENANT.md) | Host/customer isolation, GDAP and admin-consent workflow |

## Engineering references

Primary specifications:

- [Model Context Protocol tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Planner task details API](https://learn.microsoft.com/en-us/graph/api/plannertaskdetails-update?view=graph-rest-1.0)
- [Microsoft Purview eDiscovery case API](https://learn.microsoft.com/en-us/graph/api/security-casesroot-list-ediscoverycases?view=graph-rest-1.0)
- [Microsoft Purview retention labels API](https://learn.microsoft.com/en-us/graph/api/security-labelsroot-list-retentionlabel?view=graph-rest-1.0)
- [Power BI REST API](https://learn.microsoft.com/en-us/rest/api/power-bi/)

The architecture was informed by, but does not import runtime code from:

- [`aixolotl/microsoft-planner-mcp`](https://github.com/aixolotl/microsoft-planner-mcp)
- [`Softeria/ms-365-mcp-server`](https://github.com/Softeria/ms-365-mcp-server)
- [`merill/lokka`](https://github.com/merill/lokka)

The adopted and rejected patterns are recorded in
[docs/REFERENCE_REVIEW.md](docs/REFERENCE_REVIEW.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
