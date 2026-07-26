# Security architecture

## Security objective

Give local AI coding clients useful access to Microsoft 365 while minimizing
the blast radius of:

- prompt injection embedded in mail, meetings, files, contacts, tasks, or Teams;
- an over-eager or compromised model invoking a tool;
- token theft from files, logs, process arguments, or MCP output;
- excessive Microsoft Graph consent;
- arbitrary Graph endpoint substitution;
- confused-deputy behavior between an MCP client and Microsoft identity;
- accidental or repeated writes.

## Trust boundaries

1. **MCP client → local server.** The client controls tool inputs. Tool
   annotations are hints, not an authorization boundary.
2. **Local server → Microsoft identity.** MSAL performs PKCE authorization for a
   tenant-specific public client.
3. **Local server → Microsoft APIs.** Curated tools use Graph v1.0 or the
   tenant-scoped Power BI REST root. The two APIs use different tokens.
4. **Microsoft 365 content → model context.** All returned business content is
   considered attacker-controlled.
5. **Write server → external people/data.** A write can affect recipients,
   calendars, Planner, applications, service principals, or Conditional Access
   and therefore needs independent local gates and MCP-client approval.

## Implemented controls

### Identity and tokens

- Single-tenant authority from a validated tenant UUID.
- Public-client authorization code with PKCE; no client secret.
- Permissions must be added and admin-consented before runtime. MSAL requests
  the preconsented `/.default` set; dynamic consent is not a configuration
  mode and no consent URL or grant API is exposed.
- Device-code flow disabled unless explicitly opted in. Microsoft classifies
  device code as higher risk and allows Conditional Access policies to block
  it.
- Serializable MSAL cache stored in OS Keychain. If Keychain fails, the server
  fails closed unless ephemeral memory mode is explicitly selected.
- Tokens never appear in tool parameters, results, logs, environment examples,
  or command arguments.
- Access-token claims are checked locally for exact tenant, trusted issuer,
  API audience, lifetime, allowlisted object ID, required scopes and unexpected
  scope drift before a token is used.
- The first Graph request resolves `/me`; object ID and UPN domain policies are
  then enforced locally.
- Power BI gets a separate token for
  `https://analysis.windows.net/powerbi/api`; a Graph bearer token is never
  sent to Power BI.
- Tenant, client, deployment kind, profile and API resource namespace each
  keychain entry. Customer deployments require an exact operator object ID.

### Least privilege

- Delegated permissions only.
- Scope set derived from the enabled read modules or write-action allowlist.
- Default is read profile plus `User.Read` only.
- SharePoint uses `Sites.Selected` and local site allowlists.
- Teams and Planner require local resource allowlists before their modules can
  start.
- Groups require group IDs; Teams chats require chat IDs before their content
  can be returned.
- Administrative users, Entra devices, Intune devices, Cloud PCs, Office
  items, OneNote pages and every Power BI resource use separate allowlists.
- Organization, Defender, Entra audit, Intune, service health, Entra
  applications, governance, licensing, domains, and Purview compliance
  require an independent privileged-module gate.
- Purview eDiscovery cases and retention labels use independent UUID
  allowlists. Only metadata/definition reads exist; case content, searches,
  holds, exports, label assignment, mutation, close, and delete are absent.
- Application registrations, service principals, and Conditional Access
  writes require separate UUID resource allowlists and the privileged-write
  gate.
- Exact per-tool allowlists/denylists are applied after module registration;
  unknown tool names fail startup.
- No `Directory.ReadWrite.All`, `Directory.AccessAsUser.All`, app-only
  authentication mode, Graph `beta`, Agent Registry preview or Azure Resource
  Manager access.
- Role definitions and assignments can be inspected, but role assignment,
  PIM activation, OAuth grants, app-role grants and admin consent cannot be
  changed through the MCP.

### MCP and prompt injection

- Read and write profiles run as separate processes and should be separate
  client entries.
- All content-derived fields are bounded and control characters removed.
- HTML message bodies are converted to plain text; script, style, and SVG
  content is discarded.
- Every content-bearing response includes a provenance warning that embedded
  instructions are data, not authorization.
- There is no arbitrary URL/method/body Graph tool.
- Pagination links are validated against the Graph v1.0 egress allowlist and
  wrapped in a process-local HMAC cursor bound to the originating tool.
- Tool outputs are capped below common MCP client warning thresholds.

### Writes

- Write profile refuses startup unless `M365_WRITE_ENABLED=true` and at least
  one action is explicitly allowlisted.
- Mail recipients and calendar attendees are locally restricted. Planner
  assignees use a separate UUID allowlist from the principals authorized to
  operate the MCP.
- Sending is separate from creating a draft.
- Calendar uses Graph `transactionId` for retry idempotency.
- Planner task and task-details updates require their distinct `If-Match`
  values; stale writes fail before mutation or with Graph 412.
- Planner task-details writes verify the task's plan, re-read current details,
  accept only known fields, cap the checklist at 20, and reject unknown item
  UUIDs. Additions use deterministic UUIDv5 identifiers.
- Checklist deletion by `null`, whole-checklist replacement, and description
  clearing are absent from the tool contract.
- Administrative writes expose only bounded metadata/control fields. They
  cannot manage credentials, owners, redirect URIs, consent grants, app roles,
  role assignments, licenses, or Conditional Access conditions.
- User profile and account-state tools cannot manage passwords,
  authentication methods, identities or licenses. Every group write requires
  Graph to explicitly confirm `isAssignableToRole=false`; role-assignable or
  unclassified groups fail closed before mutation.
- Office writes require exact drive/item allowlists and `If-Match`. OOXML is
  bounded before parsing and rejects traversal, duplicate/encrypted members,
  entities, macros, ActiveX, embedded OLE and suspicious compression.
- Excel accepts a bounded rectangular matrix of literal values and rejects
  strings beginning with formula-trigger characters (`=`, `+`, `-`, `@`).
  OneNote appends HTML-escaped plain text and verifies it by reading the page
  back.
- Power BI refresh and rebind use workspace/report/dataset allowlists, a
  separate token audience and the same idempotency/uncertainty controls.
- Privileged writes require `M365_PRIVILEGED_WRITES_ENABLED=true` in addition
  to the write profile, global write gate, exact action, exact resource
  allowlist, Entra consent/RBAC, and MCP-client approval.
- Every write is reserved in a mode-`0600` local SQLite ledger before Graph is
  called. Reused keys with changed payloads are rejected.
- The ledger issues a metadata-only UUID receipt and records `pending`,
  `completed`, `rejected`, or `uncertain`. It never stores M365 content.
- A lost/uncertain response, a write-side timeout, or a `502`/`503`/`504`
  blocks automatic retry indefinitely. A Graph `429` explicitly means the
  request failed and is the only write response retried automatically.
- A successful write response that violates local size, JSON, or shape
  expectations is also classified as uncertain because the mutation may
  already have committed.
- Every accepted update is followed by a bounded read that verifies the
  requested fields. A missing or mismatched postcondition is classified
  `uncertain`, never as a safe rejection.
- `m365_get_write_operation` reads one receipt by exact selector, cannot list
  history, is limited to actions active in the current policy, and never calls
  Graph.
- Each write tool has an independent process-local per-minute rate limit.
- The receipt ledger is stamped with a tenant/profile deployment namespace and
  refuses reuse by another namespace.
- No delete tools are implemented.
- Every tool logs an attempt and result metadata correlated by operation ID.

### Network and response handling

- Exact Graph and Power BI hostnames, HTTPS, standard ports, fixed API roots,
  and no userinfo or fragment.
- Redirect following is disabled. Office download redirects are handled
  manually only after validating an HTTPS Microsoft storage hostname; the
  Graph Authorization header is dropped before the second request.
- Timeouts, bounded read retries, safe write throttling retries,
  `Retry-After`, byte limits, item limits, and character limits.
- Provider error bodies are not returned to the model. Correlation/request IDs
  may be returned for support.

### Audit

- Append-only JSONL with mode `0600` in a directory created with mode `0700`.
- Audit and receipt paths reject symlinks, non-regular files, foreign owners,
  and parent directories broader than mode `0700`.
- Records time, tool, outcome, request ID, public operation ID, duration, and a
  process-keyed HMAC of parameters plus a non-reversible deployment namespace.
- It does not record message bodies, subjects, addresses, filenames, event
  content, Teams messages, Planner content, tokens, or raw parameters.

## Residual risks

- A model can still read any data allowed by both Graph consent and local tool
  policy. MCP approval policy remains important.
- Tool annotations alone do not stop a malicious client.
- A local process with the user's OS privileges may access Keychain subject to
  OS policy.
- A pending or uncertain idempotency record requires manual verification after
  a crash, timeout, or ambiguous transport failure. This deliberately prefers
  a blocked retry over a duplicate write.
- Metadata can itself contain sensitive business information.
- eDiscovery and retention-label metadata can reveal legal matters or records
  policy. Keep discovery output and private allowlists out of repositories and
  require the narrowest supported Purview role.
- A privileged delegated scope still lets the signed-in operator perform
  whatever Microsoft Graph and Entra RBAC allow outside this MCP. Separate app
  registrations and user assignment remain essential.
- Each host or customer tenant must have a separate MCP process and private
  policy. Tenant ID is never a tool argument; cross-tenant runtime switching is
  intentionally absent.
- This local profile is single-user. Multi-user remote deployment requires a
  separate OAuth 2.1 resource-server design, per-client consent, token audience
  validation, session isolation, CSRF/state protection, and a reviewed OBO
  exchange. Do not expose the stdio process through a generic proxy.

## Recommended enterprise controls

- Conditional Access with phishing-resistant MFA and compliant devices.
- User/admin consent policy restricted to verified apps and approved scopes.
- Project/user MCP allowlists in Codex and managed MCP configuration in Claude
  Code.
- Separate Entra app registrations for read and write profiles.
- Dedicated non-production tenant for integration tests.
- Regular `uv lock --upgrade` review plus `pip-audit`.
- Review audit events in the organization's SIEM without ingesting M365
  content.

## Vulnerability reporting

Do not include tenant data, tokens, secrets, or customer content in an issue.
Provide only sanitized reproduction steps and correlation IDs.
