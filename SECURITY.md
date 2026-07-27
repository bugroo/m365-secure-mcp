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

The security objective supports three equal capabilities: observe/diagnose,
operate/automate and assure/provide evidence. The server is neither a generic
Graph proxy nor an autonomous administrator, but it is intentionally capable
of bounded administrative effects under signed authority.

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
   and therefore needs independent local gates. T1 can use an administrator-
   signed standing policy; higher tiers require host approval or stronger
   authorization.
6. **Build/Governance → runtime.** Independently pinned and signed global
   manifests define contract floors, playbook DAGs and tenant-neutral posture
   controls. A separate signed tenant policy can select resources and harden
   authorization, but runtime cannot edit or sign any authority.
7. **Assurance evidence → operator.** Conditional Access, directory roles,
   application permission grants, credentials and ownership are sensitive.
   Runtime returns only metrics, deterministic findings, public permission
   values and deployment-keyed references/digests; full minimized snapshots
   are encrypted in a tenant-local owner-only file with no MCP read/decrypt
   surface.

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
  applications, governance, Assurance, licensing, domains, and Purview compliance
  require an independent privileged-module gate.
- The Assurance vertical slice requests only `Policy.Read.All` and
  `RoleManagement.Read.Directory`, requires a signed `privileged-read` tenant
  profile and performs four fixed GET workflows. It cannot accept a tenant,
  endpoint, method, query, approval or resource ID from the model.
- Permission-grant drift is a separate fixed T0 Assurance contract using
  `Directory.Read.All`. Targets must appear in a signed contract-derived
  baseline and a separate local UUID allowlist. It accepts no target/filter,
  treats app-only grants as critical unless exactly excepted, and has no
  consent, revocation or remediation tool.
- Application credential posture is a separate fixed T0 contract using only
  `Application.Read.All`. Targets must appear in a signed baseline and the
  local application allowlist. It never lists all applications, accepts no
  target input, returns no raw IDs or credential material, and has no
  credential/owner write path.
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
- No tenant metadata, remote schema or runtime policy can generate or register
  an MCP tool. There is no in-process updater.
- Playbook DAGs are signed tenant-neutral build artifacts. Every node resolves
  to a compiled contract, and runtime cannot add a node, edge, scope, Graph
  endpoint or output field from tenant data.
- Posture control definitions use an independent signed manifest and a closed
  evaluator-ID enum. Definitions contain no executable expressions, severity,
  tenant selectors, Graph calls or customer policy. Unverified framework
  mappings cannot be published by the compiler.
- Control signing is an explicit offline operator command, separate from
  compile/check and MCP runtime. It accepts only an encrypted Ed25519 signer
  from an owner-only external path and refuses a key ID, public key or lifecycle
  state that does not match the reviewed source trust metadata.
- The control trust ring has exactly one current key. Retired public keys are
  retained only for closed historical manifest digests; compromised keys are
  never accepted. Production and ephemeral test authorities cannot be mixed.
- Pagination links are validated against the Graph v1.0 egress allowlist and
  wrapped in a process-local HMAC cursor bound to the originating tool.
- Tool outputs are capped below common MCP client warning thresholds.
- Assurance snapshots fail closed unless every fixed collection selected by
  the contract is complete and within page, record, catalog, nesting and
  encrypted-byte bounds. Graph-derived IDs and policy conditions never enter
  MCP output.

### Assurance and drift

- Governance v2 extends the existing signed tenant policy with an exact
  control-manifest digest/schema/library binding and an exact canonical
  M1-compatibility-metadata digest, explicit enabled control IDs, customer
  severity, non-relaxing evidence freshness and exact expiring exceptions.
  Unknown fields, controls, versions, selectors, changed compatibility
  metadata and relaxed freshness fail closed. Governance v1 remains valid for
  existing tools but cannot enable the Control Library and is never migrated
  automatically.
- The M1 signed definitions do not contain freshness metadata. The public
  compatibility artifact is not signed-manifest metadata; Governance v2 pins
  its independent content digest so installed-code drift cannot silently
  change effective freshness. A future signed definition revision must retire
  this bridge through reviewed manifest and policy rotation.
- M2 validates and deterministically resolves Control Library configuration
  only. It does not inspect evidence, execute evaluators, change assessment
  statuses or produce compliance conclusions. The runtime cannot choose an
  evaluator, Graph route, evidence source, expression or severity.
- The optional Entra Identity Governance baseline is part of the signed private
  Governance policy. It stores keyed domain digests and administrator-selected
  severity, not raw tenant configuration.
- The permission-grant baseline is independently signed and maps allowlisted
  targets to exact compiled contract IDs. Expected scopes are derived
  deterministically; runtime cannot accept arbitrary permission expectations.
- The application-credential baseline independently signs exact application
  targets, owner minimums, expiry windows, secret policy and active-credential
  limits. Credential exceptions bind an exact kind/key ID; application-level
  exceptions cannot suppress arbitrary credential findings.
- The profile-debt baseline signs severity for every supported control,
  minimum policy version, review age, evidence window, failure threshold and
  exact expiring exceptions. It correlates validated token scope names with
  current-app grant posture, the active profile closure, audit metadata and
  resource fences; it cannot change any of them.
- Profile-debt audit inspection is limited to the configured application-owned
  path, 16 MB and 100,000 records. Missing, malformed, oversized, symlinked or
  broadly accessible evidence is `not_evaluated`; the runtime does not search
  the home directory or inspect unrelated files.
- Workload Identity Readiness is `automatic_read` and has the exact permission
  closure of its two signed child contracts. It correlates the application and
  service-principal views with a deployment-keyed HMAC reference rather than a
  raw client/object ID. An incomplete node halts the parent or marks the target
  `not_evaluated`; it cannot trigger a write or remediation.
- HMAC keys are deployment/tenant-profile local, kept in OS Keychain and
  cryptographically separated from the Fernet encryption operation. Digests
  cannot be compared across customer deployments.
- Runtime can compare a snapshot with a signed baseline but cannot promote,
  edit, sign or learn a baseline, change severity, create an exception or
  remediate drift.
- Exceptions are signed, exact and expiring. Posture exceptions bind a
  control/domain; permission exceptions bind target, kind, resource app,
  permission value and consent type. Expired exceptions stop affecting
  classification automatically.
- Application credential evidence never stores names, secret hints,
  thumbprints, `secretText`, public key values or certificate material. The
  fixed Graph request avoids the `$select=keyCredentials` opt-in and rejects an
  unexpected non-empty `key` or `secretText` before snapshot persistence.
- A policy change during collection invalidates the result. A missing baseline
  is `not_evaluated`, never silently `aligned`.
- The encrypted append-only snapshot contains raw normalized IDs/conditions
  needed for local investigation. Its outer record contains only timestamps,
  domain counts, an opaque snapshot ID and ciphertext; there is no MCP
  retrieval tool.

### Runtime and release self-check

- Offline doctor verifies the independently signed contract and playbook
  manifests before comparing their exact per-item digests with compiler
  evidence packaged inside the installed distribution.
- Packaged provenance binds the manifest digests, digest maps, CycloneDX SBOM,
  dependency lock digest and package version. Doctor compares installed
  runtime dependency versions with that SBOM; external release
  signature/attestation remains an install-pipeline responsibility.
- Local compiler provenance is explicitly `local-unattested`,
  `not-a-release`, and `external-required`. Local wheel/sdist builds are not
  release attestations. A future protected release workflow must replace the
  source-revision placeholder and bind tagged source, archives, attestation,
  SBOM and the signed control-manifest digest before publication.
- Filesystem checks inspect metadata only for explicit configuration paths and
  application-owned audit, receipt, snapshot, recovery and approval paths.
  There is no recursive directory traversal, home-directory search, secret
  discovery or automatic permission repair.
- Profile isolation checks cache namespacing, distinct state roles and
  compatibility between runtime read/write class and the active signed
  Governance profile without printing tenant/client IDs or private paths.
- Effective-scope closure is derived from the actual exposed static tool
  surface. A missing or excessive scope fails with one operator action; doctor
  never edits Entra consent or local configuration.

### External MSP radar

- The radar is an external orchestrator, not a tenant selector inside MCP.
  Every deployment launches a separate child from a distinct owner-only policy
  file and therefore retains its own identity, token cache, baseline and
  evidence boundary.
- Configuration accepts only fixed read-only Assurance tool names, unique
  opaque deployment references and unique policy files. It cannot configure a
  command, Graph URL, write tool or remediation.
- Child stderr and exception bodies are not copied into aggregate output.
  Results are reduced to status, coverage, severity/alignment counts and
  evidence availability; raw findings, IDs, paths and Graph content are
  discarded.
- Parallelism is bounded to four. A failed child becomes an isolated result
  and cannot cancel or expose another tenant.

### Writes

- Write profile refuses startup unless `M365_WRITE_ENABLED=true` and at least
  one action is explicitly allowlisted.
- The compiled authorization matrix is `automatic_read` for T0,
  `standing_policy` for bounded T1, `explicit_plan` for T2, dual control or
  break glass for T3, and `prohibited` for T4. Tenant policy may tighten but
  never lower the contract floor.
- Approval is never a tool parameter or model-controlled boolean. The T1 Entra
  vertical slice needs no per-call prompt under a valid signed standing policy;
  an `explicit_plan` override returns `AWAITING_APPROVAL` before mutation.
- The Change-safe operator derives a stable plan ID from the tenant/profile
  deployment namespace, fixed contract and caller idempotency key. The private
  plan binds operator, contract/policy digests, normalized parameter digest,
  target fingerprint, precondition digest, Permission Impact Preview and
  expiry; requested/previous M365 values are not written into approval files.
- External approval uses a separate Ed25519 trust anchor and owner-only broker
  directory. Runtime consumes a verified approval once in a deployment-bound
  SQLite replay ledger after TOCTOU validation and before the Graph write.
  Expired, tampered, replayed or cross-plan artifacts fail closed.
- The non-write preview path completes preflight and impact calculation, calls
  no write endpoint and explicitly denies that it is a provider simulation.
- `entra.user.operational_profile.update` accepts only `department`,
  `jobTitle`, and `officeLocation`. It rejects guests, synchronized users,
  protected users, active/eligible directory-role principals and members of
  role-assignable groups.
- The T1 handler repeats manifest, policy, tenant, target, source-of-authority,
  privilege and current-value checks immediately before PATCH to prevent
  time-of-check/time-of-use substitution.
- Public receipts and change records are metadata-only. Previous/requested
  profile values are written only to a tenant-local encrypted recovery capsule
  whose key material is kept in the OS Keychain.
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
- No current runtime DELETE is implemented. `object_delete` is permanently
  prohibited. A future `relationship_remove` may use DELETE only through a
  compiled exact path ending literally in `/$ref`.
- Every tool logs an attempt and result metadata correlated by operation ID.

### Contract and supply-chain assurance

- The tenant-neutral manifest and signature are packaged separately and
  verified against a pinned Ed25519 public key before server construction.
- The deterministic build compiler emits internal definitions, a permission
  matrix, per-contract SHA-256 digests, contract assertions, provenance and a
  CycloneDX 1.6 SBOM.
- CI runs the compiler in `--check` mode. A manifest or generated-artifact
  change without an updated valid signature fails closed.
- The closed semantic effect vocabulary distinguishes reads, object creation,
  property updates, state transitions, relationship addition/removal, action
  invocation and prohibited object deletion. Unknown effects, Graph beta,
  unsafe path segments and invalid method/effect combinations fail closed.
- Only `relationship_remove` may declare DELETE; percent encoding, traversal,
  placeholders or caller input cannot alter its required literal `/$ref`
  suffix. No tool input can supply a URL, method, query, raw body, scope,
  header, API version or suffix.
- Tenant Governance policies use an external Ed25519 trust anchor and
  owner-only files. Runtime re-reads and verifies policy and manifest before
  the write, and rejects any digest change after preflight.
- The optional exact-plan approver is an independent external authority.
  `m365-approval` can create encrypted signing material and sign/verify private
  plan requests, but it cannot call Graph, edit Governance or grant consent.
- The MCP has no auto-update, dynamic tool registration, dynamic consent,
  arbitrary Graph proxy, or learned policy mutation path.

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
- Assurance snapshots remain sensitive encrypted evidence. Compromise of both
  the owner-only file and its Keychain material exposes normalized tenant
  configuration; loss or rotation of that material requires a newly reviewed
  and signed baseline.
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

## Security roadmap boundary

The [official implementation roadmap](docs/ROADMAP.md) records planned
Secure Operations, Assurance and Change-safe workflows. The binding
[legacy-write freeze](docs/SECURE_OPERATIONS.md#binding-legacy-write-freeze)
prohibits new legacy writes, expanded legacy effects and new legacy
permissions. Security/regression fixes remain permitted; useful effects must
migrate to compiled contracts and the common operator engine. Equivalent
legacy and compiled effects cannot be active together. Roadmap entries are not
active capabilities and cannot weaken the controls documented here.

Every future vertical must preserve the permanent no-go rules: no arbitrary
Graph proxy, runtime tool generation, dynamic consent, model-controlled
approval, OAuth grant, role/PIM assignment, application credential creation,
object deletion, routine device wipe, Graph beta, executable rule language,
secret-bearing LLM output, in-process auto-update, inbound webhook authority,
automatic permission widening, cross-tenant evidence reuse, remediation
authorized by untrusted content or automatic retry after an uncertain write.
New capabilities require an exact signed contract, private tenant policy,
deterministic verification and the definition-of-done gates in the roadmap.

## Vulnerability reporting

Do not include tenant data, tokens, secrets, or customer content in an issue.
Provide only sanitized reproduction steps and correlation IDs.
