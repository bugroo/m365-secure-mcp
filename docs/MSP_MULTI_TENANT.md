# MSP host and customer-tenant deployment

## Security position

`m365-secure-mcp` is multi-tenant by deployment, not by tool argument. One
running process belongs to one Microsoft Entra tenant, one app registration,
one operator boundary and one read or write profile.

```text
MCP entry
  └── private policy
      ├── exact tenant authority
      ├── exact client registration
      ├── exact operator object ID
      ├── compiled API audiences and scopes
      ├── resource allowlists
      ├── keychain namespace
      ├── audit namespace
      └── idempotency namespace
```

No MCP tool accepts `tenant_id`, `client_id`, scope, token, URL, method or
request header. A model therefore cannot switch from the host tenant to a
customer tenant during a call.

## Recommended topology

Create separately named entries:

| Tenant | Profile | Typical contents |
|---|---|---|
| MSP host | routine read | mail, calendar, files, Planner |
| MSP host | routine write | selected routine actions |
| MSP host | privileged read | Defender, audit, Entra, Intune |
| Customer | routine read | approved service-delivery resources |
| Customer | privileged read | signed Entra Assurance baseline and approved posture modules |
| Customer | selected write | only the change actions in the contract |

Use a customer-owned, single-tenant public-client app registration for each
customer profile whenever possible. The customer retains ownership and can
disable the enterprise application or remove consent without relying on the
MSP.

An MSP operator can use a customer-tenant identity or a delegated
administrative relationship such as GDAP, but Microsoft remains authoritative:
the operator still needs the workload/Entra role required by each API. GDAP
does not cause this MCP to acquire scopes or roles automatically.

## Manual administrator boundary

For every app/profile, the administrator must:

1. Create the single-tenant public desktop registration.
2. Add `http://localhost` as the desktop redirect URI.
3. Add only the delegated permissions printed by
   `m365-secure-mcp --explain-permissions`.
4. Grant admin consent.
5. Restrict enterprise-app assignment to approved operator users/groups.
6. Assign the least-privileged Microsoft 365, Entra, Intune, Windows 365,
   Power BI, or Microsoft Purview role needed by the enabled tools.
7. For `Sites.Selected`, grant the app access only to approved SharePoint
   sites.
8. Configure Conditional Access for the enterprise application and operators.

The server can list existing application permissions and delegated grants in
read mode. It cannot add, update or revoke:

- API permissions or required resource access;
- OAuth delegated grants or admin consent;
- app-role assignments;
- Entra directory roles or PIM eligibility/activation;
- credentials, certificates, secrets or authentication methods.

These omissions remain in force even if an administrator grants a broader
scope to the app.

## Customer policy

A customer policy must include:

```json
{
  "deployment_kind": "customer",
  "tenant_id": "<customer-tenant-guid>",
  "client_id": "<customer-app-guid>",
  "allowed_user_object_ids": "<operator-object-guid-in-customer-tenant>",
  "profile": "read",
  "modules": "profile"
}
```

The values are private deployment data and must not be committed. Export the
complete policy into an owner-only directory:

```bash
uv run m365-secure-mcp --export-policy \
  "/private/customer-a/routine-read.json"
uv run m365-secure-mcp --policy-file \
  "/private/customer-a/routine-read.json" --doctor
uv run m365-secure-mcp --policy-file \
  "/private/customer-a/routine-read.json" --explain-permissions
```

The export refuses overwrite, symlinks, foreign ownership, broad directory
permissions and unknown fields.

## Scope and resource selection

Permissions answer what the app could ask Microsoft to do. The private policy
answers what this MCP process will expose.

Use both:

- smallest app registration per profile;
- exact `M365_ENABLED_TOOLS` when a module contains more than the service
  contract needs;
- separate operator-principal, target-user and Planner-assignee allowlists;
- exact user, group, device, plan, drive, Office, OneNote, application,
  Conditional Access, Power BI, eDiscovery-case, and retention-label
  allowlists;
- a separate write process with only named `M365_WRITE_ACTIONS`;
- a signed tenant Governance policy; routine T1 may use `standing_policy`,
  while T2/T3, dual-control and break-glass flows retain hard host gates.
- one tenant-specific Assurance baseline and snapshot key; never copy a host or
  another customer's HMAC digests into this policy.

Operator-only discovery can identify candidates without editing the policy:

```bash
uv run m365-secure-mcp --policy-file "/private/customer-a/read.json" \
  --discover-resources users directory_devices managed_devices cloudpcs \
  drives planner teams groups applications service_principals \
  conditional_access powerbi_workspaces ediscovery_cases retention_labels

# After approved workspace IDs are added to the private policy:
uv run m365-secure-mcp --policy-file "/private/customer-a/read.json" \
  --discover-resources powerbi_content
```

Discovery is not an MCP tool. It prints tenant identifiers, so its output must
remain private.

## Isolation guarantees

- Token cache usernames include tenant, client, deployment kind, profile and
  API resource.
- Graph and Power BI use different access tokens and audiences.
- Customer profiles require an exact signed-in object-ID allowlist.
- Default audit and ledger paths include a hash-derived deployment namespace.
- Encrypted Assurance snapshots and their Keychain material use the same
  tenant/client/deployment/profile namespace, but a cryptographically separate
  key from audit parameter fingerprints and OAuth token caches.
- A receipt database stamped by one namespace refuses another
  tenant/profile.
- Audit records contain the namespace but not tenant IDs, resource IDs or
  Microsoft 365 content.
- The access token is checked for tenant, issuer, audience, lifetime,
  principal and exact policy scopes before use.

## Onboarding sequence

1. Design routine-read, privileged-read and only necessary write contracts.
2. Create the customer-owned registrations.
3. Export and privately review the policies.
4. Run offline doctor and permission explanation.
5. Administrator adds permissions and grants consent.
6. Administrator assigns operator and workload roles.
7. Run `--doctor live`.
8. For privileged-read Assurance, run the initial complete snapshot, review it,
   place only its keyed domain digests in the private Governance baseline and
   sign a new policy version.
9. For permission-grant drift, select service principals in both the local and
   signed allowlists, map each one to exact compiled contract IDs, then sign the
   private baseline. Use a separate privileged-read app and manual
   `Directory.Read.All` consent.
10. For application credential posture, select application object IDs in both
    the local and signed allowlists, define owner/expiry/secret/count limits,
    and sign the private baseline. Consent only `Application.Read.All`.
11. To enable Workload Identity Readiness, select both application and service
    principal targets, enable both child contracts and the signed playbook in
    `privileged-read`, pin the playbook-manifest digest, and sign the next
    policy version. Consent its exact union: `Application.Read.All` and
    `Directory.Read.All`.
12. Discover candidates and manually place approved IDs in the policy.
13. Run offline doctor again and compare the policy and manifest digests.
14. If a customer policy hardens a write to `explicit_plan`, provision a
    customer/profile-specific approval directory and Ed25519 verifier. Keep the
    approval signer outside MCP runtime and separate from Governance signing.
    Do not share its replay ledger across customers.
15. Connect named MCP entries. Allow prompt-free execution only for exact T1
    tools covered by signed `standing_policy`; keep host approval for all
    higher-risk or not-yet-compiled write contracts.

The MCP never edits the policy after discovery and never selects customer
resources on the administrator's behalf.

## Offboarding

Customer offboarding is performed in Microsoft Entra and the client
configuration:

1. Disable or delete the MCP client entry.
2. Remove enterprise-application user/group assignment.
3. Revoke admin consent or remove the customer app registration.
4. Remove GDAP/role assignments according to the MSP offboarding process.
5. Retain or dispose of the local audit/receipt files under the applicable
   retention policy.

Removing consent or roles takes effect at Microsoft even if a stale local
policy remains. Existing access tokens can remain valid until expiry, so
incident offboarding should also follow the tenant's token-revocation process.

## Planned MSP operations

Workload Identity Readiness is now implemented as a signed T0 playbook. The
[official implementation roadmap](ROADMAP.md) is the canonical plan for
profile/scope drift and the multi-tenant drift radar. These workflows retain
the topology in this document: an external orchestrator may schedule runs, but
every customer still uses an isolated single-tenant MCP process, registration,
private policy, token cache, baseline and evidence store. No implemented or
planned feature creates a central token pool or allows a tool call to select a
tenant.
