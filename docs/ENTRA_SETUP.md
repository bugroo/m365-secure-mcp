# Microsoft Entra setup

## 1. Create a single-tenant public client

In Microsoft Entra admin center:

1. Open **App registrations → New registration**.
2. Choose **Accounts in this organizational directory only**.
3. Record the application/client ID and directory/tenant ID.
4. Under **Authentication → Add a platform**, select **Mobile and desktop
   applications**.
5. Add `http://localhost` as the redirect URI.
6. Enable public client flows only because this is deliberately a desktop
   public client.
7. Do not create a client secret.
8. Do not use **Expose an API** for the local stdio server.

MSAL Python automatically protects interactive acquisition with PKCE.

## 2. Add and admin-consent only the required delegated permissions

Start with `User.Read`. Add modules independently:

| Feature | Permission |
|---|---|
| Mail read | `Mail.Read` |
| Calendar read/free-busy | `Calendars.Read` |
| OneDrive read | `Files.Read` |
| Selected SharePoint sites | `Sites.Selected` |
| Personal contacts | `Contacts.Read` |
| To Do read | `Tasks.Read` |
| Planner read | `Tasks.Read` |
| Team metadata | `Team.ReadBasic.All` |
| Team channel metadata | `Channel.ReadBasic.All` |
| Channel members | `ChannelMember.Read.All` |
| Teams channel messages | `ChannelMessage.Read.All` |
| Teams chat metadata | `Chat.ReadBasic` |
| Teams chat messages | `Chat.Read` |
| Basic directory users | `User.ReadBasic.All` |
| Allowlisted administrative user profiles | `User.Read.All` |
| Group metadata/membership | `GroupMember.Read.All` |
| Entra devices | `Device.Read.All` |
| Organization metadata | `Organization.Read.All` |
| OneNote | `Notes.Read` |
| OneNote content append | `Notes.ReadWrite` |
| Word/PowerPoint read | `Files.Read` |
| Word/PowerPoint replace, Excel range read/write | `Files.ReadWrite` |
| Relevant people | `People.Read` |
| Own presence | `Presence.Read` |
| Defender incidents | `SecurityIncident.Read.All` |
| Defender alerts | `SecurityAlert.Read.All` |
| Entra sign-in/directory audit | `AuditLog.Read.All` |
| Intune managed devices | `DeviceManagementManagedDevices.Read.All` |
| Intune configuration/compliance | `DeviceManagementConfiguration.Read.All` |
| Intune device sync | `DeviceManagementManagedDevices.PrivilegedOperations.All` |
| Windows 365 inventory | `CloudPC.Read.All` |
| Windows 365 reboot | `CloudPC.ReadWrite.All` |
| Microsoft 365 service health | `ServiceHealth.Read.All` |
| Entra applications/service principals | `Application.Read.All` |
| Service-principal delegated grants | `Directory.Read.All` |
| Conditional Access read | `Policy.Read.All` |
| Directory role definitions/assignments | `RoleManagement.Read.Directory` |
| Compiled Entra governance posture snapshot | `Policy.Read.All`, `RoleManagement.Read.Directory` |
| Compiled Entra permission-grant drift | `Directory.Read.All` |
| Compiled Entra application credential posture | `Application.Read.All` |
| Signed Workload Identity Readiness playbook | `Application.Read.All`, `Directory.Read.All` |
| Access reviews | `AccessReview.Read.All` |
| Entitlement catalogs | `EntitlementManagement.Read.All` |
| License inventory | `LicenseAssignment.Read.All` |
| Tenant domains | `Domain.Read.All` |
| Purview eDiscovery case metadata | `eDiscovery.Read.All` |
| Purview retention-label definitions | `RecordsManagement.Read.All` |
| Mail draft | `Mail.ReadWrite` |
| Send existing draft | `Mail.ReadWrite`, `Mail.Send` |
| Calendar create | `Calendars.ReadWrite` |
| Calendar update | `Calendars.ReadWrite` |
| Contact create | `Contacts.ReadWrite` |
| To Do create/update | `Tasks.ReadWrite` |
| Send Teams channel message | `ChannelMessage.Send` |
| Send Teams chat message | `ChatMessage.Send` |
| Planner task and task-details create/update | `Tasks.ReadWrite` |
| Governed user operational-profile update | `User.ReadUpdate.All`, `RoleManagement.Read.Directory`, `GroupMember.Read.All` |
| Enable/disable allowlisted user | `User.EnableDisableAccount.All`, `User.Read.All` |
| Group metadata update | `Group.ReadWrite.All` |
| Add allowlisted user to non-role group | `GroupMember.ReadWrite.All` |
| Entra application/service-principal update | `Application.ReadWrite.All` |
| Conditional Access state/name update | `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess` |

Power BI uses a different API resource and access token:

| Power BI feature | Delegated Power BI permission |
|---|---|
| Workspaces | `Workspace.Read.All` |
| Reports | `Report.Read.All` |
| Datasets, refresh history and datasources | `Dataset.Read.All` |
| Dashboards | `Dashboard.Read.All` |
| Queue dataset refresh | `Dataset.ReadWrite.All` |
| Rebind report | `Report.ReadWrite.All` |

Power BI workspace roles and dataset Build permission remain independently
authoritative. Do not add these scopes to the Microsoft Graph permission list;
select the Power BI Service API in Entra.

Teams scopes are broad/admin-restricted. Keep the Teams module disabled unless
there is a specific approved use case.

Organization, administrative users/devices, Defender, audit, Intune, Windows
365, Power BI, service health, Entra applications, governance, licensing, and
domain and Purview compliance permissions are administrative or tenant-wide.
They are blocked locally unless `M365_PRIVILEGED_MODULES_ENABLED=true`.
Administrative write actions also require
`M365_PRIVILEGED_WRITES_ENABLED=true`. Admin consent and the signed-in user's
Microsoft 365/Entra/Purview roles still apply; the MCP never bypasses Graph or
Purview RBAC. For delegated eDiscovery reads, assign only the supported Purview
role needed by the operator; an eDiscovery Manager is narrower than an
eDiscovery Administrator.

The compiled Assurance snapshot uses one `Global Reader` operator because that
role is supported across its Conditional Access, permanent-role and PIM
readbacks. The two delegated permissions above must still be added and
admin-consented manually. The MCP does not create the app registration, add
permissions, grant consent, assign Global Reader, activate PIM or edit the
signed Governance baseline.

The separate compiled permission-grant drift process requests
`Directory.Read.All` and should use `Directory Readers` or `Global Reader`.
That scope is required by Graph to list delegated permission grants and also
covers its fixed service-principal and app-role-assignment reads. Configure
only `m365_get_entra_permission_grant_drift`, place every approved target
service-principal object ID in both the local allowlist and signed Governance,
and sign a contract-derived `permission_grant_baseline`. The MCP never creates,
updates, revokes or consents a grant.

The application credential posture process requests only
`Application.Read.All` and should use `Directory Readers` or `Global Reader`.
Configure only `m365_get_entra_app_credential_posture`, place every approved
application object ID in both `M365_ALLOWED_APPLICATION_IDS` and signed
`resources.applications`, and sign an `application_credential_baseline`.
Runtime reads those exact applications and their owner collections; it does
not enumerate the tenant. It never returns or persists application names,
secret hints, thumbprints, public keys or secret values, and has no credential
rotation or owner-assignment action.

The Workload Identity Readiness process composes those two exact contracts. It
therefore requests only their union, `Application.Read.All` and
`Directory.Read.All`, and should use `Directory Readers` or `Global Reader`.
Configure only `m365_get_entra_workload_identity_readiness`, enable the signed
playbook plus both child contracts in `privileged-read`, and configure both
local allowlists, both signed resource fences and both signed baselines. It
does not add a new Graph endpoint or permission. The administrator must add
and consent both delegated scopes manually; the MCP cannot request consent.

For `Sites.Selected`, an administrator must additionally grant the application
access to each approved site. Configure the same site IDs and hostnames in the
local MCP allowlists.

## 3. Use separate app registrations per tenant and profile

For a high-security deployment, create separate registrations for:

- `M365 Secure MCP Routine Read` with user-work permissions only.
- `M365 Secure MCP Routine Write` with only routine write permissions.
- `M365 Secure MCP Privileged Read` with selected administrative read scopes.
- `M365 Secure MCP Privileged Write` with one selected administrative write
  scope and restricted user assignment.

Repeat that pattern inside each customer tenant; do not reuse a host-tenant
policy file or token cache for a customer. Use each app's client ID only in
the corresponding MCP entry. This preserves the read/write and tenant
boundaries even if environment configuration is changed.

Never add a permission merely because it appears in this table. Run
`--explain-permissions` for each private policy and grant only its reported
scopes. In particular, `Directory.Read.All` is needed only for the delegated
grant tool, not for general Entra application inventory.

## 4. Admin consent is mandatory

Run `--explain-permissions` against the final private policy, compare its
tool-by-tool report with the app registration, then have an administrator grant
tenant consent. Runtime requests use the resource's `/.default` scope and
reject missing or unexpected permission claims by default.

The MCP has no tool or CLI command that can add API permissions, create an
OAuth grant, grant admin consent, assign an app role, change a directory role,
or activate PIM. Never add a permission only to suppress an error; map it to an
enabled tool first.

The optional Change-safe external approval broker adds no Microsoft Graph
scope, Entra role, app registration or consent. Its Ed25519 authority is local
to the host and must be separate from both the public-client registration and
the Governance signer. `standing_policy` does not require this broker;
configure it only for a signed `explicit_plan` override.

## 5. Conditional Access

Recommended:

- phishing-resistant MFA;
- compliant or managed device;
- sign-in risk policy;
- block device-code flow unless a documented exception exists;
- restrict the enterprise application to the intended users/groups.
