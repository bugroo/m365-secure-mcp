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

## 2. Add only required delegated Graph permissions

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
| Group metadata/membership | `GroupMember.Read.All` |
| Organization metadata | `Organization.Read.All` |
| OneNote | `Notes.Read` |
| Relevant people | `People.Read` |
| Own presence | `Presence.Read` |
| Defender incidents | `SecurityIncident.Read.All` |
| Defender alerts | `SecurityAlert.Read.All` |
| Entra sign-in/directory audit | `AuditLog.Read.All` |
| Intune managed devices | `DeviceManagementManagedDevices.Read.All` |
| Intune configuration/compliance | `DeviceManagementConfiguration.Read.All` |
| Microsoft 365 service health | `ServiceHealth.Read.All` |
| Entra applications/service principals | `Application.Read.All` |
| Service-principal delegated grants | `Directory.Read.All` |
| Conditional Access read | `Policy.Read.All` |
| Directory role definitions/assignments | `RoleManagement.Read.Directory` |
| Access reviews | `AccessReview.Read.All` |
| Entitlement catalogs | `EntitlementManagement.Read.All` |
| License inventory | `LicenseAssignment.Read.All` |
| Tenant domains | `Domain.Read.All` |
| Mail draft | `Mail.ReadWrite` |
| Send existing draft | `Mail.ReadWrite`, `Mail.Send` |
| Calendar create | `Calendars.ReadWrite` |
| Calendar update | `Calendars.ReadWrite` |
| Contact create | `Contacts.ReadWrite` |
| To Do create/update | `Tasks.ReadWrite` |
| Send Teams channel message | `ChannelMessage.Send` |
| Send Teams chat message | `ChatMessage.Send` |
| Planner task and task-details create/update | `Tasks.ReadWrite` |
| Entra application/service-principal update | `Application.ReadWrite.All` |
| Conditional Access state/name update | `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess` |

Teams scopes are broad/admin-restricted. Keep the Teams module disabled unless
there is a specific approved use case.

Organization, Defender, audit, Intune, service health, Entra applications,
governance, licensing, and domain permissions are administrative or
tenant-wide. They are blocked locally unless
`M365_PRIVILEGED_MODULES_ENABLED=true`. Administrative write actions also
require `M365_PRIVILEGED_WRITES_ENABLED=true`. Admin consent and the signed-in
user's Microsoft 365/Entra roles still apply; the MCP never bypasses Graph
RBAC.

For `Sites.Selected`, an administrator must additionally grant the application
access to each approved site. Configure the same site IDs and hostnames in the
local MCP allowlists.

## 3. Prefer separate app registrations

For a high-security deployment, create up to four registrations:

- `M365 Secure MCP Routine Read` with user-work permissions only.
- `M365 Secure MCP Routine Write` with only routine write permissions.
- `M365 Secure MCP Privileged Read` with selected administrative read scopes.
- `M365 Secure MCP Privileged Write` with one selected administrative write
  scope and restricted user assignment.

Use each app's client ID only in the corresponding MCP entry. This preserves
the read/write boundary even if environment configuration is changed.

Never add a permission merely because it appears in this table. Run
`--explain-permissions` for each private policy and grant only its reported
scopes. In particular, `Directory.Read.All` is needed only for the delegated
grant tool, not for general Entra application inventory.

## 4. Consent

Use tenant policy to determine whether user consent is allowed. Admin consent
may be required for broad organizational scopes. Never grant a permission only
to suppress an error; map it to an enabled tool first.

## 5. Conditional Access

Recommended:

- phishing-resistant MFA;
- compliant or managed device;
- sign-in risk policy;
- block device-code flow unless a documented exception exists;
- restrict the enterprise application to the intended users/groups.
