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
| Teams channel messages | `ChannelMessage.Read.All` |
| Teams chats | `Chat.Read` |
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
| Mail draft | `Mail.ReadWrite` |
| Send existing draft | `Mail.ReadWrite`, `Mail.Send` |
| Calendar create | `Calendars.ReadWrite` |
| Calendar update | `Calendars.ReadWrite` |
| Contact create | `Contacts.ReadWrite` |
| To Do create/update | `Tasks.ReadWrite` |
| Send Teams channel message | `ChannelMessage.Send` |
| Send Teams chat message | `ChatMessage.Send` |
| Planner create/update | `Tasks.ReadWrite` |

Teams scopes are broad/admin-restricted. Keep the Teams module disabled unless
there is a specific approved use case.

Organization, Defender, audit, Intune, and service-health permissions are
administrative or tenant-wide. They are blocked locally unless
`M365_PRIVILEGED_MODULES_ENABLED=true`. Admin consent and the signed-in user's
Microsoft 365/Entra roles still apply; the MCP never bypasses Graph RBAC.

For `Sites.Selected`, an administrator must additionally grant the application
access to each approved site. Configure the same site IDs and hostnames in the
local MCP allowlists.

## 3. Prefer separate app registrations

For a high-security deployment, create:

- `M365 Secure MCP Read` with read permissions only.
- `M365 Secure MCP Write` with only the explicitly needed write permissions.

Use each app's client ID only in the corresponding MCP entry. This preserves
the read/write boundary even if environment configuration is changed.

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
