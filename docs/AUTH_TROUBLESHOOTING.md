# Authentication troubleshooting

## AADSTS500011: resource principal not found

Meaning: the authorization request names a resource/audience that the selected
tenant cannot resolve or has not consented.

If the resource starts with `api://`, it is a custom API, not Microsoft Graph.
This commonly appears in remote MCP designs that expose their own API and then
use an On-Behalf-Of exchange to Graph.

Check:

1. The custom API app registration exists in the same tenant.
2. Its Application ID URI exactly matches the requested `api://...`.
3. The API scope exists and is enabled.
4. The client application is authorized for that scope.
5. Admin/user consent has been granted as required.
6. The authorization endpoint uses the tenant that owns the resource app.

For this project's local stdio profile, none of those custom-resource steps
should be necessary. The requested scopes should be Graph scope names such as
`User.Read` and `Mail.Read`. If an error from this server names `api://`, inspect
the MCP entry: it is probably launching a different server or using an old
OAuth configuration.

## AADSTS65001: consent required

The configured Entra app does not have consent for one or more scopes derived
from the enabled modules. Run `m365-secure-mcp --explain-permissions`, compare the
reported scopes with Entra API permissions, and consent only to the missing
scope that maps to an approved tool.

## AADSTS50011: redirect URI mismatch

For MSAL Python interactive public-client auth:

- platform type: Mobile and desktop applications;
- redirect URI: `http://localhost`;
- no web client secret is required.

## 403 from Graph

Possible causes:

- delegated permission missing or not consented;
- Conditional Access or tenant authorization policy;
- resource outside the signed-in user's access;
- SharePoint `Sites.Selected` grant missing;
- local MCP resource allowlist rejected the request.

The server returns a Graph request ID when available. Use it for tenant-side
diagnostics without copying message/file content into support tickets.
