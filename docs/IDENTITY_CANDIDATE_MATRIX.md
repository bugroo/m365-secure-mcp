# Identity Slice candidate contract matrix

Generated from the unsigned schema-2.0 candidate manifest. These contracts are **not active MCP tools** and cannot execute Graph.

| Contract | Lifecycle | Effect | Graph call | Tier | Authorization | Role | Delegated scopes | Verification |
|---|---|---|---|---|---|---|---|---|
| `entra.user.sessions.revoke` | `candidate` | `invoke_action` | `POST /users/{user_id}/revokeSignInSessions` | `T2` | `explicit_plan` | `Helpdesk Administrator` | `RoleManagement.Read.Directory`<br>`User.Read.All`<br>`User.RevokeSessions.All` | `provider_acknowledged` |
| `entra.user.account_state.set` | `candidate` | `state_transition` | `PATCH /users/{user_id}` | `T2` | `explicit_plan` | `User Administrator` | `RoleManagement.Read.Directory`<br>`User.EnableDisableAccount.All`<br>`User.Read.All` | `strong_readback` |
| `entra.group.user_membership.add` | `candidate` | `relationship_add` | `POST /groups/{group_id}/members/$ref` | `T2` | `explicit_plan` | `Groups Administrator` | `GroupMember.ReadWrite.All`<br>`RoleManagement.Read.Directory`<br>`User.Read.All` | `strong_readback` |
| `entra.group.user_membership.remove` | `candidate` | `relationship_remove` | `DELETE /groups/{group_id}/members/{user_id}/$ref` | `T2` | `explicit_plan` | `Groups Administrator` | `GroupMember.ReadWrite.All`<br>`RoleManagement.Read.Directory`<br>`User.Read.All` | `strong_readback` |
| `entra.user.direct_license.set` | `candidate` | `state_transition` | `POST /users/{user_id}/assignLicense` | `T2` | `explicit_plan` | `License Administrator` | `LicenseAssignment.Read.All`<br>`LicenseAssignment.ReadWrite.All`<br>`RoleManagement.Read.Directory`<br>`User.Read.All` | `strong_readback` |

Activation requires the external contract-signing direct cutover, a
current production authority, and the signature plus generated active
artifacts in one reviewed change. Test keys cannot activate candidates.
