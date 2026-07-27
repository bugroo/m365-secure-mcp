# Compiled contract matrix

Generated from the signed, tenant-neutral global manifest.
Schema 1.0 effects are derived by the closed compiler mapping `GET → read`, `PATCH → update_properties`; ambiguous POST is rejected. Future schema 2.0 contracts must sign an explicit effect.

| Contract | Tool | Effect | Graph call | Tier | Authorization | Delegated scopes |
|---|---|---|---|---|---|---|
| `entra.organization.summary.read` | `m365_get_organization` | `read` | `GET /organization` | `T0` | `automatic_read` | `Organization.Read.All` |
| `entra.user.operational_profile.read` | `m365_get_allowed_user` | `read` | `GET /users/{user_id}` | `T0` | `automatic_read` | `User.Read.All` |
| `entra.conditional_access.policies.read` | `m365_list_conditional_access_policies` | `read` | `GET /identity/conditionalAccess/policies` | `T0` | `automatic_read` | `Policy.Read.All` |
| `entra.role_assignments.read` | `m365_list_directory_role_assignments` | `read` | `GET /roleManagement/directory/roleAssignments` | `T0` | `automatic_read` | `RoleManagement.Read.Directory` |
| `entra.identity_governance.posture.snapshot` | `m365_get_entra_identity_governance_posture` | `read` | `GET /identity/conditionalAccess/policies` | `T0` | `automatic_read` | `Policy.Read.All`<br>`RoleManagement.Read.Directory` |
| `entra.permission_grants.drift.snapshot` | `m365_get_entra_permission_grant_drift` | `read` | `GET /oauth2PermissionGrants` | `T0` | `automatic_read` | `Directory.Read.All` |
| `entra.profile_debt.posture.snapshot` | `m365_get_entra_profile_debt_posture` | `read` | `GET /oauth2PermissionGrants` | `T0` | `automatic_read` | `Directory.Read.All` |
| `entra.app_credentials.posture.snapshot` | `m365_get_entra_app_credential_posture` | `read` | `GET /applications/{application_id}` | `T0` | `automatic_read` | `Application.Read.All` |
| `entra.user.operational_profile.update` | `m365_update_entra_user_operational_profile` | `update_properties` | `PATCH /users/{user_id}` | `T1` | `standing_policy` | `GroupMember.Read.All`<br>`RoleManagement.Read.Directory`<br>`User.ReadUpdate.All` |

Permissions are informational build output. The server cannot add delegated
permissions or grant tenant consent; an administrator must do that manually.
