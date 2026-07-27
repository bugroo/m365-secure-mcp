# Compiled posture control matrix

Generated from the independently signed, tenant-neutral control manifest.
Definitions contain no customer severity, tenant selectors or executable rules.
The separate M1 freshness compatibility artifact is not signed control definition metadata. Governance v2 pins its canonical digest: `sha256:741892a8dda46b4b468c0acd9b4b5f75230b4611001d41389c15e169e67c8d60`.

| Control ID | Definition | Evaluator | Evidence dependency | Maximum evidence age | Intended result | Lifecycle |
|---|---|---|---|---|---|---|
| `entra.applications.active_credential_count` | `1.0.0` | `ENTRA_APPLICATION_ACTIVE_CREDENTIAL_COUNT_V1` | `entra.app_credentials.posture.snapshot` | `86400` seconds | `application_active_credential_counts_match_policy` | `active` |
| `entra.applications.credential_expiry_posture` | `1.0.0` | `ENTRA_APPLICATION_CREDENTIAL_EXPIRY_POSTURE_V1` | `entra.app_credentials.posture.snapshot` | `86400` seconds | `application_credentials_meet_expiry_policy` | `active` |
| `entra.applications.owner_coverage` | `1.0.0` | `ENTRA_APPLICATION_OWNER_COVERAGE_V1` | `entra.app_credentials.posture.snapshot` | `86400` seconds | `application_owner_count_meets_policy` | `active` |
| `entra.applications.password_credential_policy` | `1.0.0` | `ENTRA_APPLICATION_PASSWORD_CREDENTIAL_POLICY_V1` | `entra.app_credentials.posture.snapshot` | `86400` seconds | `application_password_credentials_match_policy` | `active` |
| `entra.applications.permission_contract_closure` | `1.0.0` | `ENTRA_APPLICATION_PERMISSION_CONTRACT_CLOSURE_V1` | `entra.permission_grants.drift.snapshot` | `86400` seconds | `application_permissions_match_compiled_contracts` | `active` |
| `entra.conditional_access.mfa_policy_coverage` | `1.0.0` | `ENTRA_CA_MFA_POLICY_COVERAGE_V1` | `entra.identity_governance.posture.snapshot` | `86400` seconds | `mfa_policy_covers_required_identities_and_resources` | `active` |
| `entra.directory_roles.permanent_active_assignment` | `1.0.0` | `ENTRA_DIRECTORY_ROLE_PERMANENT_ACTIVE_ASSIGNMENT_V1` | `entra.identity_governance.posture.snapshot` | `86400` seconds | `no_unexcepted_permanent_active_role_assignment` | `active` |
| `entra.profiles.contract_closure` | `1.0.0` | `ENTRA_PROFILE_CONTRACT_CLOSURE_V1` | `entra.profile_debt.posture.snapshot` | `86400` seconds | `active_profile_contracts_have_current_evidence` | `active` |
| `entra.profiles.resource_fence_closure` | `1.0.0` | `ENTRA_PROFILE_RESOURCE_FENCE_CLOSURE_V1` | `entra.profile_debt.posture.snapshot` | `86400` seconds | `active_profile_resource_fences_are_closed` | `active` |
| `entra.profiles.scope_closure` | `1.0.0` | `ENTRA_PROFILE_SCOPE_CLOSURE_V1` | `entra.profile_debt.posture.snapshot` | `86400` seconds | `active_profile_scopes_match_contract_closure` | `active` |

## Published framework mappings

| Mapping | Source | Reference | Relationship | Technical | Organizational |
|---|---|---|---|---|---|
| `eu.nis2.article-21-2-f` | `eu.nis2.directive-2022-2555` | Article 21(2)(f), policies and procedures to assess effectiveness | `supporting` | `partial` | `supporting` |
| `eu.nis2.article-21-2-i` | `eu.nis2.directive-2022-2555` | Article 21(2)(i), human resources security, access control and asset management | `supporting` | `partial` | `supporting` |
| `eu.nis2.article-21-2-j` | `eu.nis2.directive-2022-2555` | Article 21(2)(j), multifactor or continuous authentication where appropriate | `supporting` | `partial` | `supporting` |
| `microsoft.apps.credential-hygiene` | `microsoft.entra.app-security-20250620` | Credentials, including certificates and secrets | `direct` | `direct` | `none` |
| `microsoft.apps.least-privilege` | `microsoft.entra.app-security-20250620` | Permissions, follow least privilege principles | `direct` | `direct` | `none` |
| `microsoft.apps.owner-review` | `microsoft.entra.app-security-20250620` | App ownership configuration | `supporting` | `partial` | `supporting` |
| `microsoft.ca.mfa-all-users` | `microsoft.entra.ca-mfa-20260324` | Require multifactor authentication for all users | `direct` | `direct` | `none` |
| `microsoft.pim.zero-permanent-active` | `microsoft.entra.pim-plan-20260423` | Type of assignments, zero permanently active assignments outside emergency access | `direct` | `direct` | `none` |

Mappings express bounded evidence relationships only. They do not certify
legal, regulatory or organizational compliance. Unverified sources are not
published by the compiler.
