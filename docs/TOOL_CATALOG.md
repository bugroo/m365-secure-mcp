# Tool catalog and exposure model

Microsoft Graph is the primary product surface. Planner is one workload in the
catalog, not a separate architectural boundary or the project's central use
case.

The source defines 130 fixed tools; the build plane compiles nine Entra
Governance/Assurance contracts and one signed T0 playbook while the remaining
static catalog is migrated incrementally. A maximally enabled read process
exposes 102 tools: 93 Microsoft Graph reads, 8 Power BI reads, plus the local
security-posture tool. A write
process exposes the two common tools, the local receipt query, and only its
selected write actions. The default process exposes only the two common tools.

This catalog, the [compiled contract matrix](CONTRACT_MATRIX.md), and the
[compiled playbook matrix](PLAYBOOK_MATRIX.md) describe the active surface.
Items in the [official implementation roadmap](ROADMAP.md) are planned only; a
roadmap name is never a runtime-discovered or dynamically registered tool.

## Identity schema-2.0 candidates

Five Identity contracts are compiled and reviewed as inactive `candidate`
artifacts:

- `entra.user.sessions.revoke`
- `entra.user.account_state.set`
- `entra.group.user_membership.add`
- `entra.group.user_membership.remove`
- `entra.user.direct_license.set`

They do not appear in `--list-tools`, are not registered by the MCP server and
cannot execute Graph. Their public review surface is the
[candidate matrix](IDENTITY_CANDIDATE_MATRIX.md). Activation requires the
independent production contract-signing ceremony and an atomic reviewed
cutover. README examples and active counts therefore continue to exclude them.

Secure Operations 1 adds internal Operator Foundation schemas, state machines,
signed synthetic fixtures and metadata only. It adds no MCP tool and activates
no Graph operation. Future T2/T3 tools must satisfy the
[Operator Foundation Definition of Done](OPERATOR_FOUNDATION.md#definition-of-done-for-a-stable-t2t3-operation).

## Legacy-write freeze

The 27 current write registrations are frozen compatibility surfaces. No new
legacy write, parameter/effect expansion or Graph permission may be added;
only security and regression fixes are permitted. Useful effects must migrate
to signed compiled contracts and the common `ChangeSafeOperator`. A legacy
tool and its compiled equivalent may never be enabled together for the same
effect, and a legacy receipt is not a governed Change-safe operation record.

The complete binding rule and disposition of all 27 writes are maintained in
[Secure Operations](SECURE_OPERATIONS.md#legacy-write-inventory). No tool is
removed from the runtime by this documentation milestone.

## Common

- `m365_get_security_posture`
- `m365_get_my_profile`

## Local write evidence

- `m365_get_write_operation` (read-only, write profile)

This tool retrieves one metadata-only receipt by operation ID or by the exact
write-tool/idempotency-key pair. It cannot enumerate the ledger and never calls
Microsoft Graph.

## Mail

- `m365_search_mail`
- `m365_get_mail_message`
- `m365_list_mail_folders`
- `m365_list_mail_attachment_metadata`
- `m365_create_mail_draft` (write)
- `m365_send_mail_draft` (write)

Attachments are metadata-only and are never executed.

## Calendar

- `m365_list_calendar`
- `m365_find_schedule`
- `m365_list_calendars`
- `m365_get_calendar_event`
- `m365_create_calendar_event` (write)
- `m365_update_calendar_event` (write)

## OneDrive and selected SharePoint

- `m365_search_files`
- `m365_get_file_metadata`
- `m365_list_onedrive_root`
- `m365_list_recent_files`
- `m365_list_shared_files`
- `m365_list_file_children`
- `m365_list_allowed_sites`
- `m365_list_site_lists`
- `m365_list_site_list_items`
- `m365_list_site_drives`
- `m365_list_site_pages`
- `m365_list_workbook_tables`

SharePoint operations require a site allowlist. OneDrive search returns drive
IDs so Office items can be placed in a separate write/read allowlist.

## Word, PowerPoint, Excel, and OneNote content

- `m365_get_word_document_text`
- `m365_get_powerpoint_presentation_text`
- `m365_list_workbook_worksheets`
- `m365_get_workbook_range`
- `m365_get_onenote_page_text`
- `m365_replace_word_text` (write)
- `m365_replace_powerpoint_text` (write)
- `m365_update_excel_range` (write)
- `m365_append_onenote_page_text` (write)

Word and PowerPoint accept only exact drive/item allowlists and macro-free OOXML
within configured compressed/expanded limits. Package traversal, duplicate or
encrypted members, entities, macros, ActiveX and embedded OLE are rejected.
Writes use `If-Match`. Excel accepts bounded A1 ranges and literal values only;
formula-trigger strings beginning with `=`, `+`, `-`, or `@` are rejected.
OneNote content is converted to plain text, and appends escape the supplied text
before Graph receives HTML.

## Contacts, people, presence, and directory

- `m365_search_contacts`
- `m365_list_contact_folders`
- `m365_create_contact` (write)
- `m365_list_relevant_people`
- `m365_get_my_presence`
- `m365_list_users`
- `m365_get_user`
- `m365_list_allowed_users`
- `m365_get_allowed_user`
- `m365_list_allowed_directory_devices`
- `m365_get_directory_device`
- `m365_update_entra_user_operational_profile` (governed T1 write)
- `m365_set_directory_user_account_enabled` (write)

Directory tools use the constrained `User.ReadBasic.All` permission instead of
`Directory.Read.All`. Administrative user/device tools use exact UUID
allowlists. The compiled operational-profile contract can change only
`department`, `jobTitle`, and `officeLocation` on a cloud-managed,
non-privileged Member user. It requires a signed tenant policy and the
least-privileged write permission `User.ReadUpdate.All`; role and
role-assignable-group reads are preconditions, not write capabilities.
Passwords, authentication methods, identities, account state, phones,
licenses and custom security attributes are absent.

The compiled T1 handler uses the reusable Change-safe operator engine.
`standing_policy` remains prompt-free. Its complete internal preflight-only
path produces a Permission Impact Preview without calling PATCH and never
claims to simulate Graph. Plan expiry, signed write windows, immutable target
fences, operator identity, contract/policy digests and current resource
preconditions are rechecked immediately before effect.

If signed Governance raises the authorization floor to `explicit_plan`,
runtime accepts only a single-use Ed25519 artifact created by an external
host/broker over the exact private plan. The artifact is never a tool argument;
the tool schema still contains only the three optional profile fields, target
UUID and idempotency key. An approval is consumed after TOCTOU validation and
before PATCH. A replay, stale binding or changed precondition fails closed.

## To Do and Planner

- `m365_list_todo_lists`
- `m365_list_todo_tasks`
- `m365_get_todo_task`
- `m365_list_allowed_plans`
- `m365_list_planner_tasks`
- `m365_list_planner_buckets`
- `m365_get_planner_task`
- `m365_list_my_planner_tasks`
- `m365_create_planner_task` (write)
- `m365_update_planner_task` (write)
- `m365_update_planner_task_details` (write)
- `m365_create_todo_task` (write)
- `m365_update_todo_task` (write)

Planner results are restricted to locally allowlisted plans. Updates require an
ETag. Task-details writes use their separate `details_etag`, accept description
and preview changes, add checklist items with deterministic UUIDs, and update
only checklist UUIDs verified against the current task. Checklist removal,
arbitrary `null` values, references, and whole-object replacement are not
exposed. Task assignees have their own UUID allowlist and are never inferred
from the principals authorized to operate the MCP.

## Teams and groups

- `m365_get_team`
- `m365_list_team_channels`
- `m365_list_channel_members`
- `m365_list_channel_messages`
- `m365_list_allowed_chats`
- `m365_list_chat_messages`
- `m365_get_group`
- `m365_list_group_members`
- `m365_list_group_owners`
- `m365_send_channel_message` (write)
- `m365_send_chat_message` (write)
- `m365_update_directory_group` (write)
- `m365_add_user_to_group` (write)

Teams, chats, and groups use separate resource allowlists. Every group write
requires Graph to explicitly confirm `isAssignableToRole=false`; role-assignable
or unclassified groups fail closed before a PATCH or membership POST.

## OneNote

- `m365_list_onenote_notebooks`
- `m365_list_onenote_sections`
- `m365_list_onenote_pages`

This module is metadata-only. Page content is a separate allowlisted module.

## Privileged administration and security

- `m365_get_organization`
- `m365_list_security_incidents`
- `m365_list_security_alerts`
- `m365_list_signins`
- `m365_list_directory_audits`
- `m365_list_managed_devices`
- `m365_list_device_compliance_policies`
- `m365_list_device_configurations`
- `m365_list_allowed_cloudpcs`
- `m365_get_cloudpc`
- `m365_sync_managed_device` (write)
- `m365_reboot_cloudpc` (write)
- `m365_list_service_health`
- `m365_list_service_issues`
- `m365_list_service_messages`
- `m365_list_allowed_applications`
- `m365_get_application`
- `m365_list_application_owners`
- `m365_list_allowed_service_principals`
- `m365_get_service_principal`
- `m365_list_service_principal_owners`
- `m365_list_service_principal_app_role_assignments`
- `m365_list_service_principal_delegated_grants`
- `m365_list_conditional_access_policies`
- `m365_list_directory_role_definitions`
- `m365_list_directory_role_assignments`
- `m365_list_access_review_definitions`
- `m365_list_entitlement_catalogs`
- `m365_list_subscribed_skus`
- `m365_list_domains`

These tools require both their module and
`M365_PRIVILEGED_MODULES_ENABLED=true`. Microsoft admin consent, licensing, and
the signed-in user's RBAC roles remain authoritative. Application and service
principal results are narrowed by separate local UUID allowlists.

## Entra Assurance

- `m365_get_entra_identity_governance_posture`
- `m365_get_entra_permission_grant_drift`
- `m365_get_entra_profile_debt_posture`
- `m365_get_entra_app_credential_posture`
- `m365_get_entra_workload_identity_readiness`

This compiled T0 tool is a fixed, read-only workflow over Conditional Access,
permanent directory-role assignments, active PIM assignments and PIM
eligibilities. It requires the `assurance` module, the privileged-module gate,
an active signed `privileged-read` Governance profile, `Policy.Read.All`,
`RoleManagement.Read.Directory`, and a `Global Reader` operator.

It accepts only `response_format`; tenant, Graph path, method, filters, approval
and resource IDs are not inputs. The operation returns no policy/principal IDs,
names or conditions. It emits counts, findings, complete-coverage evidence and
deployment-keyed HMAC digests. Full normalized values are stored only in an
encrypted, owner-only tenant-local snapshot with no MCP retrieval tool.

The optional drift baseline is part of the signed private Governance policy.
Baseline promotion and exceptions are operator actions outside runtime.
Exceptions are control/domain-specific and expiring. A pagination loop, record
or byte overflow, unknown state, malformed page, or policy change rejects the
whole snapshot rather than reporting partial posture. The tool has no
remediation path and performs no Graph write.

The permission-grant drift tool is a separate fixed T0 workflow. It accepts
only `response_format` and scans service principals present in both the signed
Governance baseline and `M365_ALLOWED_SERVICE_PRINCIPAL_IDS`. It requires
`Directory.Read.All` plus a supported read role such as `Directory Readers` or
`Global Reader`; consent and role assignment remain manual Entra actions.

For each signed target it reads `/oauth2PermissionGrants`, the target's
`appRoleAssignments`, and the referenced resource service-principal catalogs.
Expected delegated scopes are derived from exact compiled contract IDs plus
the runtime base `User.Read`. Extra delegated grants, app-only permissions,
missing expected scopes and consent-type mismatches become deterministic
findings. Runtime never changes grants or promotes a baseline.

MCP output contains public permission values and opaque keyed references, not
tenant, service-principal, grant, resource or principal IDs. Complete raw
evidence is encrypted in the same owner-only tenant-local Assurance store.
Coverage is explicitly limited to the signed target set and fails closed on
pagination, shape, size, policy or resource-fence ambiguity.

Profile debt is a separate fixed T0 contract that composes the current App
Registration's permission-grant evidence with validated token scope names,
the active signed profile contract closure, policy lifecycle, bounded
metadata-only audit evidence and local/Governance resource fences. It accepts
no scope, resource ID, tenant, URL, method or remediation parameter.

The signed `profile_debt_baseline` owns severity, policy-version/age
thresholds, the evidence window, persistent-failure threshold and exact
expiring exceptions. Missing or unsafe audit evidence and a current app absent
from the permission baseline are `not_evaluated`, never silently aligned.
Public output contains public permission/contract names, counts and opaque
HMAC references. Private IDs are stored only inside the encrypted
tenant-specific snapshot. No grant, consent, policy, allowlist or baseline can
be changed by this tool.

Application credential posture is a third fixed T0 workflow. It uses
`Application.Read.All` to read only application object IDs present in both a
signed `application_credential_baseline` and the local
`M365_ALLOWED_APPLICATION_IDS` fence, plus each target's complete owner
collection. It never lists the tenant and accepts no target ID from MCP.

The signed baseline sets the minimum owner count, expiry warning window,
whether password credentials are allowed, and maximum active password/key
credential counts per application. Findings cover owner shortage, expired,
expiring or unbounded credentials, invalid validity windows, prohibited
secrets and redundant active credentials. Exceptions are signed and expiring;
credential exceptions bind the exact kind and credential key ID.

Graph's opt-in `$select=keyCredentials` path can include public key data, so
this workflow deliberately does not use it. Runtime discards names, hints,
thumbprints and credential material, and fails closed if Graph unexpectedly
returns `key` or `secretText`. MCP output contains only counts, findings and
opaque HMAC references. The encrypted snapshot contains normalized IDs and
validity metadata only. Credential rotation, removal and owner changes are
absent.

Workload Identity Readiness is a separately signed, fixed T0 playbook. Its
acyclic build-time DAG invokes exactly the permission-grant drift and
application-credential posture contracts. It introduces no Graph call or
permission beyond their exact closure:
`Application.Read.All` and `Directory.Read.All`, plus the common runtime
`User.Read`.

The active signed `privileged-read` profile must enable the playbook and both
child contracts, pin the current playbook-manifest digest, and configure both
signed baselines. Applications and service principals must pass their separate
local and Governance allowlists. There is no approval parameter or per-call
dialog under `automatic_read`.

The workflow correlates both evidence streams through an opaque,
deployment-keyed workload reference. A combined excess-permission and
credential/ownership weakness is classified deterministically. If a node is
incomplete, the policy changes mid-run, or an application/service-principal
mapping is unavailable, the playbook halts or marks the affected target
`not_evaluated`; it never claims complete coverage from partial evidence.
Detailed IDs remain in the two encrypted tenant-local snapshots. The playbook
has no write, remediation, consent, owner-management or credential-management
path.

## Microsoft Purview compliance

- `m365_list_allowed_ediscovery_cases`
- `m365_get_ediscovery_case`
- `m365_list_allowed_retention_labels`
- `m365_get_retention_label`

Compliance is a privileged read-only module. eDiscovery cases and retention
labels have independent UUID allowlists. The list tools filter Graph output
locally; the get tools reject non-allowlisted IDs before network access.
eDiscovery case content, searches, holds, exports, case mutation, retention
label assignment/mutation, and every compliance delete action are absent.
Microsoft Purview RBAC and licensing remain authoritative in addition to admin
consent.

## Power BI

- `m365_list_allowed_powerbi_workspaces`
- `m365_list_powerbi_reports`
- `m365_get_powerbi_report`
- `m365_list_powerbi_datasets`
- `m365_get_powerbi_dataset`
- `m365_list_powerbi_dataset_refreshes`
- `m365_list_powerbi_dataset_datasources`
- `m365_list_powerbi_dashboards`
- `m365_refresh_powerbi_dataset` (write)
- `m365_rebind_powerbi_report` (write)

Power BI uses its own OAuth audience and token. Workspace, report, dataset and
dashboard allowlists are independent. Datasource connection details are
removed from output. Refresh/rebind also require the privileged-write gate,
idempotency ledger, local rate limit and client approval.

## Privileged administration writes

- `m365_update_entra_application` (write)
- `m365_update_entra_service_principal` (write)
- `m365_update_conditional_access_policy` (write)
- `m365_set_directory_user_account_enabled` (write)
- `m365_add_user_to_group` (write)
- `m365_sync_managed_device` (write)
- `m365_reboot_cloudpc` (write)
- `m365_refresh_powerbi_dataset` (write)
- `m365_rebind_powerbi_report` (write)

These require the write profile, global write gate, privileged-write gate,
exact action, exact resource allowlist, delegated Entra consent/RBAC, UUID
idempotency key, and MCP-client approval. Each tool sends a closed PATCH and
then reads the target back to verify the requested fields.

The application tool can change only `displayName` and
`groupMembershipClaims`. The service-principal tool can change only
`displayName`, `accountEnabled`, and `appRoleAssignmentRequired`. The
Conditional Access tool can change only `displayName` and `state`.
Credential, consent, owner, role, policy-condition, license, and object-delete
surfaces are absent. No current runtime DELETE exists. A future relationship
removal must be an exact compiled `relationship_remove` path ending in
`/$ref`; it cannot be added to this legacy surface.

In particular, there is no tool for required-resource permissions, OAuth
grants, admin consent, app-role assignments, directory-role assignments or PIM
activation. The administrator must configure those outside the MCP.

## Exact selection

To expose only three tools from otherwise enabled modules:

```dotenv
M365_MODULES=profile,mail,calendar,files
M365_ENABLED_TOOLS=m365_search_mail,m365_list_calendar,m365_search_files
```

`m365_get_security_posture` always remains visible. An allowlisted tool outside
the active profile causes a startup error.

## Result contract

All tools advertise the same versioned output schema. Text content remains
available for compatibility; structured content includes `ok`, `tool`,
`operation_id`, `error`, `retry`, and `evidence`. Execution failures set MCP
`isError=true`. Successful writes attach their durable receipt.
