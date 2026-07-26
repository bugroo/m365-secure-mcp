# Tool catalog and exposure model

The source defines 72 fixed-contract tools. A maximally enabled read process
exposes 60; a write process exposes the two common tools plus only its selected
write actions. The default process exposes only the two common tools.

## Common

- `m365_get_security_posture`
- `m365_get_my_profile`

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

## OneDrive, SharePoint, and Excel

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
- `m365_list_workbook_worksheets`
- `m365_list_workbook_tables`

Download redirects, arbitrary paths, workbook cells, and formulas are not
exposed. SharePoint operations require a site allowlist.

## Contacts, people, presence, and directory

- `m365_search_contacts`
- `m365_list_contact_folders`
- `m365_create_contact` (write)
- `m365_list_relevant_people`
- `m365_get_my_presence`
- `m365_list_users`
- `m365_get_user`

Directory tools use the constrained `User.ReadBasic.All` permission instead of
`Directory.Read.All`.

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
exposed.

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

Teams, chats, and groups use separate resource allowlists.

## OneNote

- `m365_list_onenote_notebooks`
- `m365_list_onenote_sections`
- `m365_list_onenote_pages`

Only metadata is exposed; page HTML is not downloaded.

## Privileged administration and security

- `m365_get_organization`
- `m365_list_security_incidents`
- `m365_list_security_alerts`
- `m365_list_signins`
- `m365_list_directory_audits`
- `m365_list_managed_devices`
- `m365_list_device_compliance_policies`
- `m365_list_device_configurations`
- `m365_list_service_health`
- `m365_list_service_issues`
- `m365_list_service_messages`

These tools require both their module and
`M365_PRIVILEGED_MODULES_ENABLED=true`. Microsoft admin consent, licensing, and
the signed-in user's RBAC roles remain authoritative.

## Exact selection

To expose only three tools from otherwise enabled modules:

```dotenv
M365_MODULES=profile,mail,calendar,files
M365_ENABLED_TOOLS=m365_search_mail,m365_list_calendar,m365_search_files
```

`m365_get_security_posture` always remains visible. An allowlisted tool outside
the active profile causes a startup error.
