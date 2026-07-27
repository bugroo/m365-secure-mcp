# Compiled playbook matrix

Generated from the signed, tenant-neutral playbook manifest.

| Playbook | Tool | Nodes | Tier | Authorization | Permission closure |
|---|---|---|---|---|---|
| `entra.workload_identity.readiness.playbook` | `m365_get_entra_workload_identity_readiness` | `application_credentials` → `entra.app_credentials.posture.snapshot`<br>`permission_grants` → `entra.permission_grants.drift.snapshot` | `T0` | `automatic_read` | `Application.Read.All`<br>`Directory.Read.All` |

The permission closure is the exact union of referenced compiled
contracts. Playbooks cannot add scopes, Graph calls, or runtime tools.
