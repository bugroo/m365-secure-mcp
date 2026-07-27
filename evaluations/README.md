# Read-only MCP evaluations

These fixtures exercise stable, sanitized properties of compiled workflows.
They contain no tenant content and require no write or destructive tool.

`workload-identity-readiness.xml` covers the first signed T0 playbook. Its
answers are backed by deterministic pytest scenarios in
`tests/test_entra_workload_readiness.py`; the XML is the agent-facing
evaluation set, while pytest remains the authoritative security gate.

Live-tenant evaluations are intentionally not committed because tenant
inventory and posture are neither public nor stationary. They belong in a
dedicated non-production tenant and must remain read-only.
