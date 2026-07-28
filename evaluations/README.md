# Read-only MCP evaluations

These fixtures exercise stable, sanitized properties of compiled workflows.
They contain no tenant content and require no write or destructive tool.

`workload-identity-readiness.xml` covers the first signed T0 playbook. Its
answers are backed by deterministic pytest scenarios in
`tests/test_entra_workload_readiness.py`; the XML is the agent-facing
evaluation set, while pytest remains the authoritative security gate.

`change-safe-operator.xml` covers the reusable write engine: low-friction
standing policy, exact external approval, single-use consumption, TOCTOU,
preflight-only behavior and uncertain-write handling. Its executable scenarios
live in `tests/test_entra_operational_profile.py`.

`profile-debt-posture.xml` covers signed customer severity, explicit partial
coverage, token/grant/profile correlation, bounded audit evidence, output
privacy and the prohibition on consent/policy/allowlist remediation. Its
executable scenarios live in `tests/test_entra_profile_debt.py`.

Live-tenant evaluations are intentionally not committed because tenant
inventory and posture are neither public nor stationary. They belong in a
dedicated non-production tenant and must remain read-only.

`operator-foundation-adversarial.json` is a deterministic, synthetic security
suite for exact-plan approval, dual control, replay, expiry, digest drift,
accepted-versus-verified async semantics, uncertainty, prompt injection and
public-output privacy. Each scenario references its executable pytest case.
It contains no model score, tenant data or customer policy.
