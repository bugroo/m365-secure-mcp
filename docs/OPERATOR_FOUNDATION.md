# Secure Operations 1 — Operator Foundation

Operator Foundation is the common execution substrate for future T2/T3
contracts. It is implemented and tested with synthetic contracts and
ephemeral test-only keys. It does not activate a new Microsoft Graph endpoint,
permission, write tool, or production effectful playbook.

The permanent product constraints are defined by the
[project north star](PROJECT_NORTH_STAR.md).

## Authority chain

```text
signed contract manifest + Effect Model
  → signed tenant Governance v3 operational binding
  → immutable private plan
  → external exact-plan approval(s)
  → ChangeSafeOperator
  → closed provider adapter
  → durable observation and verification
  → minimized public status + private receipt evidence
```

Governance v3 is required for future effectful schema-v2 contracts. It binds
the exact contract-manifest and Effect Model digests, contract digest,
operation/effect/tier, authorization floor, resource-fence classes,
protected-object policy, async requirement, verification mode, approval
authority identities, signer groups, key IDs, and public-key fingerprints.
Governance can raise authorization but never lower a contract floor. v1 and v2
remain unchanged for existing tools; no policy is migrated or re-signed.

## T2 and T3

T2 uses one externally signed, expiring, single-use approval for an immutable
plan. T3 requires two cryptographically independent authorities, identities,
keys, and signer groups approving the identical digest. Aliased identities,
duplicate keys, missing groups, retired authorities, compromised authorities,
expiry, replay, changed parameters, changed target, or changed trusted digest
fail closed.

The code enforces different authority IDs, identity IDs, public keys,
fingerprints, and signer groups. It cannot prove that two keys are held by
different natural persons or organizational functions. That separation of
duties depends on external key custody, operator assignment, and Governance
procedures.

Approval keys and customer policies remain outside the repository. Production
runtime never generates an approval, and approval documents are not MCP tool
arguments or public output. Retired keys may verify historical pre-retirement
evidence but may not authorize execution; compromised keys are never trusted.

## Durable lifecycle

The provider-neutral state vocabulary is:

`PLANNED` → `AWAITING_APPROVAL` → `AUTHORIZED` → `EXECUTING` →
`EXECUTED_ACCEPTED` → `OBSERVING` → `EXECUTED_VERIFIED` → `COMPLETED`

Explicit failure states are `EXECUTED_UNCERTAIN`, `TIMED_OUT`,
`FAILED_CONFIRMED`, `MANUAL_REVIEW_REQUIRED`, and `COMPENSATION_REQUIRED`.

- provider acceptance is not verification;
- observation handles are opaque and polling limits are part of the signed
  plan;
- `EXECUTING` recovered after a crash becomes uncertain instead of repeating
  the effect;
- a post-commit transport ambiguity requires manual review;
- only a confirmed pre-commit failure can be considered for a new plan;
- cancellation is attempted only when a provider adapter explicitly supports
  it and confirms the non-effect;
- SQLite state is owner-only and fenced to one deployment namespace.

## Effectful playbooks

The future schema-v2 playbook model uses a closed node and executor registry:
preflight, plan, approval, write, observe, verify, checkpoint, manual handoff,
and explicit compensation proposal. It contains no expression language,
Python, CEL, JMESPath, dynamic tool lookup, or caller-selected Graph request.

A durable DAG pins playbook, contract-manifest, Effect Model, policy, plan, and
contract digests. It advances one deterministic node at a time. A node
interrupted while running or returning uncertainty pauses the entire DAG.
Completed nodes do not run twice. Changed trusted digests require a new plan.
Compensation is a separately authorized future operation, never implicit
rollback.

The production signed playbook manifest remains schema v1 and read-only. The
effectful schema is exercised only by signed synthetic fixtures until a future
reviewed manifest and external signing operation activate a workload.

## Public metadata and privacy

Canonical contract semantics project MCP annotations and stable experience
metadata: effect, tier, approval, async behavior, reversibility, verification,
maturity, privacy class, and terminal states. Annotations are informational;
Governance and runtime enforce security.

Public progress contains status plus opaque operation, observation, and
evidence references. Tenant IDs, target IDs, parameters, operator IDs,
signers, approval material, rationale, and customer data remain private.

## Definition of Done for a stable T2/T3 operation

A future operation cannot be `stable` without all of the following:

- official Microsoft Graph v1.0 fixed endpoint and method;
- least-privileged delegated permission, minimum role, and licensing
  prerequisite;
- explicit semantic effect, tier, and authorization mode;
- exact tenant/profile/resource fences and protected-object exclusions;
- idempotency and TOCTOU analyses;
- verification and asynchronous-completion semantics;
- ambiguous-result and no-retry behavior;
- compensation/manual rollback analysis;
- minimized public projection and tenant-local private evidence;
- unit, adversarial, recorded, and live lab tests;
- agent-facing evaluation, documentation, and rollback instructions.

Identity, Intune, Defender, Conditional Access, Posture runtime, contributor
scaffolding, Registry publication, Docker distribution, and contract packs are
later programs.
