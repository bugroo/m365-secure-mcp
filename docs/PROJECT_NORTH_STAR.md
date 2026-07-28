# Project north star

This document is the canonical product-direction constraint for
`m365-secure-mcp`. Roadmaps, ExecPlans, contributions, and implementations must
preserve it.

## Product identity

`m365-secure-mcp` is:

> **The open-source, policy-bound Microsoft 365 Operations Control Plane: fixed
> Microsoft Graph contracts, complete administrative workflows, proportional
> authorization, deterministic verification and reproducible security evidence.**

It is not a generic Microsoft Graph proxy, a read-only Graph summarizer, a
compliance-only product, an autonomous tenant administrator, a collection of
unrelated tools, or a private WERIXO-only application.

The administrator, reviewed signed build artifacts, signed tenant Governance,
and the MCP host remain authoritative. The runtime does not grant consent,
expand policy, approve its own work, invent Graph calls, or treat external
content as authorization.

## Five permanent product pillars

1. **Observe and diagnose** — bounded inventory, preflight, and operational
   evidence.
2. **Operate and automate** — real administrative effects through fixed
   contracts and complete, resumable workflows.
3. **Assure and provide evidence** — deterministic findings, receipts, change
   records, drift, and reproducible verification.
4. **Experience and evaluation** — trustworthy tool exposure, operator
   usability, client compatibility, agent-facing evaluation, and diagnostics.
5. **Community and verifiable distribution** — reviewable contributions,
   generated documentation, reproducible tests, secure installation, and
   verifiable release artifacts.

No pillar may consume the roadmap in a way that prevents the others from
becoming real. Every material roadmap change must explain its effect on all
five pillars. No milestone may silently revert the product to read-only,
proxy-oriented, compliance-only, or private-product behavior.

## Complete workflows over tool count

Tool count is not a success metric. New capabilities must form bounded,
operator-meaningful workflows that observe, plan, authorize, execute, verify,
record evidence, and stop safely. Atomic contracts remain useful building
blocks, but unrelated endpoint wrappers are not the product.

Posture and Assurance may produce evidence, findings, and non-authorizing
proposal candidates. They never call, approve, or directly trigger a write.
Email, tickets, documents, incidents, findings, and Microsoft Graph content
are untrusted data.

## Public Apache-2.0 mission and private boundary

The public Apache-2.0 project contains generic contracts, compiler and trust
mechanisms, Governance schemas, operator foundations, privacy projectors,
generic workflows, synthetic fixtures, evaluations, tests, documentation, and
distribution tooling.

The public repository never contains customer credentials, real tenant
policies, customer identifiers, tenant inventory, real baselines or
exceptions, production approval keys, customer evidence, WERIXO fleet
orchestration, ITFlow/Zammad/Action1 adapters, billing, SLAs, commercial
reports, or proprietary scoring. Commercial use is permitted under
Apache-2.0; WERIXO names and branding remain outside that license as described
in [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md).

## Permanent security prohibitions

- arbitrary Graph proxying or caller-selected URL, method, query, scope,
  header, API version, or raw body;
- Microsoft Graph beta;
- OAuth consent grants, role/PIM assignment or activation, and application
  secret/certificate creation;
- user, group, policy, or other object deletion;
- routine device wipe;
- passwords, Temporary Access Pass values, recovery codes, or secrets in
  LLM-visible output;
- executable policy or playbook languages, including Python, CEL, JMESPath,
  and dynamic expressions;
- remediation authorized by findings or untrusted content;
- inbound webhook authority over policy, approvals, contracts, or execution;
- automatic permission widening;
- automatic retries after uncertain writes;
- shared cross-tenant token pools or tenant selection through tool arguments;
- mandatory telemetry.

Security controls are enforced by canonical schemas and runtime checks, not by
tool descriptions or MCP annotations.

## Roadmap governance

Significant work starts with a self-contained ExecPlan. The plan must identify
its contribution to each pillar, preserve the public/private boundary, list
non-goals and prohibitions, and define deterministic validation and rollback.
Implementation evidence belongs in a persistent progress log.

