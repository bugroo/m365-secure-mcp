# Open-source boundary

## Community purpose

`m365-secure-mcp` is a public, community-oriented Microsoft Graph MCP server.
Its Apache-2.0 security core is intended to be useful in its own right: fixed
contracts, deterministic controls and tenant isolation are not intentionally
restricted to create a separate commercial feature tier.

## Public security core

The public repository may contain tenant-neutral Microsoft Graph contracts,
signed global manifests, generic posture control definitions, closed evaluator
identifiers, privacy schemas, encrypted evidence mechanisms, opaque evidence
references, generic multi-tenant isolation, compiler and diagnostic code,
tests, SBOM/provenance metadata and verified public framework mappings.

The public control manifest contains no customer policy, customer severity,
tenant selector or proprietary scoring methodology. Downstream extensions must
use their own reviewed namespace and signing authority; the runtime does not
load remote definitions or generate controls dynamically.

## External managed-service implementations

Customer inventories, credentials, App Registrations, Governance policies,
baselines, exceptions, reports, findings and operational data stay outside
this repository. The same applies to managed-service scheduling, billing,
SLAs, commercial evidence-pack templates and product-specific adapters for
ticketing, asset management, endpoint management, automation or SIEM systems.

External integrations must run as separate processes. They may consume signed,
minimized outbound evidence, but inbound authorization over MCP tools is
prohibited. Inbound data cannot change contracts or policies, create
exceptions, grant permissions or trigger Microsoft Graph writes.

## License, contributions and commercial use

The source is available under the [Apache License 2.0](../LICENSE), including
its permissions for downstream commercial use, modification and distribution
subject to the license terms. Contributions intentionally submitted for
inclusion are handled under the contribution terms in section 5 of that
license unless explicitly stated otherwise.

Apache-2.0 licenses the copyrighted work; it does not license WERIXO names,
logos or other trademarks. See [TRADEMARKS.md](../TRADEMARKS.md).

## Customer-data rule

Never commit customer policies, tenant or object identifiers, secrets, tokens,
credentials, private signing keys, reports, findings or operational content.
Examples and tests must use clearly synthetic data. Suspected exposure must be
handled privately through the process in [SECURITY.md](../SECURITY.md), not in
a public issue.
