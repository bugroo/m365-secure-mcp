# Identity Slice live-lab boundary

Identity live tests are writes. They may run only in a dedicated,
non-production tenant with synthetic resources. Customer tenants, WERIXO
production, routine administrator identities and real emergency-access
accounts are prohibited.

PR #5 merged the five schema-2.0 contracts as inactive candidates. Live-lab
validation occurs before production signing. A candidate signature is not a
prerequisite for the lab; a reviewed lab correction instead changes the
candidate digest that will later be signed.

## Fail-closed process gate

`m365-identity-live-lab` is an offline boundary utility. It does not register
an MCP tool, sign a plan, authenticate or execute Graph. Before a separate
reviewed live runner may write, the process must satisfy all of these bindings:

- `M365_IDENTITY_LIVE_LAB=1`;
- `M365_LAB_PROFILE=live-lab`;
- `M365_IDENTITY_LIVE_LAB_WRITE_ACK=DEDICATED_NONPRODUCTION_IDENTITY_LAB`;
- `M365_LAB_TENANT_ID` exactly matches the external inventory;
- `M365_CLIENT_ID` exactly matches the dedicated lab App Registration;
- `M365_IDENTITY_LIVE_LAB_INVENTORY` points to an owner-only regular `0600`
  file and not a symlink;
- the external Governance v3 policy verifies, binds the exact tenant,
  `selected-write` profile, candidate/effect digests and exact inventory
  fences;
- the external approval verifier is owner-only and its public-key fingerprint
  is pinned by that signed Governance policy;
- candidate-manifest and Effect Model digests match the checked-out source.

The inventory path and all identifiers stay outside Git. Errors and successful
summaries contain no tenant, client, user, group, SKU or service-plan IDs.
Use the committed
[`identity-live-lab.inventory.template.json`](../examples/identity-live-lab.inventory.template.json)
only as a substitution template; it intentionally does not validate as an
inventory.

```bash
uv run m365-identity-live-lab requirements
uv run m365-identity-live-lab validate-inventory \
  --inventory /external-owner-only/identity-live-lab.json
uv run m365-identity-live-lab gate
```

The process profile `live-lab` is an independent lab boundary; the signed
Governance profile remains the closed `selected-write` profile used by T2
operations. The explicit flags are necessary but not sufficient. Before every
write, the live runner must also authenticate the exact operator, validate the
token tenant/audience/scope closure, verify the independent marker group,
inspect all synthetic fixtures and compare signed Governance fences.

## Required delegated permission closure

Administrator consent is manual and applies only to the dedicated lab App
Registration:

- `GroupMember.ReadWrite.All`
- `LicenseAssignment.Read.All`
- `LicenseAssignment.ReadWrite.All`
- `RoleManagement.Read.Directory`
- `User.EnableDisableAccount.All`
- `User.Read.All`
- `User.RevokeSessions.All`

Do not add a permission merely to make a test pass. A missing permission is
recorded against the exact preflight, effect, readback or protected-object
call and reviewed against the candidate matrix.

The lab operator uses the project effect roles already selected by the
candidates:

- Helpdesk Administrator;
- User Administrator;
- Groups Administrator;
- License Administrator.

It also requires `Global Reader` for the protected-object evidence calls.
`Global Reader` is the least common Microsoft-supported role across the fixed
v1.0 calls for permanent role assignments, active assignment schedule
instances and eligible assignment schedule instances. This evidence role does
not authorize the write itself; each operation still requires its separate
effect role. Both role categories are explicit in the generated candidate
matrix.

Groups Administrator remains deliberate for this phase. Group owner is not
enabled until token-subject ownership of the exact group is cryptographically
bound, revalidated at TOCTOU and proven by reviewed live tests.

## External synthetic inventory

The dedicated tenant must contain the following fixtures. Roles, consent,
credentials and emergency-access controls are prepared manually and verified;
this repository never creates them.

### Users

- normal cloud-managed Member, enabled;
- normal cloud-managed Member, disabled;
- user with the allowed SKU assigned directly;
- user with the allowed SKU inherited from a group and not directly assigned;
- Guest;
- synchronized user;
- user holding an administrative role;
- ordinary synthetic user classified as break-glass only by lab Governance;
- user without `usageLocation`;
- user outside every operation allowlist.

The synthetic break-glass fixture is not a real emergency-access account and
must have no production purpose.

### Groups

- allowed static group;
- protected static group;
- dynamic group;
- role-assignable group;
- group outside the operation allowlist;
- independent static marker group outside all operation allowlists.

The marker group description is random lab text whose SHA-256 digest is pinned
only in the external inventory. Its immutable ID and description digest form
the independent in-tenant lab marker. Marker content is evidence, never
authorization.

### Licensing and relationships

- allowed subscribed SKU with available units;
- second subscribed SKU outside Governance;
- target with valid `usageLocation`;
- target without `usageLocation`;
- direct and group-inherited assignments;
- allowed and non-allowed service plans from the allowed SKU;
- one existing and one absent membership relationship.

Dynamic membership and role-assignable group fixtures may require Microsoft
Entra licensing. Group-based licensing must be supported by the selected lab
subscription. No customer or production subscription is acceptable.

## Live execution order

After the offline gate and read-only tenant inspection succeed, the reviewed
runner executes only the candidate contracts through Governance v3, exact T2
plans, external lab approvals and `ChangeSafeOperator`:

1. session revocation: provider acceptance, bounded observation and no retry;
2. account enabled/disabled transitions, no-op, drift and protected denials;
3. membership add/remove, no-op, replication, concurrency and exact `/$ref`;
4. direct-license assign/plan-update/remove/no-op and negative capacity,
   location, inherited and allowlist cases;
5. regression of all five contracts after any correction.

An uncertain write pauses testing for that target and requires manual
verification. Compensation is always a new approved plan. The harness never
promotes session revocation to verified token invalidation.

## Public evidence

Only the closed `PublicLiveLabEvidence` schema may be committed. It permits:

- scenario;
- synthetic resource class;
- operation;
- expected and observed state;
- approximate duration bucket;
- accepted/verified/uncertain classification;
- sanitized error code;
- contract digest;
- pass/fail.

Run the deterministic scanner before staging evidence:

```bash
uv run m365-identity-live-lab scan-evidence \
  --evidence /external-owner-only/sanitized-live-lab.evidence
```

The scanner rejects tenant/object/device/subscription/request IDs, UUIDs,
UPNs, email addresses, IP addresses, tokens, key material and unknown fields.
Recordings update only through an explicit reviewed action.

## Activation gate

Production signing is allowed only after all five operations and negative
cases have reviewed live evidence, regressions pass and final public evidence
passes the privacy scanner. Then:

1. regenerate every candidate artifact;
2. freeze and review the final digest;
3. set `signing_eligible: true` only with the five reviewed evidence records;
4. perform the external signing ceremony;
5. activate through a separate small PR.

No candidate is an MCP tool before that activation PR. Live-lab completion
does not make an operation `stable`; initial maturity remains `preview`.
