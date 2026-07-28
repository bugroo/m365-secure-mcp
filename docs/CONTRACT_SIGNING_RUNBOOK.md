# Contract manifest signing runbook

This runbook governs the independent Ed25519 authority for fixed Microsoft
Graph contract manifests. It is separate from posture-control, playbook,
Governance, approval, and release authorities. Neither the MCP runtime nor CI
can generate, register, rotate, unlock, or use a production private key.

## Roles and custody

- **Manifest approver:** reviews the canonical manifest, generated matrices,
  Graph-surface diff, tests, provenance, SBOM binding, and signing request.
- **Signing operator:** uses the approved digest and an externally mounted
  encrypted signer after approval. The operator must not be the runtime.
- **Primary custodian and recovery custodian:** maintain independent encrypted
  copies and unlock factors outside Git, CI, package data, and repository
  configuration. Names, real mount paths, and recovery factors are external.

The externally generated key must be Ed25519 PKCS#8 encrypted with a strong
passphrase entered interactively. Store its file in a current-user-owned
directory with mode `0700`; the regular key file must be mode `0600`.
The CLI rejects symlinks and never accepts a passphrase through arguments or
environment variables. It has no key-generation command.

## Offline inspection

After external generation, inspect only public metadata:

```bash
uv run m365-contract-signing inspect-key \
  --key-file /external-secure-mount/contracts.pem \
  --key-id m365-contracts-YYYY-MM
```

Record the immutable key ID, raw Ed25519 public key, and SHA-256 fingerprint in
an independently reviewed source change. Inspection does not modify the trust
registry and never prints private bytes.

## Direct cutover

The candidate implementation PR may merge with all schema-2.0 operations
inactive. Before the first reviewed cutover:

1. execute and review the mandatory Core Identity Lab scenarios for all five
   operations using isolated session, account, group, license and negative
   operator profiles;
2. assemble and privacy-scan the final Core results, then place only the
   sanitized canonical output at
   `contract-candidates/identity-live-lab-evidence.json`;
3. apply any resulting correction and regenerate every candidate artifact;
4. confirm the compiler binds the evidence digest into provenance, SBOM
   metadata and a `signing_eligible: true` signing request;
5. review the final manifest, evidence and artifact digests;
6. sign only that final post-lab manifest digest.

Any candidate correction, including one derived from live-lab evidence,
invalidates the earlier digest and signing request. Signing a pre-lab digest is
prohibited. Activation is delivered in a separate, small PR; no candidate is
registered as a tool before that PR.

Initial activation maturity is `preview`. Extended Identity Lab evidence
(real synchronization, active/eligible PIM, dynamic and role-assignable groups,
group-based licensing, and advanced replication/concurrency) is required
before promotion to `stable`. An unavailable Extended scenario remains
`not_executed`; it is never converted into a pass and does not weaken the Core
signing gate.

The activation cutover is atomic:

1. Preserve the public key for `profile-debt-2026-07`.
2. Mark it `retired` and pin only
   `sha256:1a33a244371405402df75a125fe6c18a9d6d0af0d2b692f5a831cde82248f5ba`.
3. Add one new immutable `m365-contracts-YYYY-MM` production authority as
   `current`, using public metadata obtained from the external signer.
4. Sign the exact reviewed post-live-lab schema-2.0 candidate manifest.
5. Add the trust metadata, signature, activated manifest, generated artifacts,
   and passing current/historical tests in the same reviewed change.

There is no overlap, network discovery, unsigned transition, or fallback.
Before that atomic change the candidate remains non-executable.

## Signing and verification

The signing command refuses retired, compromised, test-only, wrong-ID, or
wrong-public-key signers and never overwrites output:

```bash
uv run m365-contract-signing sign \
  --manifest contract-candidates/identity-slice.json \
  --key-file /external-secure-mount/contracts.pem \
  --key-id m365-contracts-YYYY-MM \
  --signature-output /external-secure-mount/identity-slice.sig.review.json

uv run m365-contract-signing verify \
  --manifest contract-candidates/identity-slice.json \
  --signature /external-secure-mount/identity-slice.sig.review.json
```

Historical verification is explicit and succeeds only for a retired key and
one of its pinned digests:

```bash
uv run m365-contract-signing verify --historical \
  --manifest src/m365_secure_mcp/contract_data/global-manifest.json \
  --signature src/m365_secure_mcp/contract_data/global-manifest.sig.json
```

## Rotation, retirement, and compromise

- **Rotation:** use direct cutover. Add a new immutable key ID; retire the old
  public key with the exact historical digests it may verify. Re-sign only the
  newly reviewed manifest.
- **Retirement:** blocks signing and current verification. It permits only
  explicit historical verification of pinned digests.
- **Compromise:** immediately mark the authority `compromised`; it verifies
  neither current nor historical manifests. Inventory affected releases and
  manifests externally, create a replacement authority, and publish a reviewed
  incident notice without secret material.
- **Unavailable current key:** do not fall back, generate an unsigned manifest,
  or promote a test key. Recover the independent encrypted copy under the
  external custody process, or perform a reviewed direct cutover.

Archived private keys remain outside the repository under external retention
policy. Destruction needs dual custody evidence. Preserve public metadata and
historical digests indefinitely enough to verify supported artifacts.

## Audit evidence

Retain externally: manifest approval, canonical digest, public fingerprint,
operator identity reference, signing time, signature digest, artifact digests,
test report, recovery/rotation decisions, and review reference. Never retain a
passphrase, private bytes, real custody path, unlock factor, or customer data.

CI may run verification and leak scanning. Routine builds never sign and local
artifacts remain `local-unattested`, `not-a-release`, and
`release-attestation-status: external-required`.
