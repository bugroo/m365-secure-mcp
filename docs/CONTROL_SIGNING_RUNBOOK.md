# Control-manifest signing runbook

This runbook governs the independent Ed25519 authority for
`global-controls.json`. Signing is an offline build-plane operation. It is not
an MCP tool, does not call Microsoft Graph and cannot change a trust anchor,
policy, permission or control definition.

## Roles and approval

Production signing requires two distinct roles:

1. **Manifest approver** — reviews control IDs, lifecycle transitions, evidence
   dependencies, framework mappings, canonical diff, generated matrix and test
   results. The approver authorizes one exact manifest digest.
2. **Signing operator** — has temporary access to the external encrypted signer,
   confirms the approved digest and runs the signing command. The operator
   cannot approve their own manifest change.

Repository maintainers review the public-key metadata and signature in the
normal protected change process. CI compiles and verifies; it never receives
the production private key.

## Trust model

- Public metadata lives in `contract_trust.py`.
- Exactly one production key is `current`.
- A `retired` key verifies only the explicit historical manifest digests pinned
  to that key. It cannot sign a new manifest.
- A `compromised` key is preserved as forensic metadata but is never trusted
  for current or historical verification.
- Production and test authorities cannot be mixed. Test key IDs must start
  with `test-posture-controls-`.
- There is no unsigned transition, alternate-key fallback, network discovery,
  runtime key fetching or automatic trust-anchor replacement.

The project uses **direct cutover**, not overlapping active signers. A reviewed
source change retires the previous key, pins its historical digest and adds one
new current key. The new manifest signature and trust metadata must land
together.

## 1. Offline generation

Generate the production key only on an approved offline workstation or custody
device. Use an encrypted PKCS#8 Ed25519 private key and an interactive
passphrase prompt; never pass the passphrase or raw key on a command line, in an
environment variable or through CI.

One compatible OpenSSL procedure is:

```sh
umask 077
openssl genpkey -algorithm ED25519 -aes-256-cbc \
  -out /secure-control-signing/control-signing-YYYY-MM.pem
```

The destination must be an explicitly mounted, current-user-owned directory
with mode `0700`; the key file must be a regular, non-symlink file with mode
`0600`. The repository command intentionally has no `generate-key` operation.

Inspect only the public material:

```sh
uv run m365-control-signing inspect-key \
  --key-file /secure-control-signing/control-signing-YYYY-MM.pem \
  --key-id posture-controls-YYYY-MM
```

The command prints the public key and SHA-256 public-key fingerprint. It never
prints private bytes or the passphrase.

## 2. Encrypted custody, backup and recovery

- Keep the primary encrypted signer outside Git, repository configuration,
  package data and routine CI secrets.
- Store at least one independently encrypted recovery copy in an approved
  offline custody system under dual control.
- Store the passphrase or unlock factors separately from the encrypted key.
- Record custodian identities, key ID, public fingerprint, activation date and
  recovery-test date in the external security register.
- Perform a periodic offline recovery test by deriving and comparing only the
  public fingerprint. Do not sign a production manifest during a recovery test.
- Never place custody paths, unlock factors or private bytes in tickets or
  repository documentation. A filesystem path is not treated as a secret, but
  the runbook does not require publishing it.

If the active key is unavailable but there is no compromise evidence, stop
signing. Attempt the approved recovery copy under dual control. If recovery
fails, perform the direct-cutover rotation below; do not create an unsigned
manifest or silently select another key.

## 3. Authorized signing

The manifest approver records the exact result of:

```sh
uv run m365-compile-contracts --check
```

The signing operator then signs deterministic canonical JSON with an explicitly
provided external key path:

```sh
uv run m365-control-signing sign \
  --manifest src/m365_secure_mcp/contract_data/global-controls.json \
  --key-file /secure-control-signing/control-signing-YYYY-MM.pem \
  --key-id posture-controls-YYYY-MM \
  --signature-output /secure-control-signing/global-controls.sig.review.json
```

The output path must not already exist. The command fails closed unless:

- the key ID is the sole reviewed `current` production authority;
- the encrypted private key derives the pinned public key;
- the manifest passes the strict schema;
- the signature covers the canonical manifest bytes.

Verify before proposing the reviewed signature update:

```sh
uv run m365-control-signing verify \
  --manifest src/m365_secure_mcp/contract_data/global-controls.json \
  --signature /secure-control-signing/global-controls.sig.review.json
```

The operator records externally: approved manifest digest, key ID, public-key
fingerprint, signature-artifact digest, approver, signer operator and change
reference. No private material or passphrase belongs in audit evidence.

## 4. Rotation and retirement

Every rotation requires an explicit reviewed source change:

1. Generate the replacement signer offline and record its public fingerprint.
2. Assign a new immutable key ID; never reuse an old ID.
3. Change the previous metadata from `current` to `retired`, add its state-change
   date and pin the exact old manifest digest under
   `historical_manifest_digests`.
4. Add the replacement public key as the sole `current` authority.
5. Sign the reviewed manifest with the replacement key.
6. Commit trust metadata, manifest signature, generated artifacts and tests in
   the same reviewed change.
7. Verify both the new current signature and the old historical signature.
8. Move the retired private key to offline archival custody or destroy it under
   the organization's approved retention policy. Public metadata remains.

Historical verification uses:

```sh
uv run m365-control-signing verify \
  --historical \
  --manifest /reviewed-history/global-controls.json \
  --signature /reviewed-history/global-controls.sig.json
```

A retired key works only for a digest explicitly recorded before retirement.

The current `posture-controls-2026-07` public key verifies the existing M1
manifest, but its original ephemeral private key is unavailable. The first
future signature therefore requires the direct-cutover procedure; this runbook
does not create or retain a replacement production key.

## 5. Compromise response

Retirement is an orderly lifecycle event. Compromise means confidentiality or
exclusive control of the private key may have been lost.

On suspected compromise:

1. Stop all signing and distribution immediately.
2. Mark the key `compromised`, with a reviewed state-change date; do not mark it
   merely `retired`.
3. Preserve its public metadata for incident investigation, but reject every
   current and historical signature under it.
4. Identify every manifest and release previously signed by that key.
5. Generate a replacement offline, perform direct cutover and re-sign the
   reviewed current manifest.
6. Publish any security notice and replacement release only through the future
   release process.

There is no automatic fallback during compromise response.

## 6. Local build versus release attestation

`uv build` creates local verification artifacts only. Compiler provenance marks
them:

- `build_kind: local-unattested`;
- `distribution_status: not-a-release`;
- `release_attestation_status: external-required`;
- `source_revision: release-attestation-required`.

These files are not release attestations and must not be distributed as an
official release.

As checked on 2026-07-27, the public repository had no Git tags, GitHub Releases
or retained GitHub Actions artifacts, and PyPI returned no project named
`m365-secure-mcp`. This is evidence that no official `0.13.0` publication was
found; it cannot prove that nobody manually copied a local archive.

## Future release gate

Release-attestation work is explicitly deferred. A future protected release
workflow must refuse publication unless all of the following are true:

1. `source_revision` is the exact commit selected by a protected release tag.
2. Wheel and sdist are built by that release workflow from the tagged commit,
   not uploaded from a workstation.
3. An externally verifiable artifact attestation binds both archive hashes to
   the protected source revision and workflow identity.
4. The release SBOM is bound to those archives and its digest is present in
   provenance.
5. Provenance binds the signed control-manifest digest and control digest map.
6. Consumer instructions verify the tag/commit, archive hashes, attestation,
   SBOM binding, manifest signature and pinned public-key state before install.

Until that workflow exists and its attestations are independently verified, the
project makes no SLSA or signed-release-provenance claim.
