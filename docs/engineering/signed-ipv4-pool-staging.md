# Signed IPv4 pool migration: offline staging only

This slice stages one IPv4-only Core or Edge identity from the legacy
`10.20.0.0/16` overlay for a different canonical RFC1918 `/16`. It does not
modify installed node material or any policy/identity watermark, and does not
activate a target prefix or migrate any running network. A policy prefix is still
genesis-immutable in live state; do not delete/reset an existing watermark to
work around its prefix-change rejection.

## Offline sequence

Use an offline CA, a separate operator-controlled staging directory, a verified
current/unrevoked source `local.signed`, and a NetworkRoot fingerprint obtained
from independent trusted provisioning (not from the candidate or roots bundle
being checked). The fingerprint commits to the network ID as well as both keys.
Use only one candidate and verify one consistent set of sources per cutover
plan. Re-running for the same exact source and policy yields the same TBS;
staging a different policy does not reserve a new generation and must not be
used to publish a second identity at that generation.

```sh
boreas pki sign-policy --ca-dir "$CA" --out-dir "$CANDIDATE" \
  --overlay-prefix 172.19.0.0/16 --sequence "$TARGET_SEQ" --ttl-seconds 3600

boreas pki stage-pool-migration --ca-dir "$CA" --out "$STAGING/node.signed" \
  --legacy-identity "$SOURCE/local.signed" --roots "$TRUST/roots.cbor" \
  --expected-root-fingerprint "$PINNED_FINGERPRINT" \
  --tbs-file "$CANDIDATE/tbs.cbor" \
  --ed25519-signature-file "$CANDIDATE/ed25519.sig" \
  --mldsa65-signature-file "$CANDIDATE/mldsa65.sig"

boreas pki verify-pool-migration --staged-identity "$STAGING/node.signed" \
  --legacy-identity "$SOURCE/local.signed" --roots "$TRUST/roots.cbor" \
  --expected-root-fingerprint "$PINNED_FINGERPRINT" \
  --tbs-file "$CANDIDATE/tbs.cbor" \
  --ed25519-signature-file "$CANDIDATE/ed25519.sig" \
  --mldsa65-signature-file "$CANDIDATE/mldsa65.sig"
```

Verification needs no CA secret. Both commands report `prefix_active:false`.
The stage command creates a new output file and refuses any existing path. If
an interrupted write leaves a partial file, discard it and use a new output
path. These commands do not establish source revocation/current generation or a
trusted clock; operators must confirm those independently. Do not place
staged output in deployed material directories or use it as a TLS identity.

## Evidence and scope

- Both policy signatures and both signatures on each identity cover their
  respective exact canonical TBS. The selected IdentityAuthority delegation
  must be valid under the same pinned NetworkRoot and cover the source role
  and home Core. The signer must possess the exact delegated key pair.
- The new signature covers a critical, offline-only extension `0x4252504d`
  containing `SHA-256(destination policy TBS) || SHA-256(source identity TBS)`,
  exactly 64 bytes. It does not register a live protocol extension. The legacy
  parser still rejects the staged object. A new sequence for the same prefix
  cannot be substituted for the selected policy.
- Only the two network octets of the IPv4 VIP change; role, home Core, NodeID,
  host slot, public keys and body scope remain unchanged. The generation is the
  source plus one, checked for overflow; validity is the intersection of the
  source, destination policy and issuer windows. EnrollmentService, IPv6 VIPs
  and source extensions are deliberately unsupported.
- Activation still needs authenticated policy/epoch negotiation, a fleet-wide
  single-writer generation and status/revocation transition, collision checks
  against physical, LAN and management routes, TUN/route and DNS integration,
  certificate/session verification, and coordinated cutover and recovery. The
  daemon rejects signed non-default policies before touching its watermark.
  No arbitrary-CIDR or rolling migration support is implied.
