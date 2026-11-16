# Network policy binding candidate contract

**Status: design candidate, 2026-11-16. Not frozen, not implemented, not permission to enable a custom overlay prefix.** This document defines one narrow contract: a NetworkRoot-signed policy that binds a canonical RFC1918 IPv4 `/16` overlay to a `net_id`, a root-pin fingerprint, a version/sequence/validity window, and a dual signature over exact raw bytes. Object type `7`, its field numbers, and the `BRRB0002` layout are proposals pending review; the `BOREAS-MGMT-OBJECT\0` domain and `signature_input` format are existing code, not proposals. This change contains no Rust, no config relaxation, no test/build/format run, and no commit or push.

Normative words: **MUST**, **MUST NOT**, **MAY** apply to the future implementing slice. Today's runtime MUST remain fail-closed: [`Config::validate`](../../crates/boreas-cli/src/config.rs#L881-L973) still returns `CustomOverlayPrefixUnavailable` for every non-default prefix, and no daemon path consumes this policy.

## 1. Trust anchor: independent NetworkRootPin

The root of trust is a `NetworkRootPin` provisioned out of band: `net_id`, Ed25519 SPKI DER, ML-DSA parameter set, ML-DSA SPKI DER ([root_authorization.rs](../../crates/boreas-pki/src/root_authorization.rs#L91-L159)). It MUST NOT be inferred from the bundle being verified.

- `expected_root_fingerprint` = `NetworkRootPin::fingerprint()` (SHA-256 over the `BOREAS-NETWORK-ROOT-PIN-FINGERPRINT\0` domain, net ID, algorithm tag, length-prefixed key DER) MUST be supplied independently of `roots.cbor` and the binary. The fingerprint correlates an external pin; it is not proof of provenance.
- It is optional for the legacy v1 default path and **MUST** be present whenever a `BRRB0002` bundle or a non-default prefix is evaluated. Missing expectation on those paths MUST reject. The source (config, CLI/environment, or an operator pin file) is an open review question; this candidate adds **no** config field and does not relax `Config::validate`.
- [`verify_all`](../../crates/boreas-pki/src/provisioning.rs#L220-L248) derives a pin from the bundle's own keys and returns that fingerprint. That value is a correlation identifier only; treating it as policy provenance is a trust-boundary error.
- The policy signer MUST be the pinned `NetworkRoot` directly. `ReleaseRoot`, `IdentityAuthority`, `RouteAuthority`, `StatusSigner`, and any delegated `RootAuthorizationCandidate` chain MUST NOT sign or stand in for the policy. Root rotation and delegation are out of scope; `issuer_key_id = b"network-root-v1"` and `issuer_generation = 1` are fixed candidate constants, not a rotation mechanism.

## 2. Signed object

Object type `ObjectType::NetworkPolicy = 7`, carried in the existing `SignedObject` envelope with `ObjectKind::Genesis`. This is a **candidate extension of management schema 1**, not existing support: `ObjectType` currently stops at `StatusSnapshot = 6` ([objects.rs](../../crates/boreas-proto/src/objects.rs#L18-L34)), `ObjectBody` has no policy variant, and the current parser rejects type `7`. `SubjectIdentity::Network` (tag `[3]`) and `ObjectKind::Genesis` already exist as schema concepts, but no current object uses `Genesis` for a network parameter. Reusing them here requires explicit parser/body/validation arms; the envelope does not already support this object. `Authority::NetworkRoot` already may issue `Genesis` ([may_issue](../../crates/boreas-pki/src/lib.rs#L300-L312)), so no authority widening is allowed.

The management envelope (the object body plus envelope fields) is the exact TBS. The outer `SignedObject` is not signed; it carries the exact `raw_tbs` bytes and the signature records. Envelope map keys `0..=10`:

| Key | Field | Required value |
|---:|---|---|
| 0 | `schema_version` | `1` |
| 1 | `object_type` | `7` |
| 2 | `net_id` | 16 bytes, non-zero |
| 3 | `issuer_key_id` | `b"network-root-v1"` |
| 4 | `issuer_generation` | `1` |
| 5 | `subject_identity` | `[3]` (`Network`) |
| 6 | `seq` | `>= 1` |
| 7 | `issued_at` | Unix UTC µs |
| 8 | `expires` | Unix UTC µs; `issued_at < expires` |
| 9 | `body` | body map below |
| 10 | `extensions` | empty array in v1; unknown critical extensions reject |

Body is one deterministic-CBOR map with exactly keys `0..=4`:

| Key | Field | Constraint |
|---:|---|---|
| 0 | `net_id` | 16 bytes, non-zero, equal to envelope `net_id` |
| 1 | `overlay_base` | 4 bytes, canonical IPv4 `/16`, low 16 bits zero |
| 2 | `overlay_prefix_len` | exactly `16` |
| 3 | `root_key_fingerprint` | 32 bytes, non-zero, equal to the pin fingerprint |
| 4 | `flags` | exactly `0` |

Encoding rules: one complete canonical item, no trailing bytes, shortest heads, sorted unique keys, no text/negative/float/tag/indefinite items ([decode_tbs](../../crates/boreas-proto/src/objects.rs#L859-L922)). Round-trip MUST be exact: `encode_tbs(decode_tbs(raw)) == raw`. Limits: raw TBS `<= 16 KiB`; envelope 11 entries; body 5 entries.

Version, `net_id`, `seq`, `issued_at`, and `expires` are inside the signed TBS, so they are bound by the signature, not asserted by the carrier; the bundle's `net_id` and root keys are separately bound by the pin fingerprint. A policy missing any of these bindings MUST reject.

Prefix MUST pass [`OverlayPrefix::new`](../../crates/boreas-pki/src/lib.rs#L120-L131): mask exactly 16, `base[2] == base[3] == 0`, and `10/8`, `172.16/12`, or `192.168/16` only. Public, CGNAT `100.64/10`, loopback, link-local, multicast, reserved, IPv6, and every other mask length MUST reject, never round. No text CIDR is signed. A custom `/16` changes the first two octets only; service block zero and core blocks `1..=16` stay. The fixed `/16` is a constraint of this candidate, not a claim that other mask lengths are permanently impossible: any future non-`/16` policy requires a separate layout specification and security review of slot, DNS, routing, and peer-assignment semantics.

## 3. Signature rule

Both signatures cover the same exact bytes:

```text
message = b"BOREAS-MGMT-OBJECT\0" || u16be(schema_version) || u8(object_type)
        || u64be(raw_tbs_len) || raw_tbs
```

This is exactly [`objects::signature_input(raw_tbs, NetworkPolicy, 1)`](../../crates/boreas-proto/src/objects.rs#L925-L940). The field widths were checked in the current implementation, not assumed: `SIGNATURE_DOMAIN` is 19 bytes, `schema_version` is encoded as a two-byte big-endian `u16`, `object_type` as one `u8`, and the TBS length as an eight-byte big-endian `u64` ([objects.rs](../../crates/boreas-proto/src/objects.rs#L933-L938)). The verifier MUST pass the retained `raw_tbs`; a re-encoded substitute MUST NOT be accepted.

| Signature | Length | Rule |
|---|---:|---|
| Ed25519 | 64 | mandatory |
| ML-DSA-65 | 3309 | mandatory under the current `RootsBundle` profile |

Acceptance is AND only over those exact bytes: no Ed25519-only, no ML-DSA-only, no "either key", no alternate parameter set. Signature lengths and the ML-DSA parameter set MUST match the pinned key before verification; mismatch rejects. The current `RootsBundle` carries an `mldsa65` field only, so an ML-DSA-87 pin cannot be accepted through this carrier without a separately reviewed bundle/pin profile. The outer `SignedObject` envelope is not signed.

## 4. Versioned carrier and legacy meaning

`RootsBundle` v1 remains `BRRB0001`, byte-identical to today ([provisioning.rs](../../crates/boreas-pki/src/provisioning.rs#L133-L248)). Its version carries one explicit meaning: a legacy default-overlay bundle with **no signed policy**. It MUST remain decodable and MUST NOT be reinterpreted as policy evidence.

`BRRB0002` adds exactly one policy record after the root keys:

```text
"BRRB0002" || net_id[16] || root_ed25519_spki || root_mldsa65_spki
|| policy_present:u8 = 1 || u32be(len) || policy_signed_object
|| u16be(auth_count) || auth_count × { candidate, ed25519_sig, mldsa_sig }
```

- Encoding is by state: `policy = None` => `BRRB0001`; `policy = Some` => `BRRB0002`. A v1 byte string MUST NOT be padded or re-tagged into v2.
- `policy_present = 0` MUST NOT encode "no policy"; that is v1. Any value other than `1` rejects.
- [`verify_all`](../../crates/boreas-pki/src/provisioning.rs#L220-L248) MUST reject a present policy with a specific error such as `PinnedPolicyVerificationRequired`; it MUST NOT ignore it. Policy acceptance requires `verify_all_pinned(expected_net_id, expected_root_fingerprint, now_us)`, which checks net ID, builds the pin from the bundle keys, compares the fingerprint to the independent expectation, verifies the policy, then verifies every authorization against the same pin.
- An explicit signed default policy (`BRRB0002` with `10.20.0.0/16`) is distinct from the implicit legacy default. It is a signed binding and removing it later is a downgrade (§6). Old nodes that reject type 7 fail closed; a default network needing old-node compatibility stays on v1.

## 5. RouteGrant and other non-substitutes

A `RouteGrant` MUST NOT be used as a network genesis. It is node-subject scoped, its `prefix` is a route destination rather than a network-wide overlay base, `seq`/`expires` are per route, and its authority is `RouteAuthority` ([objects.rs](../../crates/boreas-proto/src/objects.rs#L117-L125), [may_issue](../../crates/boreas-pki/src/lib.rs#L300-L312)). Substituting it would conflate route delegation with network creation and require widening route authority.

For the same reason, `RootAuthorizationCandidate`, `StatusSnapshot`, `NodeIdentity`, and any unsigned config value MUST NOT be treated as a signed network policy or as proof of an overlay prefix.

## 6. Migration: conflict and rollback

Replay state inside `ManagementTrust` is process-local and already implements stale-sequence, duplicate, same-sequence equivocation, and `issued_at` regression ([record_replay](../../crates/boreas-pki/src/management.rs#L496-L543)). A durable binding record MUST exist before a signed policy is relied on across restarts. Minimum fields: magic/version, `net_id[16]`, `root_fingerprint[32]`, `policy_sequence:u64`, `issued_at:u64`, `policy_object_id[32] = SHA-256(raw_tbs)`, `overlay_base[4]`, `overlay_prefix_len:u8`, `source:u8` (1 = explicit signed policy). It is written atomically before use.

At startup/reload, with trusted `now_us`:

1. Verify the policy with the independent pin (§1). Malformed or unverifiable policy is fatal; there is no "skip policy" path.
2. Require `policy.net_id == config.net_id` and `policy.overlay_prefix == config.overlay_prefix`. A different prefix is a conflict even if both are private `/16`s.
3. No binding yet: a valid policy is first use and MUST be persisted before use. No policy is allowed only for the legacy default path (`10.20.0.0/16`) with no signed binding expected.
4. Binding exists:
   - net ID, pin fingerprint, or prefix differs => **conflict**, reject.
   - lower `policy_sequence` => **rollback**, reject.
   - equal sequence: same `policy_object_id` => duplicate, not renewed, not advanced; different object ID => **equivocation/conflict**, freeze the slot, retain both exact signed objects as evidence, reject until operator resolution.
   - higher sequence: `issued_at` regression => reject; changed `overlay_base`/length => prefix change, reject in v1 (the prefix is genesis-immutable); otherwise advance atomically.
5. A signed binding exists but the incoming bundle is v1 or has no policy => **downgrade**, reject. This includes a previously accepted explicit signed default.
6. Missing, corrupt, unreadable, or not operator-owned binding when a signed policy is expected => fail closed. It MUST NOT be silently recreated from the bundle.
7. Config requests a non-default prefix but no verified policy => policy-required error, not fallback to `10.20.0.0/16`.

Conflict MUST NOT be resolved by highest sequence or last file. Deleting the entire local binding together with config and bundle is indistinguishable from a genuine first run; defending against whole-state replacement needs a hardware counter or remote watermark and is out of scope.

## 7. Runtime gate: no custom prefix until full wiring

The default path MUST keep working exactly as today: v1 bundles, omitted `overlay_prefix` meaning `10.20.0.0/16`, existing config validation, status freshness, and daemon startup.

A verified policy MUST NOT enable a custom prefix until **all** of the following consume the same verified value end to end:

- `NodeIdentity` schema and signer/verifier — current validation still hard-codes `vip[0] == 10 && vip[1] == 20` ([objects.rs](../../crates/boreas-proto/src/objects.rs#L668-L670)), so no non-default `/16` identity can even be validated;
- identity issuance and session handshake;
- VIP allocation, packet addressing, TUN/route installation;
- DNS service VIP, TLS certificate profile, and peer negotiation.

A future `validate_with_verified_policy(...)` MAY bind config prefix to the `VerifiedNetworkPolicy` token, but it MUST stay private-gated and MUST NOT be wired into daemon startup in the parser slice. Until this whole gate is met, `CustomOverlayPrefixUnavailable` stays and no policy object may open a prefix.

## 8. Acceptance for this candidate

- A reviewer accepts or rejects, with reasons: object type `7` and type/field layout; `BRRB0002` carrier (versus a sidecar with identical signed bytes); bounded `expires` tied to root-authorization validity (versus network lifetime); fixed `issuer_key_id`/generation; and whether `root_key_fingerprint` stays in the body as explicit conflict evidence.
- Any accepted change MUST preserve: independent pin requirement, dual-signature AND over exact raw bytes, canonical RFC1918 `/16` parsing, explicit v1/v2 semantics, RouteGrant exclusion, and the conflict/rollback/downgrade rules above.
- The implementing slice is limited to parser/verifier/bundle-carrier plus vectors. It MUST NOT remove the config gate, change `OverlayPrefix::DEFAULT`, alter `NodeIdentity`, wire a custom prefix into the daemon, or claim wire freeze.

Non-claims: this is not a wire freeze, implementation, security proof, or production acceptance; it does not make custom prefixes usable; `verify_all` is not an independent pin check; and no local rollback protection is claimed against whole-state replacement.