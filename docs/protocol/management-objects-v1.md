# Management objects v1 — candidate typed schema

**Status: candidate; not frozen.** This is a byte-level proposal for the six object bodies in master plan §5.4. It is an implementation/test baseline, not a signature implementation, certificate policy, authorization engine, or security review. Fixed vectors under `vectors/management-objects-candidate-v1.json` are candidate and require independent Python/Rust cross-check before any freeze claim.

## Encoding and raw-byte rule

The TBS is one deterministic-CBOR map with unsigned integer keys and the exact schema below. Management-object CBOR accepts unsigned integers, byte strings, arrays and maps only; negative integers, text strings, simple values (including bool), floats, tags, and indefinite items reject. Integer/length heads are shortest; map keys ordered by encoded-key length then bytes; duplicate keys, UTF-8 text, trailing bytes reject. Object maps here use unsigned integer keys only. Maximum raw TBS is 16 KiB; parser nesting limit is 32. Decode validates the original bytes and must retain those exact bytes for signature verification—**never decode, re-encode, then verify a signature over the re-encoded result**.

Map-key assignments (candidate):

| key | Envelope field | Type / bounds |
|---:|---|---|
| 0 | schema_version | uint, exactly 1 |
| 1 | object_type | uint: 1 NodeIdentity, 2 AttachmentLease, 3 CoreLsa, 4 RouteGrant, 5 DirectGrant, 6 StatusSnapshot |
| 2 | net_id | bstr exactly 16 |
| 3 | issuer_key_id | bstr 1..=64; opaque, not algorithm inference |
| 4 | issuer_generation | uint |
| 5 | subject_identity | array `[tag, id]` (tag 1 node/u16, 2 core/u8), or `[3]` network |
| 6 | seq | uint, per object namespace |
| 7 | issued_at | uint unix_us |
| 8 | expires | uint unix_us |
| 9 | body | object-specific integer-key map |
| 10 | extensions | array of `[id:uint, critical:uint(0|1), value:bstr]`; sorted strictly by id, max 32; value max 2048 |

`object_id` is **outside this TBS** and is never an envelope key. Candidate expected value is `SHA-256(raw_tbs)`; receiver must recompute and compare before using externally carried ID. This avoids self-reference. This module does not implement SHA-256 or decide transport envelope. Signature-input candidate is `ASCII("BOREAS-MGMT-OBJECT\0") || schema_version:u16be || object_type:u8 || raw_tbs_len:u64be || raw_tbs`. Signer/verifier use the exact original raw TBS. The fixed domain label and layout remain candidate pending ADR.

Extensions preserve unknown noncritical entries in raw TBS and typed representation; unknown critical extension is rejected. No extension ID is currently declared known, so all critical extensions reject. The `critical` value is uint 0/1, not CBOR simple bool.

## Body maps

All entries are required, no unknown keys allowed; keys are consecutive integers starting at zero. Common/body duplicated identity/time/version data MUST agree exactly.

### 1 NodeIdentity (object type 1; IdentityAuthority)

`{0:net_id:bstr16, 1:node_id:u16, 2:home_core_id:u8(1..16), 3:vip:bstr4, 4:vip6:bstr16 (all zero means disabled), 5:role:u8 (1 Edge/2 Core/3 EnrollmentService), 6:mldsa_parameter_set:u8 (1 ML-DSA-65/2 ML-DSA-87), 7:identity_pub_mldsa:bstr(1..8192), 8:identity_generation:uint>=1, 9:not_before:uint, 10:expires:uint>not_before, 11:scope:bstr<=1024}`. Candidate checks `node_id=((home_core_id-1)<<8)|vip[3]`; IPv4 must be under `10.20.<home_core_id>.0/24`, Core uses `.1`, Edge `.2..=.251`, and EnrollmentService uses `10.20.0.<nonzero octet>`. All NodeID references validate high-byte home slot 1..16 and low-byte octet `.1` or `.2..=.251`. Exact allowed scope/VIP6 allocation and all role provisioning details remain policy/ADR scope. Envelope net_id, subject Node(node_id), seq=identity_generation, issued_at=not_before, expires=body expires.

The parameter set is explicit. Key bytes are opaque and capped; no algorithm or parameter is inferred from byte length. Exact standardized key parsing and lengths belong to crypto/certificate policy, not this module.

### 2 AttachmentLease (type 2; node identity primary + target Core confirmation outside this TBS)

`{0:node_id:u16, 1:identity_generation:uint>=1, 2:attach_generation:uint>=1, 3:target_core_id:u8(1..16), 4:not_before:uint, 5:expires:uint>not_before}`. Envelope subject Node(node_id), issued_at=not_before, expires=body expires. The plan requires primary signature plus Core countersignature; this TBS schema does not encode signature bytes or cryptographic algorithm IDs.

### 3 CoreLsa (type 3; own CoreOperationalKey)

`{0:core_id:u8(1..16), 1:core_generation:uint>=1, 2:seq:uint>=1, 3:neighbors:array<=15 of [peer_core_id:u8(1..16, unique and not self), rtt_p50_ms:u16, loss_ppm:u32<=1_000_000, path_type:u8(1 CDN/2 DIR)]}`. Envelope subject Core(core_id), seq=body seq. Neighbors must be unique by peer ID and cannot contain self; path_type semantics remain an ADR item.

### 4 RouteGrant (type 4; RouteAuthority)

`{0:subject_node_id:u16, 1:prefix:bstr(4|16), 2:prefix_len:u8 <= address bits, 3:metric:u16, 4:ha_group:bstr<=64, 5:seq:uint, 6:expires:uint}`. Host bits after prefix_len must be zero. Empty `ha_group` means no HA; enforcing same-prefix and group cardinality two is directory policy. Envelope subject Node(subject_node_id), seq and expires equal body.

### 5 DirectGrant (type 5; target Core's own operational key)

`{0:subject_node_id:u16, 1:endpoint_kind:uint(1 IP/2 hostname), 2:endpoint:bstr (IPv4 4 or IPv6 16 for kind 1; nonempty UTF-8 <=253 for kind 2), 3:port:u16 nonzero, 4:sni:bstr<=253, 5:expires:uint}`. Envelope subject Node(subject_node_id), expires equal body. Candidate validator currently accepts only lowercase/uppercase ASCII DNS LDH labels (1–63 bytes; no leading/trailing hyphen, total <=253) for hostnames, and only checks SNI byte cap (<=253); IDNA normalization, lowercase canonical wire form, SNI grammar, and whether IP literals are valid SNI remain ADR items. This deliberately avoids silently normalizing signed bytes.

### 6 StatusSnapshot (type 6; StatusSigner)

`{0:issued_at:uint, 1:next_update:uint, 2:sequence:uint, 3:revocations:bstr<=16KiB}`. Require `issued_at < next_update <= issued_at + 86_400_000_000` microseconds. Envelope subject Network, seq=sequence, issued_at/ expires=body issued_at/next_update. Revocation payload remains an opaque candidate sub-schema requiring its own specification; enclosing object still capped at 16 KiB.

## Cross-field and authorization boundary

Typed decoder checks body/envelope consistency, integer range, required/unknown fields, cap and canonical CBOR. It does **not** decide issuer authority, scope, expiry relative to trusted clock, rollback watermarks, signature validity, identity issuance transactions, prefix allowlists, or dual-signature AND rules. `issuer_key_id` is opaque bytes and never a key or algorithm lookup by guessed length. ML-DSA parameter enum labels a declared choice; no cryptographic operations occur here.

## Validation vectors and gates

Vector JSON contains raw TBS hex and expected typed object/error plus raw signature-input hex. Include positive object samples, malformed/noncanonical/duplicate/unknown-field cases, cross-type/body replacement, cross-net mismatch, common/body mismatch, critical extension reject, wrong ranges and signature-input raw-byte fixtures. Rust and standard-library Python independent implementations must both decode to expected semantic object, produce identical deterministic TBS and exact signature-input bytes, then negative fixtures must reject. Passing is evidence for candidate interoperability only, not schema freeze or cryptographic verification.
