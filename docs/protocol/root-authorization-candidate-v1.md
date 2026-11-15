# RootAuthorization candidate v1 (not frozen)

**Status:** implementation candidate for the P01/P03 vertical slice; not a protocol freeze. The
master plan and runtime contract remain authoritative, and this document does not mark either
complete. `boreas-proto::objects` currently defines management objects such as NodeIdentity and
RouteGrant, but contains no `RootAuthorization` object, parser, encoder, or wire fixture. This
candidate is therefore separate from (and not a parallel redefinition of) an existing proto type.
It must be reconciled with the provisioning/genesis and chain schema before any freeze.

## Candidate authorization object

A canonical CBOR map using unsigned integer keys in ascending order, definite lengths only,
shortest integer encodings, no duplicate keys, and no trailing bytes. Schema version is 1.
Candidate fields (keys 0–13, matching the unsigned-integer-key/shortest-head discipline in `management-objects-v1.md`; this independent provisioning object does not claim to be a `ManagementObject`):

| Key | Value |
|---|---|
| 0 | schema version `1` |
| 1 | `net_id`, exactly 16 bytes |
| 2 | issuer key ID, 1–64 bytes |
| 3 | issuer generation, positive unsigned integer |
| 4 | purpose: Identity=1, Route=2, Status=3, CoreOperational=4 |
| 5 | issuer Ed25519 SubjectPublicKeyInfo DER, at most 4096 bytes |
| 6 | issuer ML-DSA parameter set (65=1, 87=2) |
| 7 | issuer ML-DSA SubjectPublicKeyInfo DER, at most 4096 bytes |
| 8 | scope encoded as a canonical CBOR byte string (purpose-specific shape below) |
| 9 | not-before Unix microseconds |
| 10 | expiry Unix microseconds; strictly greater than not-before |
| 11 | chain depth, exactly 1 in this candidate |
| 12 | may-delegate, exactly false |
| 13 | extensions, currently exactly an empty array (unknown critical extensions cannot be smuggled) |

The complete candidate is capped at 16 KiB. Unknown fields, duplicate fields, malformed/noncanonical
CBOR, duplicate scope entries, invalid roles, invalid IDs, invalid prefixes, empty/oversized scopes,
and unknown critical extensions (if extensions are added by a future revision) reject. Purpose and
scope must agree. No chain traversal or delegated RootAuthorization issuance is accepted: chain
length is one direct NetworkRoot authorization, and transitive issuance is prohibited.

Scope shapes, themselves canonical CBOR:

* Identity: map `{0: [role...], 1: [home_core_id...]}`. Roles are Edge=1, Core=2,
  EnrollmentService=3; roles and core IDs are unique, nonempty, sorted ascending, and capped at 3 and 16.
* Route: array of at most 256 `[address_bytes, prefix_length]` pairs, strictly sorted by address bytes
  then prefix length; address is 4 or 16 bytes, prefix is in range, host bits zero, and a management consumer must enforce containment when
  authorizing a particular route.
* Status: empty map.
* CoreOperational: core ID integer in 1..=16.

## Signatures and trust input

The issuer authorization is signed by an independently provisioned, network-specific
`NetworkRootPin`, which contains Ed25519 and ML-DSA public keys. The distinct API type prevents
accidental in-process substitution of a `ReleaseRoot` value, but it cannot distinguish copied DER;
correct NetworkRoot provenance is an independent out-of-band provisioning responsibility. Signatures cover the exact complete
canonical candidate bytes, not a re-encoded replacement:

`b"BOREAS-ROOT-AUTHORIZATION-CANDIDATE\0" || raw_candidate`

Both Ed25519 (64 bytes) **and** the selected root ML-DSA signature (ML-DSA-65: 3309 bytes,
ML-DSA-87: 4627 bytes) are mandatory (AND). Both root keys must be parsed/type-checked by the
OpenSSL 3.5+ backend. Network ID, issuer ID/generation, delegated public key pair, purpose, scope,
and validity are bound by the signed raw bytes. Reject wrong network, not-yet-valid, expired,
key-type/parameter mismatch, or either failed signature. Verify network/purpose/scope/time policy
before invoking signature verification. No caller-provided boolean/verifier trait is trusted.

## Rust slice and limitations

With `boreas-pki/openssl-backend`, `root_authorization::verify(candidate, raw_candidate,
ed25519_signature, mldsa_signature, network_root_pin, expected_net_id, trusted_now_us)` yields a
private-field `VerifiedIssuerAuthorization`; the only export to `ManagementTrust` is the controlled
`issuer_record()` accessor. Without the feature the module is not compiled (and no success path is
available). The copied `IssuerRecord` does not carry validity, so this is not perpetual trust: a
consumer must retain/check `validity()` against trusted UTC at each admission and apply revocation /
current-generation state; never persist or treat the extracted record alone as permanently trusted.
Runtime must persist the root pin identity, verified candidate bytes/digest, issuer high-water
generation, revocation/watermark state, and replay evidence atomically before relying on it. The token
also does not implement root rotation, revocation, genesis
validation, a daemon, or durable storage. These are subsequent integration work.

The scoped code implements a bounded canonical candidate decoder/encoder and cryptographic
verification boundary, but this is not a frozen interoperability profile. Before protocol freeze,
add independently generated parser/encoder vectors, clarify scope serialization and chain/root
rotation semantics, and align the candidate package with the provisioning contract. In particular,
this direct-root-only slice rejects delegation and does not implement sequence persistence, root
rotation, revocation, or durable replay.
