# Candidate Control message payloads v1

**Status: candidate / not frozen. Revision 5.** This document and `boreas-proto::messages` define the candidate typed wire formats for TLS session negotiation, enrollment, directory/management distribution, probes, drain notices and circuit control. They do **not** define TLS, certificate policy, signature verification, identity authorization, circuit TLS, or production route policy. Fixed raw vectors live in `vectors/control-messages-candidate-v1.json` and are decoded by Rust tests; the independent Python checker is authoritative evidence only after it is wired into CI.

## Encoding conventions

Integers are unsigned big-endian fixed-width fields. Payload lengths are exact: decoders reject truncation and trailing bytes. The outer `AppHeader` still constrains frames to 65,536 body bytes. Control bodies begin with the registered subtype byte; body caps in the registry include that byte. RelayCircuit carries no subtype byte (the `AppHeader.kind` discriminates it).

Every registered control subtype has a typed schema. There is no opaque fallback payload: unknown fields, unknown subtypes, extra bytes or unregistered object types reject deterministically. Capability/GSO/MTU state can therefore not be smuggled through an alternate control body.

## Control subtype registry

| Byte | Name | Candidate legal state | Max body (incl. subtype) | Payload schema |
|---:|---|---|---:|---|
| `0x01` | SessionHello | TLS ready, session not accepted | 4096 | SessionParams |
| `0x02` | SessionAccept | legal SessionHello received | 4096 | SessionParams |
| `0x03` | Enrollment | enrollment-service connection, enrollment incomplete | 16384 | Enrollment |
| `0x04` | DirectoryPage | accepted session | 16384 | DirectoryPage |
| `0x05` | Lease | accepted session and registered identity | 16384 | SignedObject(AttachmentLease) |
| `0x06` | Lsa | accepted Core–Core session | 8192 | SignedObject(CoreLsa) |
| `0x07` | Grant | accepted session | 8192 | SignedObject(RouteGrant\|DirectGrant) |
| `0x08` | Revoke | accepted session | 16384 | SignedObject(StatusSnapshot) |
| `0x09` | Probe | accepted session | 256 | Probe |
| `0x0A` | Drain | accepted session | 256 | Drain |
| `0x10` | CircuitOpen | e2e-required, accepted session | 4096 | CircuitOpen |
| `0x11` | CircuitAccept | matching CircuitOpen exists | 4096 | CircuitAccept |
| `0x12` | CircuitReset | circuit opening or established | 256 | CircuitReset |
| `0x13` | CircuitClose | circuit established | 256 | CircuitClose |
| `0x14` | IdentityRevocation | accepted Core–Core, e2e-required, neither opening nor established circuit | 19767 | independent signed carrier or end marker |
| `0x15` | MeshPath | accepted Core–Core, e2e-required, neither opening nor established circuit | 6 | ordered slot proposal |

`0x00`, `0x0B..=0x0F` and `0x16..=0xFF` are unregistered and reject with `unknown_subtype`. Mesh `0x14` and `0x15` are candidate extensions to the base registry, not used by the generic daemon. See [authority-specific revocation](authority-revocation-v1.md#explicit-core-adjacency-distribution-and-route-denial) for the bounded exchange and the distinction from legacy `0x08`.

**Lease cap deviation (reported conflict).** Master plan §5.4 lists Lease at 4 KiB. A single Ed25519+ML-DSA-87 signature pair is 64+4627 bytes; an AttachmentLease requires Primary + Core co-signature, so two pairs (9382 B) plus TBS and envelope headers cannot fit 4 KiB. The candidate registry therefore uses 16 KiB for Lease. This is a plan/registry conflict requiring review before freeze; it is not a silent protocol change. The same arithmetic means signed envelopes must be budgeted before the per-subtype cap is applied.

## MeshPath (0x15)

The body is `0x15 | count:u8 | core_slot:u8[count]`, exactly 4 to 6 bytes. Require 2–4 distinct slots in `1..=16`, with the source slot less than the destination slot; an intermediate slot need not be in ascending order. On the opt-in routed business profile this is one hop-local transaction message, following the authenticated adjacency and authority exchanges and preceding `CircuitOpen`. It does not change `CircuitOpen`, `SessionHello`, or the fixed-route profile. No locator, new credential, or key crosses in this body. Each receiver checks the configured endpoint pair and the authenticated peer against the claimed predecessor, the entire path against its own current signed graph, and its local outgoing permission before using it. Endpoint E2E still binds the exact ordered identities and signed LSA digests; the proposal is not an attestation of the physical route. See the [Linux mesh runtime](../deployment/linux-core-mesh-runtime.md#configure-signed-topology-routing-and-tun).

## SessionHello / SessionAccept (0x01 / 0x02)

Fixed 68-byte body, including subtype:

| Bytes | Field | Candidate rule |
|---:|---|---|
| 0 | subtype | exactly 1 Hello / 2 Accept |
| 1 | `proto_major` | exactly 3 |
| 2..17 | `net_id` | 128-bit network id, nonzero; must equal local network |
| 18..19 | `source_node_id` | u16 BE, valid home-core/octet mapping |
| 20..21 | `destination_node_id` | u16 BE, valid and distinct from source |
| 22..29 | `source_identity_generation` | u64 BE, nonzero |
| 30..37 | `destination_identity_generation` | u64 BE, nonzero |
| 38..53 | `connection_instance` | 128-bit correlation value, echoed exactly |
| 54 | `source_role` | 1 Edge / 2 Core / 3 EnrollmentService |
| 55 | `path_role` | 1 CDN / 2 DIR |
| 56 | `security_mode` | 1 e2e-required / 2 hop-only |
| 57..58 | `mtu_cap` | u16 BE, candidate [576, 9000] |
| 59 | `suite` | 1 pq768 / 2 pq1024, explicit enum |
| 60..67 | `capabilities` | u64 BE; no bits allocated, nonzero rejects |

Node-id mapping: `home_core_id = (node_id >> 8) + 1` must be 1..=16; the low octet must be 1 or 2..=251. Source and destination must differ. `connection_instance` is a correlation value, not a secret, nonce, MAC or cryptographic binding.

`SessionParams` is the sender's view: `source_*` describes the sender, `destination_*` the expected peer. Accept echoes every shared field (`proto_major`, `net_id`, `connection_instance`, `path_role`, `security_mode`, `mtu_cap`, `suite`, `capabilities`) exactly; source/destination node ids and generations are swapped; `source_role` is the responder's authenticated local role. `SessionParams::accept_for(hello, LocalIdentity)` constructs the expected tuple and rejects a Hello not addressed to the local node/generation. `SessionAccept::decode_bound(data, expected)` requires exact equality; `decode_for_hello(data, &hello, local)` is the convenience entry. `SessionAccept::decode` is structural only and must not be treated as agreement to a Hello.

These fields are assertions to compare against an already authenticated TLS peer and local expected destination identity/generation; they do not prove either claim and must not authorize themselves. Suite must also be allowed by local TLS/network policy; this codec only parses its explicit enum. GSO is not negotiated in this candidate: no capability bits are allocated (`capabilities == 0`), so GSO must remain disabled. Any future GSO negotiation must be added to this typed field set and registry, not carried in another payload.

## Enrollment (0x03)

Two typed variants, discriminated by a `kind` byte immediately after the subtype. All integers big-endian; blobs are length-prefixed with exact lengths.

### Request (kind = 1)

| Bytes | Field | Candidate rule |
|---:|---|---|
| 0 | subtype | 3 |
| 1 | kind | 1 |
| 2..3 | `request_version` | u16, exactly 1 |
| 4..19 | `enrollment_id` | 16 bytes, nonzero |
| 20..35 | `invite_id` | 16 bytes, nonzero |
| 36..67 | `csr_hash` | 32 bytes, nonzero |
| 68..99 | `invite_secret` | 32-byte bearer secret, nonzero |
| 100..101 | `csr_len` | u16, 1..=8192 |
| 102.. | `csr_der` | exactly `csr_len` bytes |

`invite_secret` is the real bearer secret carried inside the inner TLS application data. It must never be logged. `EnrollmentRequest` implements `Debug` manually and prints `invite_secret: "[REDACTED]"` (length only); callers must not print the field value. The proto codec does not hash or verify the CSR; `csr_hash` is an assertion for the enrollment service/pki layer.

### Response (kind = 2)

| Bytes | Field | Candidate rule |
|---:|---|---|
| 0 | subtype | 3 |
| 1 | kind | 2 |
| 2 | `status` | 1 issued / 2 pending / 3 rejected |
| 3..18 | `enrollment_id` | 16 bytes, nonzero |
| 19..50 | `csr_hash` | 32 bytes, nonzero |
| 51..52 | `node_id` | u16 BE, valid mapping |
| 53..60 | `identity_generation` | u64 BE, nonzero |
| 61..76 | `net_id` | 16 bytes, nonzero |
| 77..78 | `signed_identity_len` | u16, 0..=16384 |
| 79.. | `signed_identity` | exact SignedObject(NodeIdentity) bytes |

Issued responses require a non-empty `signed_identity` whose NodeIdentity TBS `node_id`, `identity_generation` and `net_id` equal the response header fields. Pending/rejected responses must carry an empty blob. No secret is returned. The X.509 certificate chain is not part of this candidate payload yet; pki/transport must not treat `signed_identity` as a certificate.

## SignedObject envelope

Management-object control payloads carry the exact signed bytes plus explicit signatures so an Edge can verify independently. `raw_tbs` is preserved byte-for-byte and must not be re-encoded before verification. The envelope is not CBOR; it is a fixed/typed header followed by the TBS bytes.

| Bytes | Field | Candidate rule |
|---:|---|---|
| 0 | `version` | exactly 1 |
| 1 | `object_type` | 1..6, must equal the TBS object type |
| 2..3 | `schema_version` | u16, exactly 1 |
| 4 | `signer_count` | 1 or 2 |
| 5.. | signer 1 | role 1 (Primary), explicit signatures |
| .. | signer 2 (if count 2) | role 2 (CoSign), explicit signatures |
| .. | `raw_tbs_len` | u32, 1..=16384 |
| .. | `raw_tbs` | exactly `raw_tbs_len` bytes, canonical per `objects::decode_tbs` |

Each signer block:

| Field | Rule |
|---|---|
| `role` | 1 Primary / 2 CoSign |
| `ed25519` | exactly 64 bytes, mandatory |
| `mldsa_parameter_set` | 1 ML-DSA-65 / 2 ML-DSA-87 |
| `mldsa_len` | u16, exactly 3309 or 4627 |
| `mldsa` | exactly `mldsa_len` bytes |

Rules: Primary must be first; a second signer must be CoSign. AttachmentLease requires exactly two signers (node Primary + Core CoSign); all other object types require exactly one. Both Ed25519 and ML-DSA are mandatory for every signer; the envelope never omits or silently downgrades Ed25519. Candidate revision 2 adds `objects::NodeIdentity.identity_pub_ed25519[32]` (body key 11) so the node Ed25519 management signature is bound to the signed identity; TLS authentication remains ML-DSA. Pki must generate, persist and verify that key; proto only enforces its 32-byte nonzero shape and the signature-envelope lengths. Maximum envelope size is 16 KiB; the control body cap applies after the subtype byte.

Signature input remains `objects::signature_input(raw_tbs, object_type, schema_version)`; proto does not verify signatures, select keys, or inspect certificates.

## DirectoryPage (0x04)

| Field | Rule |
|---|---|
| subtype | 4 |
| `page_seq` | u64 BE |
| `count` | u8, 1..=16 |
| entries | repeated `{ signed_object_len u16, SignedObject }` |

Each entry is a complete SignedObject envelope (raw TBS + explicit signatures), not a bare TBS. The page cap is 16384 bytes including subtype; large envelopes reduce the practical page count. Decoders reject duplicate/unknown object types via the envelope/TBS validation.

## Lease / Lsa / Grant / Revoke (0x05 / 0x06 / 0x07 / 0x08)

Body = subtype byte followed by exactly one SignedObject envelope. Allowed object types are:

| Subtype | Allowed object type(s) | Signer count |
|---|---|---:|
| Lease | AttachmentLease | 2 (Primary + CoSign) |
| Lsa | CoreLsa | 1 |
| Grant | RouteGrant or DirectGrant | 1 |
| Revoke | StatusSnapshot | 1 |

Transport forwards the envelope bytes unchanged; pki/upper layers verify both signatures over `raw_tbs` and enforce issuer/scope/freshness.

## Probe (0x09)

Fixed 34 bytes: subtype(9), `kind` (1 ping / 2 pong), `challenge[16]` (nonzero), `sent_monotonic_us` u64, `echo_monotonic_us` u64. Ping requires `echo_monotonic_us == 0`; Pong may carry the echoed time. Times are local monotonic microseconds, not wall clock; they are measurement hints, not authentication.

## Drain (0x0A)

Fixed 12 bytes: subtype(10), `reason` (1 maintenance / 2 shutdown / 3 overload), `deadline_unix_us` u64, `retry_after_seconds` u16 (<=3600). Drain is advisory scheduling metadata; it does not authorize a peer or force routing changes.

## Circuit control (0x10..0x13)

These bodies match the transport candidate and are fixed-length; all integers big-endian. Session-level authentication/mode/MTU is bound by SessionParams, so circuit messages do not repeat those fields.

| Subtype | Body length | Fields |
|---|---:|---|
| CircuitOpen | 28 | subtype, `circuit_id[16]`, `destination_node_id` u16, `destination_identity_generation` u64, `path_hops` u8 (1..=8) |
| CircuitAccept | 18 | subtype, `circuit_id[16]`, `path_hops` u8 (1..=8) |
| CircuitReset | 17 | subtype, `circuit_id[16]` |
| CircuitClose | 17 | subtype, `circuit_id[16]` |

`circuit_id` must be nonzero; `destination_node_id` must use the valid mapping; generation must be nonzero. CircuitOpen is e2e-required by policy. Circuit identity/generation binding, matching Open/Accept, direction ownership and relay data remain circuit-state/transport checks outside this structural codec.

## RelayFragment (AppHeader kind 3)

Fixed prefix 30 bytes followed by exactly `payload_len` bytes; whole body <=65,536, therefore payload <=65,506 bytes.

| Bytes | Field | Candidate rule |
|---:|---|---|
| 0..15 | `circuit_id` | 128-bit circuit identifier |
| 16 | `direction` | 0 or 1 |
| 17..24 | `byte_offset` | u64 BE |
| 25..28 | `payload_len` | u32 BE |
| 29 | `hops_remaining` | 1..=8; per-fragment TTL, decremented by relays |
| 30.. | `payload` | exact declared length; opaque bytes |

`byte_offset + payload_len` must not overflow u64. Direction mapping, ordering, relay path and circuit binding are outside this framing codec.

## Error categories

Stable category strings used by vectors/logs: `empty_body`, `unknown_subtype`, `wrong_length`, `bad_subtype`, `bad_protocol_version`, `bad_net_id`, `bad_node_id`, `identical_node_ids`, `bad_identity_generation`, `bad_role`, `bad_path_role`, `bad_security_mode`, `bad_suite`, `invalid_mtu`, `unknown_capability`, `body_too_large`, `payload_too_large`, `length_mismatch`, `offset_overflow`, `invalid_direction`, `invalid_hop_count`, `session_mismatch`, `illegal_state`, `invalid_field`, `bad_object_type`, `bad_management_object`, `bad_signed_object`, `bad_signature_algorithm`, `wrong_signature_length`, `missing_cosignature`, `unexpected_cosignature`, `signed_object_too_large`.

## Vectors and evidence status

`vectors/control-messages-candidate-v1.json` (format `boreas-control-messages-v1`) contains fixed positive/negative vectors for SessionHello/Accept, RelayFragment, Enrollment, DirectoryPage, Probe, Drain, the four circuit messages and SignedObject envelopes (including malformed version/type/algorithm/length and signer-count cases). Each vector declares `kind` (`control`, `relay`, or `signed_object`); `relay` entries carry the 30-byte prefix body without a subtype byte. Rust tests decode those exact bytes and assert the stable category; they do not generate expected bytes from the decoder. The independent Python checker in `tools/` verifies the same document without importing Rust.

## Security and integration boundary

Neither codec proves TLS peer identity, validates expected source/destination against PKI, chooses a permitted suite, authenticates the connection instance, verifies Ed25519/ML-DSA signatures, creates a circuit, or verifies certificates. The caller must compare both NodeIDs and identity generations to the authenticated TLS session and local authorization state before accepting a session, and pki must verify signature input over the exact `raw_tbs` bytes. No cryptography is implemented or implied here. `invite_secret` is bearer material: transport/TLS protects it in transit, but proto cannot prevent a caller from logging it; the manual `Debug` redaction is a guard, not a complete secrecy proof.

## Gate gaps

- Phase 0 freeze, ADR review and independent dual-implementation vector acceptance remain open.
- NodeIdentity now carries `identity_pub_ed25519[32]` in candidate revision 2, but pki key generation/persistence, proof-of-possession binding and end-to-end Ed25519+ML-DSA verification evidence remain open; proto itself does not verify signatures.
- Lease 16 KiB is a candidate deviation from the plan's 4 KiB row, recorded in [ADR 0003](../adr/0003-lease-16k-dual-signature-envelope.md) for review.
- The X.509 certificate chain and full enrollment receipt/confirm state machine are not in this candidate payload.
- No fuzzing campaign, production TLS/WSS integration, or third-party protocol review is claimed.
