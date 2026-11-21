# E2E application confirmation candidate v1

Status: **implementation candidate, not frozen, not production acceptance**. This format implements the application-confirmation requirement in master plan §7.1 after E2E TLS has completed. It is not a key exchange, cryptographic handshake, authenticator, exporter construction, or data encryption layer. The standard E2E TLS channel authenticates endpoints and protects these bytes. The only supported suite for this candidate is `Pq768`; all other suites fail closed.

## Encoding

Each confirmation is framed by a 2-byte unsigned big-endian length, which must equal 73, followed by exactly 73 bytes of body; no padding or optional fields are permitted. Integer fields are unsigned big-endian. The record is read/written directly on the E2E TLS byte stream; it has no `AppHeader`, and is not sent as hop-level `Control` plaintext.

| Offset | Length | Field | Required value / meaning |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `BE2E` |
| 4 | 1 | version | `1`; all other versions reject |
| 5 | 1 | message_type | `1` = Offer; `2` = Ack; any other value rejects |
| 6 | 16 | net_id | Equal to both certificate-derived endpoint identities |
| 22 | 2 | initiator_node_id | Lower NodeID endpoint; TLS client |
| 24 | 8 | initiator_identity_generation | Exact authenticated identity generation |
| 32 | 1 | initiator_role | `1` Edge, `2` Core, `3` EnrollmentService |
| 33 | 2 | acceptor_node_id | Higher NodeID endpoint; TLS server |
| 35 | 8 | acceptor_identity_generation | Exact authenticated identity generation |
| 43 | 1 | acceptor_role | `1` Edge, `2` Core, `3` EnrollmentService |
| 44 | 16 | circuit_id | Exact nonzero random `CircuitOpen` ID |
| 60 | 1 | security_mode | `1` = `e2e-required`; other values reject |
| 61 | 1 | suite | Existing `boreas-proto::messages::Suite` value `1` (`Pq768`) only |
| 62 | 2 | opener_node_id | NodeID that sent `CircuitOpen`; not necessarily TLS client |
| 64 | 1 | path_hops | Exact nonzero accepted circuit path length (`CircuitAccept` echoes the original total path length; relay fragment `hops_remaining` is a separate, decremented field) |
| 65 | 8 | optional_capabilities | Exactly zero in v1 (no optional extension negotiated) |

The body is deliberately fixed-size and has no length or unknown-field extension mechanism. Extensions require a distinct candidate version (see v2 below); do not infer IPv4/IPv6 or any other feature from the zero value. This is not a statement that an L3 encapsulation has been negotiated or that a data-plane consumer exists.

## Ordering and acceptance

1. Both endpoints complete the existing authenticated E2E TLS handshake and re-check its peer identity and strict negotiated policy. Certificate-derived local/peer identities, local hop-session network and suite, plus the accepted `CircuitInfo`, are the only expected inputs; values received in the confirmation never choose the expectation.
2. The endpoint whose NodeID is lower (TLS client) writes the exact Offer record and flushes it, then reads exactly 73 bytes and requires the exact expected Ack.
3. The higher-NodeID endpoint (TLS server) reads exactly 73 bytes and requires the exact expected Offer body before writing/flushing its Ack. The received message type must be Offer.
4. Both records bind the same network, ordered endpoint identities and generations/roles, circuit ID, `e2e-required` mode, suite, opener and path length. Each endpoint checks the expected TLS peer before comparing the fixed record. Capabilities must be zero; unknown/nonzero values reject.
5. The `E2eCircuit` business byte stream and `VerifiedE2eSession` token are returned only after the expected confirmation has been received (TLS client receives Ack; TLS server validates Offer and successfully writes Ack). No L3 capability negotiation is claimed by this opaque-stream seam.

## Failure and limits

EOF/truncation, read/write error, configured underlying transport timeout, wrong magic/version/type/field, identity/network/generation/role/circuit/policy mismatch, nonzero/unknown capability, or unsupported suite rejects the circuit. There is no resynchronization or fallback. Dropping an incomplete `CircuitStream` makes a best-effort hop-level `CircuitReset`; the TLS/stream is discarded. Reset delivery itself is best effort because a failed transport cannot guarantee control delivery. Never send the pending business bytes through hop-only. A blocked read is bounded only by the surrounding runtime/backend per-I/O timeout, if configured; this candidate format itself does not impose an overall handshake deadline. A runtime must set suitable read and write timeouts and may need a distinct business-level deadline.

## Candidate interoperability and risk

This is a tunnel-local candidate schema pending Phase 0 registry/version review and independent vectors. It must not be represented as frozen, production-ready, or as G-E2E/G-NO-DOWNGRADE evidence. The underlying current backend and daemon integration remain separate gates. The role-byte assignments, fixed length, ordering and exact suite policy require protocol review before freeze. A general L3 encapsulation capability registry remains unspecified and must be defined before any product data-plane integration claims.

## Opt-in L3 multi-active confirmation candidate v2

The default and explicit `SINGLE_LANE` continue to send and expect the v1 record above, byte for byte. For multi-active, both endpoints must select the **same exact active-lane count**, not a maximum or a range. The locally required record length is checked before reading a fixed-size body; there is no peer-driven version selection or retry. V1-only peers reject v2, and v2 endpoints reject v1. A mismatched Offer does not elicit an Ack. A mismatched Ack does not yield a usable circuit.

| Body offset | Length | v2 field |
|---:|---:|---|
| 0 | 4 | Unchanged `BE2E` magic |
| 4 | 1 | Version `2` |
| 5 | 60 | Unchanged v1 fields, from message type through path length |
| 65 | 8 | u64 BE, exactly `0x0102`, `0x0103`, or `0x0104` for 2, 3, or 4 lanes respectively. Bit 8 marks multi-active, the low byte is the count, and all other bits are reserved zero. |
| 73 | 32 | Exact digest of the already verified signed network policy shared by the two packet endpoints; not a peer-provided authority |

The v2 length prefix is `00 69` (105 body bytes). V2 additionally requires the same signed permanent endpoint binding as the packet adapter, including valid slots and a shared signed policy digest. Endpoint identities, their generations and roles, circuit ID, opener and path length still come from the existing authenticated context. The negotiated hop MTU is still a local ceiling; it is not a whole-path agreement. TLS policy, relay framing and fragment offsets are unchanged.

The `boreas_tunnel::e2e` entry points `open_e2e_with_l3_profile` / `accept_e2e_with_l3_profile` take a local `E2eL3Profile` constructed via `SINGLE_LANE` or `multi_active(2..=4)` (a numeric count passed to the constructor). Linux builds with `openssl-inner-tls` also expose their `_until` forms using the existing absolute deadline guard. Only the returned `E2eCircuit::l3_profile()` is a successful confirmation result. Errors discard the in-progress circuit; the caller must discard the hop session and must not retry with a weaker profile.

This confirms a requirement separately on each circuit. It does not create, group, count, schedule or fail over lanes, authorize another circuit, change L3 framing, or enable any daemon behavior. The one-circuit-per-hop-session invariant remains. V2 is a candidate extension, not a frozen registry assignment or production acceptance result.
