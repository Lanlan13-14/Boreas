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

The body is deliberately fixed-size and has no length or unknown-field extension mechanism. A future optional capability registry or changed field set requires an explicitly reviewed new candidate version; do not infer IPv4/IPv6 or any other feature from the zero value. This is not a statement that an L3 encapsulation has been negotiated or that a data-plane consumer exists.

## Ordering and acceptance

1. Both endpoints complete the existing authenticated E2E TLS handshake and re-check its peer identity and strict negotiated policy. Certificate-derived local/peer identities, local hop-session network and suite, plus the accepted `CircuitInfo`, are the only expected inputs; values received in the confirmation never choose the expectation.
2. The endpoint whose NodeID is lower (TLS client) writes the exact Offer record and flushes it, then reads exactly 73 bytes and requires the exact expected Ack.
3. The higher-NodeID endpoint (TLS server) reads exactly 73 bytes and requires the exact expected Offer body before writing/flushing its Ack. The received message type must be Offer.
4. Both records bind the same network, ordered endpoint identities and generations/roles, circuit ID, `e2e-required` mode, suite, opener and path length. Each endpoint checks the expected TLS peer before comparing the fixed record. Capabilities must be zero; unknown/nonzero values reject.
5. The `E2eCircuit` business byte stream and `VerifiedE2eSession` token are returned only after the expected confirmation has been received (TLS client receives Ack; TLS server validates Offer and successfully writes Ack). No L3 capability negotiation is claimed by this opaque-stream seam.

## Failure and limits

EOF/truncation, read/write error, configured underlying transport timeout, wrong magic/version/type/field, identity/network/generation/role/circuit/policy mismatch, nonzero/unknown capability, or unsupported suite rejects the circuit. There is no resynchronization or fallback. Dropping an incomplete `CircuitStream` makes a best-effort hop-level `CircuitReset`; the TLS/stream is discarded. Reset delivery itself is best effort because a failed transport cannot guarantee control delivery. Never send the pending business bytes through hop-only. A blocked read is bounded only by the surrounding runtime/backend per-I/O timeout, if configured; this candidate format itself does not impose an overall handshake deadline. A runtime must set suitable read and write timeouts and may need a distinct business-level deadline.

## Candidate interoperability and risk

This is a tunnel-local candidate schema pending Phase 0 registry/version review and independent vectors. It must not be represented as frozen, production-ready, or as G-E2E/G-NO-DOWNGRADE evidence. The underlying current backend and daemon integration remain separate gates. The role-byte assignments, fixed length, ordering and exact suite policy require protocol review before freeze. L3 encapsulation capability registry remains unspecified and must be defined before any product data-plane integration claims.
