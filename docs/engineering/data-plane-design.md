# Data-plane state primitives: limits and integration boundary

This note describes the pure state types added under `crates/boreas-tunnel/src/`. They are not a functioning network data plane. There is no TLS implementation, socket/WebSocket path, TUN device, kernel route installation, cryptographic circuit ID generation, or production resource audit. All plan gates remain open; see [the v1.11 master plan](../plans/BOREAS-MASTER-PLAN-v1.11.0.md) §11 and [the implementation gate ledger](implementation-status.md).

## Resource admission (`resource.rs`)

- `Admission` is a cloneable global ledger with mutex-protected counters and RAII guards.
- `reserve_handshake()` reserves a single global unauthenticated handshake credit. It accepts no claimed identity/key ID, so an unauthenticated peer cannot debit another peer's quota.
- `HandshakeCredit::authenticate()` converts the global reservation to global and per-verified-peer authenticated connection counts. There is no production `AuthenticatedPeer` constructor yet; tests use a private `cfg(test)` constructor. A future trusted identity-verification integration must be the only production source, and no public method currently manufactures it from network data.
- `ByteCredit` holds the global byte charge for the full lifetime of an owned queue/circuit reservation and releases on drop. Relay payloads move out as `PreopenPayload`, which owns both bytes and credit; the charge remains held while the payload remains live, even after queue consumption or reset.
- The mutex serializes admission decisions; this is a first correctness primitive, not proof of lock latency or global process memory enforcement. Select limits from measured budgets and include allocator/transport overhead separately.

## Scheduler (`scheduler.rs`)

`DrrScheduler` is FIFO within each flow, uses byte deficits/quantum across flows, rejects zero-byte items to prevent metadata-only queue growth, and applies fixed packet/byte/flow and queue-age bounds. It is deliberately **not an RFC 8290 FQ-CoDel implementation**: no hash classifier, CoDel control law, ECN, or socket integration is provided. It rejects zero-byte entries to prevent metadata-only queue growth and refuses zero quantum/zero capacity configuration. It does not silently discard ciphertext. `DequeueError::QueueAgeExceeded { flow_id }` identifies the flow to reset. `DequeueResult::PendingCredit` is distinct from `Empty` and means backlog remains but needs another bounded dequeue pass; callers must reschedule without waiting for a new arrival. Once an age failure occurs, the caller must reset the logical flow/circuit and explicitly purge it; purged payloads are returned for caller-directed disposal and are never reported as delivered. The caller should preserve ordering for a given flow and must not retransmit stale ciphertext under a new session.

## Relay circuit lifecycle (`relay.rs`)

- `CircuitId` is a caller-provided 128-bit value. The production caller must generate it with an OS CSPRNG; this module does not generate IDs or authenticate them.
- Circuit endpoints bind `NodeID` plus `identity_generation`; equal NodeIDs are rejected even if generations differ. Circuit pairs are canonicalized regardless of direction; default is **one** circuit per pair, and configuration accepts only `1..=4`. The table also has a global hard circuit limit. Integrators must still ensure endpoint claims came from verified objects.
- Hop budget must be in `1..=8`; forwarding decrements it and exhaustion resets/fails closed.
- Each direction has an independent `u64` byte offset. Segments are accepted only at the exact next offset and only for the bound source, destination and generations. This records metadata continuity; it does not authenticate ciphertext or validate a TLS record.
- Before establishment, queue payload is limited to 64 KiB per circuit **and across all circuits of one canonical peer pair**, at most 128 queued entries per pair, globally charged by `ByteCredit`, and expires two seconds after opening. Empty payloads are rejected to prevent unbounded metadata-only entries. Establishment after the two-second deadline fails closed. Queue payload is not application delivery.
- Circuit lifecycle is capped at 900 seconds. The state method `mark_established` means only that the table transitioned state; it is **not** evidence of E2E TLS. `consume_preopen` and `accept_segment` require an opaque `VerifiedE2eSession` capability with no public constructor. Only a future TLS integration in the trusted crate boundary may produce it; until then production traffic cannot enter or leave as active E2E.
- A real implementation still needs pair accounting tied to authenticated peer sessions, simultaneous-open tie-breaking, reset propagation, replay/offset failure policy, TLS/E2E identity binding, cancellation/race behavior, and persistence/restart semantics as applicable.

## Test and release boundary

Unit tests use injected `Instant` values for deterministic age/expiry transitions. No local build or tests are run by this delegated task; CI must format, compile, lint and test the workspace. Passing these unit tests would establish only these isolated state invariants, not the plan's `G-RESOURCE`, `G-DATA`, `G-PERF`, `G-E2E` or production release gates. Do not claim successful TLS/E2E, bounded total process RSS, RFC 8290 compliance, static TLS builds, or completed Phase 0.
