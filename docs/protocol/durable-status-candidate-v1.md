# Durable signed-status freshness store candidate v1

Status: implementation candidate, not frozen protocol and not production acceptance. Scope is durable freshness for signed `StatusSnapshot` objects only. `revocations` remains an opaque byte string; this store does not close TLS sessions, E2E circuits, leases or routes, does not implement a daemon or `BusinessGate`, and does not claim the `G-REVOKE` gate.

## Inputs, API and trust boundary

`boreas_pki::status_store::StatusStore` is exported only with `openssl-backend`. Its API exists on all targets, but durable operation is Linux-only: `open` and every other operation return `Unsupported` on macOS, Windows and other targets; there is no in-memory fallback.

`open(path, net_id, trusted_owner_uid, trust)` takes ownership of a `management::ManagementTrust`. The store accepts no caller boolean, no timestamp-only "verified" value, no cached `IssuerRecord` and no pluggable verifier. `trust.net_id()` must equal `net_id`. `trusted_owner_uid` is an independently provisioned expected local UID; this API does not discover the process effective UID.

`accept_signed_snapshot(raw_signed, trusted_utc_us, mono_now)` passes the exact original `SignedObject` envelope bytes to `ManagementTrust::verify_and_authorize`. That verifier requires the exact canonical TBS bytes, checks the issuer authority and generation, the network, `StatusSigner` authority for `ObjectType::StatusSnapshot`, the signed validity window, and both mandatory Ed25519 and ML-DSA signatures before it can return `management::Error::Equivocation`. The store then requires the envelope's `ManagementObject`/`StatusSnapshot` fields to agree, checks sequence and signed-issued monotonicity, and durably commits before returning `Accepted`. `trusted_utc_us` must come from the caller's independent trusted time boundary; `mono_now` is used only for the process-local `Instant` deadline.

`SnapshotResult::DuplicateNotRenewed` is returned for the same sequence and same TBS SHA-256 (`object_id`), including a re-signed but logically identical envelope. It never extends lifetime. Lower sequence returns `SequenceNotIncreasing`; a lower signed `issued_at` returns `SnapshotIssuedAtRegression`; the verifier also rejects those conditions itself.

`observe_trusted_utc(utc_us)` persists a monotonic trusted-UTC floor before use. A value more than `CLOCK_ROLLBACK_TOLERANCE_US` below the persisted floor persists a rollback latch and returns `ClockRollback`; further observations fail while latched. A caller-side fresh `TrustedUtc` cannot clear this latch. `recover_trusted_utc(utc_us)` is the explicit recovery boundary: it requires `utc_us >= persisted_floor`, can release only the rollback latch, can never lower the floor, and never clears an equivocation freeze. The API cannot determine whether the supplied UTC is genuinely trustworthy; the caller must establish that externally.

`current_fresh(trusted_utc_us, mono_now)` is `&mut self` because it first persists the trusted-UTC observation/latch, then requires a persisted snapshot and computes remaining signed lifetime. It initializes or tightens an in-process `Instant` deadline with `min(existing_deadline, mono_now + (next_update - effective_now))`. A restart with a still-valid persisted snapshot therefore becomes fresh without a new `accept_signed_snapshot`; an already-expired snapshot remains expired. An accepted new sequence may legitimately establish a new deadline; a duplicate does not.

`FreshStatus` is a private-field, non-Clone borrow tied to the store. Business code must call `check(trusted_utc_us, mono_now)` at every business boundary (including each packet). `check` is read-only and rechecks poison, freeze, rollback latch, sequence/epoch, the signed UTC window, the persisted floor and the captured monotonic deadline. A large rollback (`trusted_utc_us + CLOCK_ROLLBACK_TOLERANCE_US < persisted_floor`) returns `ClockRollback`; otherwise `check` evaluates the signed window at `effective_now = max(trusted_utc_us, persisted_floor)`, matching `current_fresh`'s tolerated-rollback behavior. The same `(trusted_utc_us, mono_now)` pair that `current_fresh` accepts therefore also passes `check` at that instant. `check` cannot persist a latch; when it rejects for clock rollback, the owner must drop the token and notify the store via `observe_trusted_utc` (or explicitly recover through `recover_trusted_utc`) and must not clear the condition itself.

Because the token borrows the store immutably while `accept_signed_snapshot` and `current_fresh` require `&mut self`, a new snapshot cannot be accepted while the token is alive. This is an interface limitation, not a claim that the token is concurrently updated and automatically invalidated; a new snapshot can only be accepted after the token is dropped, and `check`'s sequence/epoch recheck is defensive. The per-packet owner wiring is therefore: hold the token, call `check` at each business use, and on a clock rejection drop the token and arrange a durable `observe_trusted_utc` before business may resume. `current_fresh` may persist/fsync the floor on each call when the floor advances, so it is an admission/refresh call and not a per-packet call.

## Freshness and clock inequalities

The persisted floor is the latest trusted observation, so the correct invariants are:

- `issued_at <= effective_now < next_update`; and
- `persisted_utc_floor >= issued_at`.

`effective_now` is the value returned by the store's monotonic observation path: the persisted floor after taking a non-rollback trusted input. A trusted input later than the floor raises it; a tolerated small rollback keeps the higher floor rather than lowering it. `current_fresh`/`check` never accept `effective_now < issued_at`, and never grant lifetime from a receive time clock.

On restart, the bounded image is decoded, but no disk field grants freshness. The persisted raw snapshot is re-verified by the owned `ManagementTrust` at its own signed `issued_at` boundary (never at the current time), and a `Snapshot` is rebuilt from the returned `VerifiedObject`. Every persisted field (network, issuer key id, issuer generation, sequence, `object_id`, signed `issued_at`, signed `next_update`, exact raw envelope) must match the rebuilt value, and the persisted floor must be at or above the rebuilt `issued_at`; otherwise the open fails closed as corrupt. Current freshness is then decided only by `effective_now` and the saved `next_update`, plus the monotonic deadline.

Without an external monotonic anchor, restoring an older whole-disk image (including its floor and latch) cannot be detected by this module. It makes no claim to detect that rollback.

## Same-sequence conflict / signer identity

A same-sequence/different-content candidate is evidence only when the candidate's issuer key id and issuer generation match the persisted snapshot exactly. For that case the store structurally decodes the candidate and calls `ManagementTrust::verify_and_authorize` at the candidate's own signed `issued_at`. `management::Error::Equivocation` is required; the verifier checks authority, network, type, signed window and both signatures before returning it. The store then atomically persists the older exact envelope (already in the snapshot) and the new exact envelope as evidence, and freezes. The verifier's single overwritten `conflict_evidence` slot is not used as storage. The conflicting evidence may be outside the current freshness window; it is evidence only and never becomes fresh.

Invalid Ed25519/ML-DSA signatures, wrong issuer/type/network, malformed bytes or non-conflicting bytes are not frozen. A different StatusSigner identity at the same sequence is rejected as `BadStatus` without touching the verifier's replay slot and without freezing: signer rotation versus global/per-signer sequence scope is not frozen in this candidate. The master plan currently describes a single `StatusSigner` role; `ManagementTrust` currently keys the `StatusSnapshot` replay slot globally, so a higher sequence from another authorized signer follows the verifier's normal global-slot path. That sequence-scope question remains open and is not claimed as protocol final.

## Disk format candidate

All integers are unsigned big-endian. The image is bounded by `MAX_STATUS_STATE_BYTES` (64 KiB):

```text
"BRSS\0\0\0\x01" || net_id[16] || utc_floor:u64 || flags:u8
  if flags.has_snapshot:
      issuer_len:u16 || issuer_key_id (<=64 bytes)
      issuer_generation:u64 || seq:u64 || object_id[32]
      issued:u64 || next_update:u64
      raw_envelope_len:u32 || exact raw SignedObject envelope (<=16 KiB)
      if flags.has_equivocation:
          second_raw_envelope_len:u32 || exact second raw envelope (<=16 KiB)
```

Flags: bit 0 rollback latched, bit 1 has snapshot, bit 2 has equivocation. A state with no snapshot is represented by `has_snapshot = 0` and no snapshot fields; an equivocation flag without a snapshot is corrupt. A legitimate signed sequence value of 0 is not used as an empty sentinel and is not confused with "no snapshot".

Unknown flags, trailing bytes, malformed/torn lengths, a zero/oversized issuer or raw envelope, an invalid `issued_at`/`next_update` window, a zero issuer generation, or `utc_floor < issued_at` fail closed. The exact raw envelopes are retained; no re-encoded substitute is written. `object_id` is SHA-256 of the exact TBS bytes.

## Storage and durability

On Linux only, the path must be absolute. Each parent component is checked as a non-symlink directory and may be non-writable by untrusted users, with root-owned sticky directories such as `/tmp` allowed. The canonical final directory must be owned by `trusted_owner_uid` with no group/other permissions. The final state file and persistent sidecar lock must be single-link regular files mode 0600 owned by that UID.

Opens use `O_NOFOLLOW` plus `O_NONBLOCK`; reads are bounded by the state cap. A persistent `.lock` sidecar advisory exclusive lock is held for the store lifetime and is never unlinked. Commit order is: encode and bound the full next image; reject any pre-existing `.staging`; create a same-directory staging file with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode 0600; write all; `sync_all` the staging file; atomic rename over the state path; `sync_all` the parent directory. If a crash leaves `.staging` behind, the next open refuses it rather than deleting, adopting or auto-recovering unauthenticated staging bytes. Operator recovery must inspect and remove only the verified stale file while holding the exclusive store lock.

A failed operation poisons the instance: `ManagementTrust`'s process-local replay may already have advanced, so no further business decision is allowed. Before rename the previous state remains; after rename but before a successful directory sync the outcome is uncertain, so use stops and reopen/recovery is required. A failed operation never opens the business gate.

## Boundaries, tests and open issues

This candidate does not apply revocations to actual sessions/circuits/leases/routes, does not implement the `BusinessGate`, does not integrate with `NodeRuntime`, and does not validate TLS certificates. It also does not attest the external trusted-time source, provide cross-host consensus, or detect whole-disk rollback without an independent monotonic anchor.

Linux tests (Actions-only; no local cargo/test/formatter claimed here) cover real generated Ed25519+ML-DSA signing keys and: accept + duplicate/no-renew; restart still-fresh without a new accept and restart expiry; same-sequence different-content both-envelope evidence and freeze across reopen; different StatusSigner at the same sequence rejected without freeze; lower sequence/issued regression; UTC rollback latch across reopen plus explicit recovery that cannot lower the floor; injected persist failure poisoning and reopen from the last durable state; wrong network, wrong authority, bad Ed25519 and bad ML-DSA; unsafe path/symlink/mode/owner/oversize/trailing-byte/tampered-raw; leftover staging; and codec round-trip/trailing bytes. These are candidate tests pending the repository's GitHub Actions run, not gate evidence.
