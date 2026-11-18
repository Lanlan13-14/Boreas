# Bounded revocations in `StatusSnapshot` — test-only model v1

Status: **test-only model and schema candidate, not protocol, not runtime enablement and not production acceptance.** It does not claim the `G-REVOKE` gate, does not close TLS sockets, does not remove kernel routes, and does not assert that every session, circuit, lease or route of a revoked peer was cleaned up. No daemon path consumes it.

## Why this is not production

Master plan §3.4 assigns each revocation class its own signing authority: `IdentityAuthority` for identity revocation, `NetworkRoot` for Core revocation, `RouteAuthority` for route revocation, and the Core's own `CoreOperationalKey` for direct-grant revocation. A `StatusSnapshot` is signed only by the network `StatusSigner`, and `ObjectKind::StatusSnapshot` is the single object kind that authority may issue. The envelope therefore proves exactly one thing: a `StatusSigner` asserted these bytes. It proves nothing about the other four authorities.

Consequently the snapshot's Ed25519 + ML-DSA signatures are **not** authority evidence for any entry in the `revocations` byte string. This candidate does not pretend otherwise:

- `StatusStore::open` authorizes **no** class. A snapshot carrying a non-empty revocation payload is refused with `status_store::Error::RevocationPermission` before the trusted verifier records replay state. No revocation state is written.
- The accepting helper `StatusStore::open_with_revocation_relay` is compiled only for Linux unit tests, and `RevocationRelayPolicy` exposes **no constructor that enables a class**: its fields are private, so a non-`none` policy can only be built inside this crate's test modules. There is no `RevocationRelayPolicy::all` in the API. This is not deployment configuration and not a trust input. Production code can only call `StatusStore::open`, which uses `RevocationRelayPolicy::none()`.
- Tests may exercise the bounded schema and the merge model, but a test-only relay policy is not a claim that the `StatusSigner` holds any of the four authorities.
- There is no daemon enablement. `StatusStore` is opened by the daemon with `StatusStore::open` (default deny); `peer_revocation` has no runtime consumer.

The sound long-term fix is a per-authority revocation object (`IdentityRevocation`, `CoreRevocation`, `RouteRevocation`, `DirectRevocation`) or a per-entry authority signature. That is an open protocol issue, not implemented here.

## `Direct` is refused, not inferred from `home_core_id`

The subject's `home_core_id` is the Core that owns its permanent node slot. It is **not** the issuer of the subject's `DirectGrant`: a roaming Core may sign a `DirectGrant` that covers the same subject, and this schema carries no grant-issuer evidence. Treating `origin_core == home_core_id(node_id)` as authority would mislabel a roaming Core's decision as the home Core's.

Therefore v1 keeps wire code `4` reserved but rejects every `Direct` entry with `revocation::Error::DirectIssuerUnverifiable`. `boreas_pki::revoke_cleanup::VerifiedRevocationScope::permitted()` also refuses `Direct`, and `apply_verified_scoped` returns `ApplyResult::RefusedOutOfScope` without touching the table. Direct-grant revocation must wait for a per-authority `DirectRevocation` object or equivalent per-grant issuer proof.

`DropSet::direct_grants` still exists because an `Identity` or `Core` decision may legitimately clear direct-grant ids for a node those authorities cover.

## Where the entries live and what proves them

The entries are a sub-schema of the `revocations` `bstr` of `ObjectType::StatusSnapshot` / `ObjectBody::StatusSnapshot`. That byte string is part of the object TBS, so every entry is covered by the enclosing object's mandatory Ed25519 **and** ML-DSA signatures over the exact TBS bytes. There is no separate entry signature and no detached signature file.

`boreas_pki::status_store::StatusStore` decodes entries only from a `VerifiedObject` produced by `ManagementTrust::verify_and_authorize` for the exact raw envelope: canonical TBS, issuer authority for `StatusSnapshot`, issuer generation, network, signed validity window, object type and both signatures are checked first. The store additionally re-encodes the decoded object and requires byte equality with the verified TBS before decoding entries, so no re-encoded substitute is trusted. A payload that cannot be decoded, or a class the policy does not allow, is rejected before the owned verifier records replay state.

This authenticates the enclosing `StatusSigner` snapshot. It does not authenticate the entry's claimed class authority; that is the unresolved §3.4 gap.

## Schema

Canonical deterministic CBOR, unsigned integer keys, ascending:

```text
payload = {0: version(1), 1: [entry*]}      ; entry count <= 64, payload <= 8 KiB
entry   = {0: class,               ; 1 Identity | 2 Core | 3 Route | 4 Direct
           1: origin_core,          ; 0 authority-issued, 1..=16 core-scoped
           2: node_id,              ; permanent overlay node slot
           3: identity_generation,  ; >= 1
           4: target_id,            ; class-specific; 0 when the class has none
           5: epoch,                ; >= 1, per-scope watermark
           6: reason}               ; <= 255, 0 = unspecified
```

Class and scope rules (enforced while decoding, so an invalid payload never reaches policy code):

| class | `origin_core` | `target_id` | may clear |
| --- | --- | --- | --- |
| `Identity` | must be 0 | must be 0 | sessions, circuits, leases, direct grants and route prefixes of the subject |
| `Core` | must equal the node's home Core | must be 0 | sessions, circuits, leases and direct grants of that Core's own node; never route prefixes, never another Core's node |
| `Route` | must be 0 | route-prefix id, or 0 for every prefix of the subject | route-prefix ids only |
| `Direct` | rejected (wire code reserved) | rejected | none in v1; see above |

Additional rules: `node_id` must be a permanent overlay slot (home Core 1..=16, host octet 1 or 2..=251), `identity_generation >= 1`, `epoch >= 1`, entries unique and strictly ascending by `(class, origin_core, node_id, identity_generation)`. Unknown classes, an unknown payload version, non-shortest integers, unsorted or duplicate entries, trailing bytes, and an explicitly encoded empty array are all rejected; the canonical empty payload is the zero-length byte string. A decoder enforces the round trip `decode(bytes).encode() == bytes`.

## Replay, rollback and equivocation (model only)

The model keeps, in memory, per scope key `(class, origin_core, node_id, identity_generation)`, the highest accepted `epoch` plus the SHA-256 of that entry's canonical bytes. The bound is 64 scopes; a payload that would add a 65th is refused with `RevocationTooLarge` and changes nothing.

- **Replay.** Re-delivering the same decision (same scope, same epoch, same bytes) at any sequence is idempotent within the process: no duplicate scope, no state change, the snapshot is still accepted.
- **Rollback.** An entry whose `epoch` is below the in-memory watermark for its scope is refused with `RevocationStale`; the whole payload is rejected and no partial mutation is applied. A decision is never withdrawn during the process: a later payload that omits a scope cannot un-revoke it, because the scope set only grows in memory.
- **Equivocation.** Two different decisions for one scope and one epoch (different canonical bytes) latch an in-memory conflict: both digests and the winning scope are retained, the store freezes (`is_frozen()`, `is_revocation_conflicted()`, `revocation_conflict()`) and further `accept_signed_snapshot`/`current_fresh`/`peer_revocation` fail closed **in that process**. The latch is not persisted; a restart does not preserve it.
- **Atomicity.** The accepted snapshot is written atomically. The revocation model is not part of that write, so there is no claim that a revocation decision or a conflict survives a crash.

## Durable image: unchanged v1, no revocation block

The existing `BRSS\0\0\0\x01` image is unchanged. This candidate adds **no** flag bit and **no** revocation block, so an older decoder cannot encounter an unknown flag or a new version. The revocation model is memory-only and is not written by `encode`.

On open, the persisted snapshot is re-verified at its own signed `issued_at`, and then the model is rebuilt **only** from that exact signed TBS:

- every entry in that payload must still be allowed by the current policy, else `RevocationPermission` (production `open` therefore refuses a persisted snapshot carrying entries);
- entries in this payload are reconstructed from the re-verified TBS, so those entries are covered by the snapshot signature just checked;
- entries contributed by *earlier* payloads are not persisted, are not re-derived, and are not claimed as `Verified`. After a restart they are absent. The same is true of a conflict latch.

There is no durable revocation watermark and no digest-only historical scope. Whole-disk rollback to an older but internally consistent image is still undetectable without an external monotonic anchor, exactly as for snapshot freshness.

## Daemon query (not wired)

`StatusStore::peer_revocation(&AuthenticatedPeer) -> PeerRevocation` answers "what does the model's verified state say about this already authenticated peer?". `AuthenticatedPeer::new(net_id, node_id, identity_generation)` refuses a malformed slot or a zero generation, and the caller must fill it from the verified certificate chain, never from a peer message. `FreshStatus::peer_revocation` gives the same answer from the snapshot that the freshness token covers.

```rust
let peer = AuthenticatedPeer::new(net_id, cert_node_id, cert_identity_generation)
    .ok_or("unauthenticated peer facts")?;
match store.peer_revocation(&peer) {
    PeerRevocation::Verified(state) => {
        // categories are separate: a route-only decision is not a session decision
        if state.sessions_revoked() {
            return Err("revoked peer");
        }
        if state.any() {
            // identifiers for this peer may be dropped; see the cleanup registry
        }
    }
    PeerRevocation::Unknown(_) => return Err("revocation state unavailable"),
}
```

`PeerRevocation::Verified` means the enclosing snapshot was verified and the entry was present in the accepted payload (or in the latest persisted snapshot at open). It is **not** a per-authority signature and does **not** cover earlier payloads after restart. Its `direct` field is always `false` in v1 because the schema refuses `Direct`. `Unknown` is always fail-closed and distinguishes `NoSnapshot`, `WrongNetwork`, `Frozen`, `Poisoned` and `ClockLatched`. A revocation decision is permanent during one process, so a positive answer stays true even after the snapshot stops being fresh; a *negative* answer is only as good as that snapshot, which is why admission would need the token. `revocation_scopes()` returns the bounded in-memory list and `revoked_scope_count()` its size.

This query has no daemon caller in this candidate. Wiring it to admission or cleanup would require the per-authority evidence above.

## Cleanup application

`boreas_pki::revoke_cleanup::apply_verified_scoped(&mut CleanupTable, &VerifiedRevocationScope)` applies one scope with the class-limited category set from the table above. It re-checks `VerifiedRevocationScope::permitted()` itself, so a forged scope cannot borrow another class's category set: a Core-class decision naming another Core's node returns `ApplyResult::RefusedOutOfScope` and leaves the table unchanged. `Route` with a non-zero `target_id` removes only that route-prefix id. `Direct` is always `RefusedOutOfScope`; the home Core is not the grant issuer. `apply_verified` (the pre-existing subject-wide path) and `apply_unverified` keep their behaviour; the unverified path still never disconnects anything.

The table holds identifiers, not live sockets, leases or installed routes. Wiring a scope to an actual socket shutdown or route removal is runtime work outside this candidate, and nothing here claims that all of a peer's sessions or routes were cleaned up.

## Tests

Actions-only; no local `cargo build`/`test`/`fmt` claim. `crates/boreas-proto/src/revocation.rs` covers canonical encode/decode round trip, the supported classes, sorting and duplicate scope keys, permission rejections (Core crossing, missing/forbidden `target_id`, non-zero `origin_core` for authority classes, invalid node slot, zero generation, zero epoch), the `Direct` rejection even when `origin_core` equals the node's home Core, unknown class and version, unsorted/trailing/non-shortest/truncated encodings, the entry-count and payload-size bounds, and per-entry canonical digest stability.

`crates/boreas-pki/src/status_store.rs` covers, with real generated Ed25519 + ML-DSA keys and a real dual-signed envelope: a payload refused with `RevocationPermission` under production `open`; the positive model path under the test-only policy with per-class query answers and generation scoping; corrupted ML-DSA and Ed25519 signatures refused with no state change; restart rebuild from the persisted signed snapshot; a tightened policy refused on reopen; `RevocationStale` for a lower epoch with no mutation; idempotent replay at a higher sequence; a latched `RevocationConflict` that freezes the process, with the explicit test that the latch and historical scopes are not persisted across restart; the 64-scope bound; `NoSnapshot`/`WrongNetwork`/`ClockLatched` fail-closed answers; a pre-feature image still opening; and a non-empty in-memory model producing exactly the same v1 image bytes as an empty one. `crates/boreas-pki/src/revoke_cleanup.rs` covers the class-limited drop sets, Core-crossing refusal, and `Direct` refusal even when `origin_core` matches `home_core_id`.

These are candidate tests pending the repository's GitHub Actions run, not gate evidence.

## Open issues

1. Per-authority attribution: entries carry no signature of their own, so consumption cannot rest on a `StatusSnapshot` relay policy. Per-authority revocation objects (`IdentityRevocation`/`RouteRevocation`/`CoreRevocation`/`DirectRevocation` already exist as `ObjectKind` values but have no CBOR body) or a per-entry authority signature are required before any runtime path is enabled.
2. `DirectRevocation` issuer binding: the grant issuer (which Core signed the `DirectGrant`) must be carried and verified; the subject's `home_core_id` is not that issuer.
3. Whether a snapshot must repeat earlier decisions (delta versus cumulative) is not frozen. This model keeps a monotone union only in memory; after restart only the latest persisted payload is known.
4. Whether `epoch` namespaces are per authority, per signer or global is not frozen.
5. Durable revocation watermarks and conflict evidence need a versioned image extension with an independently re-verifiable authority proof; this candidate deliberately stops persisting them.
6. `Reason` codes have no registry yet; they are bounded audit bytes only.
