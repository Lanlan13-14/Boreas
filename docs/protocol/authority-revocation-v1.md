# Authority-specific revocation candidate v1

Status: **candidate protocol with Linux runtime Identity/Core denial, scoped grant/lease checks and Identity-only mesh distribution; not a `G-REVOKE` claim.** The signed object is independent of `StatusSnapshot.revocations`, `objects::ObjectType` and the status-relay model. Production status policy continues to reject non-empty snapshot revocations. Core, Route and Direct decisions use local publication only.

## Why a separate object

Master plan §3.4 assigns each revocation class its own issuing authority: `IdentityAuthority` for identity revocation, `NetworkRoot` for Core revocation, `RouteAuthority` for route revocation, and the Core's own `CoreOperationalKey` for direct-grant revocation. A `StatusSnapshot` is signed only by `StatusSigner`, so it cannot prove any of those authorities. Carrying entries in a status snapshot only moves the ambiguity.

This candidate therefore defines one authority-specific object with an independent signature domain. It does not add an `objects::ObjectType` discriminant and does not reuse the `ManagementObject` envelope. The wire carrier is the canonical TBS bytes plus the mandatory Ed25519 and ML-DSA signatures; the exact TBS is what both signatures cover.

## Wire object

Canonical deterministic CBOR, unsigned integer keys, ascending:

```text
object = {0: version(1),
          1: net_id(16),
          2: class,                 ; 1 Identity | 2 Core | 3 Route | 4 Direct
          3: subject_node_id,
          4: identity_generation,   ; >= 1
          5: issuer_key_id,         ; <= 64 bytes
          6: issuer_generation,     ; >= 1
          7: scope,                 ; {0: prefix, 1: prefix_len, 2: core_id}
          8: seq,                   ; >= 1
          9: issued_at,
          10: next_update}          ; issued_at < next_update
```

`scope` always has the same three fields:

| class | `prefix` | `prefix_len` | `core_id` | meaning |
| --- | --- | --- | --- | --- |
| `Identity` | empty | 0 | 0 | every binding of `subject_node_id` / generation |
| `Core` | empty | 0 | 0 | a Core slot `subject_node_id` / generation |
| `Route` | exactly one prefix | canonical length | 0 | that one route prefix |
| `Direct` | empty | 0 | 1..=16 | grants issued by the named Core's exact issuer key ID/generation; **not** inferred from home Core |

Structural rules: `subject_node_id` must be a permanent overlay slot (home Core 1..=16, host octet 1 or 2..=251); a `Core` subject must be a Core slot (octet 1); a `Route` prefix is IPv4 `/8..=/32` or IPv6 `/48..=/128` with all host bits zero. `Identity`, `Core` and `Direct` require an empty prefix. `seq`, `identity_generation` and `issuer_generation` are non-zero. The schema version is 1; the whole map is mandatory.

The signature input is domain-separated:

```text
"BOREAS-AUTHORITY-REVOCATION\0" || u16(1) || u8(1) || u64(len(tbs)) || tbs
```

The object type byte is independent of `objects::ObjectType` and of the DNS authority profile. A signature over a management object, a status snapshot or a DNS object cannot be replayed as this object.

## Authority mapping

The verifier never accepts a caller-selected authority. It looks up the provisioned issuer record by `issuer_key_id`, requires the exact `issuer_generation`, and uses the existing permission mapping `boreas_pki::may_issue` / `may_issue_for_core`:

| class | required authority | scope check |
| --- | --- | --- |
| `Identity` | `IdentityAuthority` | The permanent node slot's role and home Core must both be delegated. |
| `Core` | `NetworkRoot` | The independently pinned root signs for a Core slot. Its issuer ID is the 32 fingerprint bytes, not their hex spelling; its issuer generation is `1`. |
| `Route` | `RouteAuthority` | The canonical prefix must be inside an authorized prefix pool of the same address family. The decision matches one exact grant prefix, not a subtree. |
| `Direct` | `CoreOperationalKey { core_id }` | The issuer's Core must equal the signed scope Core, never inferred from the beneficiary's home Core. |

The verifier checks canonical TBS, network, the half-open signed validity interval, the exact provisioned issuer key ID and generation, the issuer's half-open delegation window (if delegated), and the class and scope. It verifies Ed25519 **and** ML-DSA-65 over the exact domain-separated TBS before producing a token. Verified delegation tokens and the pinned root must agree on the root fingerprint regardless of installation order. The local `add_issuer` API is explicit out-of-band trust input, not a substitute for checking a root authorization in production. No snapshot signer or other fallback authority is accepted.

## Opaque token

`VerifiedAuthorityRevocation` has private fields and no public constructor. It exposes read-only getters for network, class, subject, identity generation, issuer key id/generation, the canonical class scope, sequence, the revocation object's validity window, the issuer grant's validity window, a digest of the exact TBS, and `is_fresh_at(now)`. There is no signing capability in the token.

The token proves only that this exact object and both signatures verified against a provisioned authority and that **both** the object and its issuer-grant intervals contained the caller-supplied UTC. It does **not** prove current freshness after the caller keeps it, durable anti-replay, global sequence monotonicity, clock trust or cleanup of any live resource. `freshness()` is the intersection of the object and issuer-grant windows, and `is_fresh_at` uses it. The daemon makes a separate durable acceptance decision before querying the resulting denial for its own endpoints.

## Linux daemon delivery and replay state

Publish optional regular files by atomic rename in the material directory (beside `status.signed`). Restrict write access to that directory. Each file carries one decision: eight header bytes, 64-byte Ed25519 signature, 3309-byte ML-DSA-65 signature, then exact canonical TBS.

| Mailbox | Header | Signed class |
| --- | --- | --- |
| `identity-revocation.signed` | `BRIR\0\0\0\x01` | Identity |
| `core-revocation.signed` | `BRSR\0\0\0\x01` | Core |
| `route-revocation.signed` | `BRSR\0\0\0\x01` | Route |
| `direct-revocation.signed` | `BRSR\0\0\0\x01` | Direct |

The mailbox name and header must match the signed class; neither is authority. Missing input is not an undo. Malformed, untrusted, conflicting or unpersistable input fails the gate, not as a new verified denial. A lower sequence is stale; the mesh runtime mailbox watcher treats it as a no-op only after successful verification against an already committed higher sequence for that exact scope.

Runtime verifiers are derived from the same root bundle and compare its fingerprint with the verified network context. New decisions require a fresh object and grant at the status store's effective trusted UTC. Under the same network/root, the replay key is `(class, issuer key ID, issuer generation, node ID, identity generation, canonical scope)`. Exact committed bytes are idempotent without renewal; the same TBS with different valid signatures is idempotent while fresh. A stale sequence or same-sequence different TBS cannot replace a committed decision. Input expiry limits admission, not the lifetime of a committed denial.

The private locked status store uses atomic staging, rename and fsync. It retains the v1 (no independent decisions) and v2 (Identity only) encodings, and writes v3 after the first Core, Route or Direct decision. It stores exact signed evidence, acceptance UTC and the root fingerprint. Reopen re-verifies each decision under the same root at its recorded acceptance time. The caps are 16 Identity records and 64 scoped records total, without eviction. An implementation without v3 support cannot read a v3 image. Whole-image rollback/deletion by the trusted state owner and historical issuer-key retention/rotation are outside this mechanism.

Both `serve` and `connect` check denials at startup and before forwarding on each authenticated E2E path. The existing watchdog polls the mailbox during business (normally 500 ms), checks the path's exact local and remote node generations, and uses its existing owned-socket shutdown and circuit error path. Invalid input or persistence errors use that same fault path. `connect` also checks the exact slots before and after a standby hop handshake, before taking a standby (including after a bounded wait), and around E2E admission. A watchdog fault is terminal rather than a failover event; normal ownership cleanup closes the standby, interrupts/joins any in-flight dial and releases socket credits. The backup is another ingress for the same authenticated peer, not a second Core. This is not a guarantee of instantaneous cessation of I/O already in flight or peer-wide cleanup.

## Explicit Core adjacency distribution and route denial

`boreas node mesh-probe` loads the optional material-directory mailbox and uses `state_dir/status.state`, opened with the same NetworkRoot-bound IdentityAuthority and StatusSigner grants as mesh admission. The store is exclusively owned; for the same node, it can supply local state to a daemon configured to use that exact path only when the other process is not holding the store lock. The generic `daemon serve|connect` does not implement this network exchange.

After strict pq768 hop authentication, Probe ping/pong and dual-signed LSA exchange, two explicitly configured Core neighbors exchange `IdentityRevocation` (`0x14`). The dialer sends its batch first; the listener receives and verifies before sending its batch. Body is `0x14 0x01 || BRIR carrier` (one unmodified committed decision) or exactly `0x14 0x00` (end). Max 16 evidence frames plus one end per direction; the body cap is 19,767 bytes. The existing absolute attempt, signed policy, status, identity and LSA cutoffs still apply. This candidate mesh extension uses a formerly reserved subtype; both peers must support it. An old peer or unexpected frame fails the adjacency, without a legacy `Revoke` fallback. No success state is inferred from a remote peer's end marker.

Every receiving Core independently checks and persists evidence using the same trust, scope, generation and admission window as local submission. Lower sequence on the wire is a no-op only after the full authority check and only when a newer denial for that exact authority/slot/generation is already durable. Invalid signatures/authority/scope, conflicts, unusable state, excess input and persistence errors fail the exchange. Batches are bounded but not atomic: a verified, committed denial survives a later rejected frame. The wire never conveys a peer's acceptance time. Relaying is limited to decisions still within the object and issuer-grant windows; expiration never lifts a local denial. No status, policy or LSA TTL renews through this exchange.

A committed denial of either endpoint rejects adjacency activation. Every member of an explicitly configured `FixedRoute` is checked at admission and at the existing forwarding/check boundaries, even if not an adjacent peer. A pre-authorized route does not bypass denial: a failing `forward_fixed` or `with_fixed_endpoint` call drops its owned dedicated adjacencies and admission credits. These are in-process route permissions for bounded transactions, not installed kernel routes. The control exchange runs before circuit start, not concurrently within a live fixed-route circuit.

## Runtime effect and limits

- **Identity / Core:** `daemon serve|connect` gate the authenticated endpoints. `mesh-run` also checks every authenticated path member and polls local mailboxes during active business I/O. A committed denial closes affected owned sockets; the source may rank a fresh path using only authorized members. A denied local generation stops business. Core denial concerns the exact Core generation, not all nodes homed there. Core decisions are not relayed by the Identity control frame: publish to every node at which the denial is needed.
- **Route:** the `StatusStore` query matches a verified RouteGrant and its authenticated beneficiary (network, node, identity generation), issuer key ID/generation and exact canonical prefix and length. Because grants do not encode beneficiary generation, the owner must retain the authenticated admission binding; a negative revocation query is not a freshness or admission decision. It does not remove a kernel route or a mesh CDN path. No live RouteGrant-owned Linux route manager consumes this query in this slice.
- **Direct:** the query matches a verified DirectGrant and its authenticated beneficiary, exact verified issuing Core, issuer key ID **and** generation. Another key on the same Core does not inherit the denial. Neither a CDN session nor a grant signed by another issuer is a matching binding. No live DirectGrant connector consumes this query in this slice.
- **Attachment lease:** the directory exposes a guarded cache lookup, separate from raw convergence/evidence views. It revalidates current signed lease and subject identity heads and denies a revoked owner or the lease owner's captured authenticated target Core generation. It does not delete evidence. The signed lease does not carry the target's identity generation; a consumer must retain the admission binding and must not rebind a cached lease to a successor Core identity. The current mesh directory exchange is CoreLSA-only and does not operate live attachment leases.

No scoped peer delivery, background gossip, partition/delivery guarantee, general resource registry or peer-wide teardown, issuer-history migration, or external monotonic rollback anchor. `IdentityAuthority` role scope is still derived from the permanent slot, not a separate role in the object. Root pin provenance and X.509 profiles are unchanged.

## Tests

The unit regressions cover canonical encoding, both signatures, exact class authority and grant lifetime, mismatched root/pin order, scope isolation, v2-to-v3 reopen, and stale/conflicting sequence handling. Direct tests distinguish the matching grant from a grant signed by another key on the same Core, the same key ID in a successor issuer generation, and a grant signed by a different Core. The live Identity tests retain adjacency distribution and held-resource teardown coverage. The Linux netns test publishes a local NetworkRoot-signed Core decision during business, checks cancellation and a fresh healthy path, verifies mailbox deletion/restart do not resurrect the denied path, and compares the administrator-installed route before and after. These regressions are intended for the repository's batched CI; this document does not claim a passing run.
