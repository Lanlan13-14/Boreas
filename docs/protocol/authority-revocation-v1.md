# Authority-specific revocation candidate v1 (Identity enabled)

Status: **candidate protocol with a bounded Linux daemon Identity slice; not a `G-REVOKE` claim.** The signed object is independent of `StatusSnapshot.revocations`, `objects::ObjectType` and the status-relay model. The daemon's production status policy continues to reject any non-empty snapshot revocations.

Only the `Identity` class is enabled. `Core`, `Route` and `Direct` have schema bytes so a later assignment cannot silently change the wire shape, but `AuthorityRevocationTrust::verify` returns `UnsupportedClass` for them. There is no caller boolean and no fallback authority path.

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
| `Direct` | empty | 0 | 1..=16 | grants issued by that Core; **not** inferred from home Core |

Structural rules: `subject_node_id` must be a permanent overlay slot (home Core 1..=16, host octet 1 or 2..=251); a `Core` subject must be a Core slot (octet 1); a `Route` prefix is IPv4 `/8..=/32` or IPv6 `/48..=/128` with all host bits zero. `Identity`, `Core` and `Direct` require an empty prefix. `seq`, `identity_generation` and `issuer_generation` are non-zero. The schema version is 1; the whole map is mandatory.

The signature input is domain-separated:

```text
"BOREAS-AUTHORITY-REVOCATION\0" || u16(1) || u8(1) || u64(len(tbs)) || tbs
```

The object type byte is independent of `objects::ObjectType` and of the DNS authority profile. A signature over a management object, a status snapshot or a DNS object cannot be replayed as this object.

## Authority mapping

The verifier never accepts a caller-selected authority. It looks up the provisioned issuer record by `issuer_key_id`, requires the exact `issuer_generation`, and uses the existing permission mapping `boreas_pki::may_issue` / `may_issue_for_core`:

| class | required authority | status |
| --- | --- | --- |
| `Identity` | `IdentityAuthority` | enabled |
| `Core` | `NetworkRoot` | schema-reserved; `UnsupportedClass` |
| `Route` | `RouteAuthority` | schema-reserved; `UnsupportedClass` |
| `Direct` | `CoreOperationalKey { core_id }` | schema-reserved; `UnsupportedClass`; must eventually use the signing Core itself, never `home_core_id` |

`may_issue` already says `IdentityAuthority` may issue `IdentityRevocation`, `NetworkRoot` may issue `CoreRevocation`, and `RouteAuthority` may issue `RouteRevocation`. `may_issue_for_core` requires `CoreOperationalKey { core_id }` to equal the target Core for `DirectRevocation`; that is the future self-issuer rule. None of these is a caller boolean.

## Identity slice (enabled)

`AuthorityRevocationTrust::add_issuer(record, not_before, expires)` accepts only an IdentityAuthority record. It requires an identity `IssuerScope` with at least one allowed role and one allowed home Core and no route prefixes, and a non-empty half-open grant window. It uses the existing `ManagementTrust::add_issuer` to parse and algorithm-check both Ed25519 and ML-DSA public keys and reject duplicate key ids.

The issuer grant validity is **not** a field of `IssuerRecord`. The trust must therefore retain `not_before`/`expires` alongside the record, and every verification checks `not_before <= now < expires`. `add_verified_issuer` takes the window directly from `VerifiedIssuerAuthorization::validity()`; converting that token to `IssuerRecord` must not discard it. An expired or not-yet-valid root-authorization grant yields `IssuerNotValid` even when the revocation object itself is inside its own window.

`AuthorityRevocationTrust::verify` then:

1. decodes the exact canonical TBS and rejects any non-canonical re-encoding;
2. requires class `Identity` (`UnsupportedClass` for others);
3. requires the trust network and the revocation object's half-open signed interval containing `now`;
4. requires the exact issuer key id and generation and `may_issue(authority, IdentityRevocation)`;
5. requires the issuer grant window to contain `now`;
6. re-derives the subject's permanent home Core and role from `subject_node_id` and requires both in the issuer scope;
7. verifies Ed25519 **and** ML-DSA-65 over the domain-separated exact TBS;
8. returns an opaque `VerifiedAuthorityRevocation` only if every check passed.

## Opaque token

`VerifiedAuthorityRevocation` has private fields and no public constructor. It exposes read-only getters for network, class, subject, identity generation, issuer key id/generation, the canonical class scope, sequence, the revocation object's validity window, the issuer grant's validity window, a digest of the exact TBS, and `is_fresh_at(now)`. There is no signing capability in the token.

The token proves only that this exact object and both signatures verified against a provisioned authority and that **both** the object and its issuer-grant intervals contained the caller-supplied UTC. It does **not** prove current freshness after the caller keeps it, durable anti-replay, global sequence monotonicity, clock trust or cleanup of any live resource. `freshness()` is the intersection of the object and issuer-grant windows, and `is_fresh_at` uses it. The daemon makes a separate durable acceptance decision before querying the resulting denial for its own endpoints.

## Linux daemon delivery and replay state

Publish an optional regular file `identity-revocation.signed` in `--material-dir` by atomic rename. The local carrier is `BRIR\0\0\0\x01` (eight bytes), followed by the 64-byte Ed25519 signature, the 3309-byte ML-DSA-65 signature, and the exact canonical TBS. The carrier is not a network message. Missing input is not an undo; malformed, untrusted, stale, conflicting or unpersistable input halts the gated daemon without reporting a new verified denial. Restrict write access to the material directory.

The daemon derives both verifiers from one read of the root bundle, compares its fingerprint with the verified identity's exact root, and adds only verified IdentityAuthority grants to the independent verifier. New decisions require a fresh object and grant at the status store's effective trusted UTC. Sequence increases per `(issuer key id, issuer generation, node id, identity generation)` under that network/root. Exact already-committed evidence is idempotent and does not renew anything; the same TBS with different valid signatures is also idempotent while fresh. Lower sequences and same-sequence different TBS are errors; neither replaces the committed decision. Decisions are terminal for the exact generation once committed: input expiry prevents new acceptance but does not reinstate the identity. Issue a new identity generation to recover that slot.

The existing private locked status state uses its existing atomic staging/rename/fsync procedure. A v1 image stays unchanged until the first independently verified decision, then the v2 image stores bounded exact signed evidence, acceptance UTC and the root fingerprint. Reopen re-verifies evidence against the same root and issuer grant at the recorded acceptance time; current startup trust verification remains unchanged. Up to 16 authority/scope records are retained without eviction; capacity exhaustion fails closed. Older implementations that do not support v2 refuse the image. Whole-image rollback/deletion by the trusted state owner is outside this mechanism.

Both `serve` and `connect` check denials at startup and before forwarding on each authenticated E2E path. The existing watchdog polls the mailbox during business (normally 500 ms), checks the path's exact local and remote node generations, and uses its existing owned-socket shutdown and circuit error path. Invalid input or persistence errors use that same fault path. This is not a guarantee of instantaneous cessation of I/O already in flight, peer-wide cleanup, or delivery to other daemons.

## Non-Identity classes are fail-closed

`Core`, `Route` and `Direct` have schema bytes so a future assignment cannot silently change the wire shape, but this verifier returns `UnsupportedClass` before minting any token. No partially checked token exists. In particular:

- a correctly signed Direct object is not accepted, so a roaming Core cannot be confused with the subject's home Core;
- a correctly signed Route object is not accepted until the single-prefix scope evidence and durable route handles are implemented;
- a NetworkRoot-signed Core object is not accepted until the Core scope semantics are frozen.

This is deliberate: "no evidence" means no token, not a weaker bool.

## What is not implemented

- No network distribution, partition guarantee, arbitrary-capacity journal, retention/rotation workflow for historical issuer authorizations, or external monotonic rollback anchor.
- No general registry-based cleanup of all sockets, circuits, grants, leases or routes; no `G-REVOKE` claim.
- No Core, Route or Direct token issuance in v1.
- `IdentityAuthority` role scope is derived from the permanent node slot (octet 1 = Core, 2..=251 = Edge); the object does not carry a separate role byte. A future role-bearing identity profile may tighten this.
- Root pin provenance, certificate-chain validation and key rotation are unchanged from the existing PKI candidates.

## Tests

Actions-only; no local `cargo build`/`test`/`fmt` claim. The proto module covers canonical round trip, the independent signature input, class/scope structural rules, and truncated/trailing/non-canonical rejection. The pki module covers a real Ed25519 + ML-DSA-65 positive Identity token, independent Ed25519 and ML-DSA failures, network/time/issuer-generation/scope failures, the issuer-grant `not_before`/`expires` bound for both `add_issuer` and `add_verified_issuer`, and rejection of non-Identity classes and non-IdentityAuthority records. These are candidate tests pending the repository's GitHub Actions run, not gate evidence.
