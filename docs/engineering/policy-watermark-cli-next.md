# Policy watermark CLI wiring — next step

**Status:** design proposal; no runtime behavior is implied.  
**Scope:** connect the existing offline policy verifier to the Linux durable anti-replay store in `boreas pki verify-policy`. This is deliberately not daemon policy activation.

## Why this is the next runtime step

The current CLI `verify-policy` reads the TBS, two signatures, network id, and two root DER keys, builds an operator-supplied `NetworkRootPin`, samples `SystemTime`, calls `verify_network_policy`, and prints a static verification summary. Its output explicitly says `clock: local-untrusted`; it has no state-file or persistence arguments. See `crates/boreas-cli/src/pki_cmd.rs` (`cmd_verify_policy`).

The library-side pieces already exist: `VerifiedNetworkPolicy` is a verification token, and Linux `NetworkPolicyStore` opens an exclusively locked durable watermark and commits only fresh tokens whose exact raw TBS matches. Store state is bound to network id/root fingerprint and persists raw TBS plus its hash. This is sufficient for a narrowly scoped runtime CLI bridge; it does not authorize a prefix or configure a daemon. CI base reportedly passes; this proposal adds no claims of execution or test results.

## Recommended minimal command

Keep current static inspection as the default, with **no write**:

```text
boreas pki verify-policy \
  --tbs-file candidate.tbs \
  --ed25519-signature-file candidate.ed25519.sig \
  --mldsa65-signature-file candidate.mldsa65.sig \
  --net-id <32HEX> \
  --root-ed25519-der root-ed25519.der \
  --root-mldsa65-der root-mldsa65.der
```

Add an explicit opt-in durable-record mode, all-or-nothing:

```text
boreas pki verify-policy \
  --tbs-file candidate.tbs \
  --ed25519-signature-file candidate.ed25519.sig \
  --mldsa65-signature-file candidate.mldsa65.sig \
  --net-id <32HEX> \
  --root-ed25519-der root-ed25519.der \
  --root-mldsa65-der root-mldsa65.der \
  --record-state \
  --state-file /var/lib/boreas/network-policy.state \
  --expect-seq <N> \
  --expect-hash <64HEX>
```

For explicitly declared first use only, represent the expected state as the paired literal `--expect-first-use` instead of `--expect-seq/--expect-hash`:

```text
... --record-state --state-file /var/lib/boreas/network-policy.state --expect-first-use
```

The spelling is a proposal: its important semantic is explicit `None` passed to `open_with_expected`, never inferred merely because a state file is absent. For restart/normal advancement, require both expected sequence and SHA-256 hash; do not silently offer an unanchored mode. If flags are omitted, keep current static-only operation. Reject `--state-file` or expectation flags without `--record-state`; reject mixing `--expect-first-use` with either expected-value flag; reject a partial seq/hash pair. No `--root-trust`, arbitrary trust-file option, or implicit root discovery is introduced: root DER pin inputs and expected network remain mandatory exactly as today.

### One minimal API gap

Existing APIs suffice for validation and commit: `verify_network_policy(raw, ed_sig, pq_sig, pin, net_id, now)`, then `NetworkPolicyStore::open_with_expected(path, net_id, fingerprint, trusted_owner_uid, expected)` and `commit(&token, raw_tbs)`. The CLI currently lacks **only the explicit durable mode/expectation parsing and a trusted-owner deployment input**. `trusted_owner_uid` cannot be guessed from an arbitrary path or equated with the caller without an explicit security decision. Prefer one required `--state-owner-uid <UID>` (or a documented root-owned service configuration source) for a standalone CLI. The target file must be an absolute Linux path beneath a private, non-symlink directory owned by that UID; owner UID must match. The store enforces private directory/file properties and uses adjacent `.lock` and `.staging` artifacts. Do not add a `--root`/allowed-root override or path normalization that weakens the store's checked-path rules.

If product policy mandates a hardcoded service UID rather than a flag, document that trusted deployment contract and omit the flag; do not infer this from the path. On non-Linux, record mode must fail closed as unsupported and must not touch filesystem state. Static verification can retain existing platform behavior.

## Execution order and trust semantics

1. Parse all flags strictly and validate mode combinations before touching state. Require absolute `--state-file`; do not create parent directories.
2. Read input files using the existing bounded no-follow input path. Preserve the exact TBS byte vector; do not decode/re-encode it for verification, hashing, or commit.
3. Sample local wall clock once (`now_utc_us`) and verify both signatures, network id/root binding, and stated validity interval using that same instant.
4. Static-only mode prints success as static inspection; it does not open a store.
5. Record mode opens the state store with the explicitly supplied expected first-use or seq/hash value, trusted owner UID, network id, and verified root fingerprint. Commit the freshly verified token with the original raw TBS bytes.
6. Report durable record success only after commit returns `Committed` or `Duplicate`; report sequence and raw-object SHA-256. Do not report prefix enabled/active. Commit/fsync failure is an error, never a success-shaped summary.

The CLI's local clock is not a trusted time authority. Policy `issued_at`/`expires` are checked against the machine's current local clock; clock skew, rollback, or hostile local time can cause false acceptance/rejection. Durable sequence/hash state prevents ordinary replay/rollback only relative to the protected local state and the caller's external expected watermark. It does not solve whole-disk snapshot rollback; the external expectation must come from a separately protected/monotonic deployment record. `--expect-first-use` makes the trust decision explicit but cannot prove the machine has never previously had a state file.

A durable commit is not a freshness token for other processes and is not prefix activation. The current `VerifiedNetworkPolicy` is valid only as the fresh verification result for this invocation; persisted bytes do not reconstruct that token.

## Durable-store failures are hard errors

Map errors to stable, actionable stderr/exit failures without swallowing distinctions:

- `Busy`: another verifier owns the exclusive lock; retry later, do not bypass lock.
- `UnsafePath`: reject symlink/reparse-like path, unsafe parent/file ownership or mode, hard-link, unexpected staging artifact, non-absolute path, or wrong owner. Never chmod/chown automatically.
- `Corrupt` / expectation mismatch: state is missing or does not equal the externally expected first-use or `(seq, hash)` pair; operator must investigate/reconcile, not reset automatically.
- `WrongNetwork` / `WrongRootFingerprint`: state belongs to a different binding; fail closed.
- `SequenceRollback`, `IssuedAtRegression`, `PrefixConflict`: reject candidate and leave prior watermark unchanged.
- `Equivocation`: same sequence, different raw-object hash; store durably freezes before returning the error. Tell operator to investigate; never auto-clear or accept a higher sequence as recovery.
- `Frozen`: state is durably frozen; reject all later commits pending explicit out-of-band incident recovery.
- `Poisoned`: persistence failure in this store instance; stop using that instance and fail the invocation. Reopen/reconcile state on a later invocation; never claim commit succeeded.
- `RawTokenMismatch`, size/encoding/signature/time errors: programming/input/security failure; preserve fail-closed behavior.
- `Unsupported`: durable recording is Linux-only in the current implementation.

Do not introduce `--reset-state`, `--force`, a permissive path-root option, or fallback to static success after any record-mode error.

## Test contract: signed files, real CLI path

Add end-to-end CLI tests using actual temporary signed candidate files and root DER files, not a mocked verifier/store. Keep the test fixture private and isolated (Linux owner/mode constraints apply); use the project’s pinned OpenSSL ML-DSA backend and refuse to silently skip required cryptographic E2E coverage. Verify JSON/output and exit status, and inspect persisted state through the public store API where practical.

Positive cases:

1. Existing invocation without record flags succeeds for valid signatures and does **not** create a state file, lock, or staging file.
2. Explicit first-use record mode commits a valid signed sequence 1; emitted result marks `durable_recorded`, reports hash/seq, and says activation is false/absent.
3. Restart with expected seq/hash from prior successful result accepts and durably advances a valid higher sequence with same network, root, and prefix.
4. Repeating identical candidate at expected current watermark returns duplicate/idempotent success; no harmful state change.
5. Verify persisted object hash equals SHA-256 of the **exact original TBS file bytes**, including a fixture where decode/re-encode would not be a permitted substitution.

Negative cases (each asserts non-zero, no success JSON, and no unauthorized state advancement):

1. Record-related flags without `--record-state`; missing state path; relative path; missing/partial expected pair; first-use mixed with pair; duplicate/unknown flags.
2. Missing/malformed expected first use: pre-existing state with `--expect-first-use`; missing state with expected seq/hash; wrong sequence; wrong hash.
3. Invalid/tampered TBS, either bad signature, wrong network, wrong supplied root, not-yet-valid or expired candidate; ensure no commit.
4. Lower sequence, issued-at regression, changed prefix, same-sequence/different valid signed raw candidate: rollback/conflict rejected; equivocation persists frozen marker and subsequent higher candidate is rejected as frozen.
5. Raw-token mismatch at store boundary (unit/API coverage); malformed/truncated/corrupt state; unexpected `.staging`; symlink/hardlink, wrong mode/owner/private-dir violation; lock contention (`Busy`).
6. Inject/force persistence failure: CLI reports error and never success; poisoned instance cannot continue to mutate. Non-Linux record mode reports unsupported without filesystem writes.

For conflict/freeze tests, use separate real signed candidates with controlled sequence/time/prefix; avoid asserting merely on hand-crafted unverified tokens. Tests should prove that invalid or rejected candidates do not advance the watermark, while the equivocation case durably freezes exactly as designed.

## Explicit non-goals

This change does not activate a prefix, update routing, start/reconfigure a daemon, create a root-trust store, establish trusted wall clock, solve disk-image rollback, add cross-process freshness-token transport, or grant policy based on persisted state. Those need separate runtime/deployment designs and authority boundaries.
