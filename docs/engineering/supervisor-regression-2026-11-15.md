# Supervisor regression CI snapshot — 2026-11-15

Scope: Actions evidence for merge commit `116968e` (`116968ed23898963ee3f6235ccbff4010e0a7287`),
plus the immediately preceding ancestor run set at `d5a215c` used only as a baseline.
Read-only: no source, doc, or ledger change is recorded here beyond this new file.

## 116968e — runs (Actions, repo Lanlan13-14/Boreas)

| workflow | run id | status at collection | conclusion |
| --- | --- | --- | --- |
| Rust CI | 43683078414 | in_progress | ubuntu job failed; windows job still running |
| Platform functional verification and development packaging | 43683078388 | in_progress | 5 of 6 target jobs running |
| Rust OpenSSL hybrid TLS backend | 43683078354 | in_progress | — |
| Linux system TUN checks | 43683078413 | completed | success |

### Rust CI 43683078414 jobs

| job id | name | state |
| --- | --- | --- |
| 132717695778 | Apply stable rustfmt | success |
| 132717695916 | Locked dependency preflight | success |
| 132717695925 | Rust checks (windows-latest) | in_progress |
| 132717695980 | Rust checks (ubuntu-latest) | **failure** |

`Rust checks (ubuntu-latest)` step 6 `Clippy` failed; steps 1–5 and 7–11 passed
(`Check workspace`, `Test`, vectors, gate tooling, release tooling all success).

### Supervisor tests: actually measured pass (Linux)

From the `Test` step log of job 132717695980 on 116968e:

- `boreas_supervisor` lib tests: `88 passed; 0 failed`
- `boreas_supervisor` bin (src/main.rs) tests: `40 passed; 0 failed`
- `tests/readiness.rs`: `4 passed; 0 failed`

So the new schema fixtures / negative regression from `ee4bda4` compile and pass at runtime
on ubuntu-latest. They do **not** yet make CI green: the same job is red on lint, and the
Windows job, the platform matrix and the TLS job had not finished when this was collected.

### First remaining error on 116968e

```
error: unused variable: `older`
  --> crates/boreas-supervisor/src/manifest.rs:1806:13
note: `-D unused-variables` implied by `-D warnings`
error: could not compile `boreas-supervisor` (lib test) due to 1 previous error
```

Cause: in `sequence_ledger_accepts_only_verified_manifests` the binding at line 1806
(`let older = verified(...)` with sequence 3 + size 43) is dead; the sibling binding at
line 1823 is the one consumed by the rollback assertion. `Test` only warns, `Clippy`
(`cargo clippy --workspace --all-targets --locked -- -D warnings`) promotes it to an error.

## Baseline d5a215c — same lint, so not a new regression

`d5a215c` run 43682623661 job 132716316343 (`Rust checks (windows-latest)`) already failed with
the identical `unused variable: older` at `manifest.rs:1806`. The lint therefore predates the
`ee4bda4` fixture work and is not introduced by it.

## Static note for the main agent (not touched here)

`d5a215c` run 43682623647 job 132716316415 (`OpenSSL 3.6.1 + rust-openssl 0.10.82 pq768 mTLS`)
failed compiling a separate crate:

```
error[E0308]: mismatched types
  --> crates/boreas-tunnel/tests/wss_e2e_openssl.rs:309:41
309 |                     ObjectRole::Edge => NodeRole::Edge,
    |                                         ^^^^^^^^^^^^^^^
    = note: expected `boreas_pki::NodeRole`, found `boreas_crypto::NodeRole`
error: could not compile `boreas-tunnel` (test "wss_e2e_openssl") due to 2 previous errors
```

Two errors are reported for that test target; only the E0308 pair is captured above.
The corresponding `116968e` TLS run (43683078354) was still running at collection time, so
whether this persists at HEAD is unverified. This is recorded for triage only — no fix applied.

## Not claimed

- No statement about the final conclusion of runs 43683078414, 43683078388, 43683078354.
- No statement about macOS/Windows/aarch64 targets or the TLS matrix.
- Local `cargo`, Python, tests and formatting were intentionally not run.

## Addendum — 116968e TLS run finished, df80a5b re-check

Collected after the first pass; the sections above are kept unchanged.

### 116968e run 43683078354 (Rust OpenSSL hybrid TLS backend) — failure

Single job 132717696228 `OpenSSL 3.6.1 + rust-openssl 0.10.82 pq768 mTLS`.
Steps 1–13 passed (pinned OpenSSL build, feature-flag assertions, policy-only tests,
backend + all-target compile, real pq768 mTLS, PKI/CSR/signing, supervisor dual-signature
tests). Step 14 `Transport inner-TLS seam tests with backend feature` **failed**
(`exit code 101`), steps 15–16 and 32–33 passed afterwards.

Cause is the `boreas-tunnel` test target noted above, now confirmed at 116968e with two sites:

```
error[E0308]: mismatched types
   --> crates/boreas-tunnel/tests/wss_e2e_openssl.rs:300:48
300 |     let scope = IssuerScope::for_identity(vec![NodeRole::Edge, NodeRole::Core], vec![1])
    |                                                ^^^^^^^^^^^^^^ expected `boreas_pki::NodeRole`, found `boreas_crypto::NodeRole`

error[E0308]: mismatched types
   --> crates/boreas-tunnel/tests/wss_e2e_openssl.rs:309:41
309 |                     ObjectRole::Edge => NodeRole::Edge,
    |                                         ^^^^^^^^^^^^^^^ expected `boreas_pki::NodeRole`, found `boreas_crypto::NodeRole`

error: could not compile `boreas-tunnel` (test "wss_e2e_openssl") due to 2 previous errors
```

So the earlier "unverified at HEAD" caveat is resolved: the `NodeRole` type mismatch
persists unchanged from d5a215c to 116968e. It is independent of the supervisor work.

### df80a5b (docs-only) — supervisor lint still failing, actually observed

Runs for `df80a5ba1a57f277d67fb0dd59036487711c0c98`: Rust CI 43683191993 **failure**,
Platform 43683191934 success, TUN 43683191930 success. No TLS run existed for this SHA.

Rust CI jobs: 132718045108 ubuntu-latest failure, 132718045258 windows-latest failure,
132718045246 rustfmt success, 132718045257 preflight success. Both failing jobs report the
same lint, so it is not platform-specific:

```
error: unused variable: `older`
  --> crates/boreas-supervisor/src/manifest.rs:1806:13
error: could not compile `boreas-supervisor` (lib test) due to 1 previous error
```

Confirmed: after the docs-only commit the surviving supervisor blocker is still the dead
`older` binding in `sequence_ledger_accepts_only_verified_manifests`, not the fixtures.
Platform and TUN green at df80a5b is consistent with the supervisor tests passing at runtime.

## Addendum 2 — 90a7ad5: both old blockers resolved, WSS fixture now the first error

Evidence read from completed `90a7ad5` runs only; earlier sections unchanged.

| workflow | run | state |
| --- | --- | --- |
| Rust CI | 43683442873 | completed success (rustfmt, preflight, windows-latest, ubuntu-latest all success) |
| Platform functional… | 43683442836 | completed cancelled — 14 target jobs success, final bundle job cancelled |
| Linux system TUN checks | 43683442993 | completed success |
| Rust OpenSSL hybrid TLS | 43683443001 | completed cancelled (job red first) |

Rust CI turning fully green confirms the `unused variable: older` lint is fixed at 90a7ad5;
platform/TUN green is consistent with the PKI `NodeRole` work. Platform's only non-success
entries are cancellation artifacts of the newer push, not test failures.

### First remaining error: `wss_e2e_openssl` fixture generation

TLS job 132718823330: steps 1–8 success, 10–13 success, **14 failure**, 15–16 success,
job cancelled afterwards (step 9 recorded cancelled for the same reason). Step 11
`Compile backend and all test targets` now succeeds, so the `NodeRole` mismatch is gone and
the target compiles; step 12 real pq768 mTLS passes. Step 14 then actually runs the WSS suite:

```
running 7 tests
thread 'e2e_generation_mismatch_never_yields_business_stream' panicked at
  crates/boreas-tunnel/tests/wss_e2e_openssl.rs:99:17:
OpenSSL fixture generation failed (Some(1)); output suppressed
... (same panic for all 7 tests) ...
test result: FAILED. 0 passed; 7 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
error: test failed, to rerun pass `-p boreas-tunnel --test wss_e2e_openssl`
```

No assertion is reached: every test dies in `setup()` on the first `openssl` invocation,
which exits 1. The harness discards stderr (`Stdio::null()`), so CI cannot say why.

Two static differences from the harness that does pass in the same job (step 12,
`crates/boreas-crypto/tests/openssl_mtls_handshake.rs`) — hypotheses only, not run locally:

1. `wss_e2e_openssl.rs:46` `MINIMAL_CNF` puts `activate = 1` inside `[provider_sect]` and
   never defines `[default_sect]`; the passing harness at `openssl_mtls_handshake.rs:111`
   defines a separate `[default_sect]` with `activate = 1`.
2. The first fixture call is `genpkey -algorithm RSA:2048`, whereas the passing harness uses
   `-algorithm ML-DSA-65` (bare algorithm name, no `:bits` suffix).

Both are test-side fixture defects in `boreas-tunnel`'s test harness, unrelated to supervisor.

### 065f24b (non-Linux trust-store cfg) — in flight at collection

Rust CI 43683612086 completed with rustfmt, ubuntu-latest, windows-latest and preflight all
success; TUN 43683611941 success; TLS 43683612062 and Platform 43683611988 still running
(no conclusions claimed).
