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
