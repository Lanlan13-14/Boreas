# Development-only Boreas performance A/B

This diagnostic cannot close `G-PERF`, qualify a build for release, or replace
any `rust-tls`, dependency, promotion or production `performance.yml` gate.
No changes to those workflows or to the strict netns harness are necessary.

## Dispatch in Actions (never run locally)

A push changing the diagnostic workflow or script on the same-repository
`fix/v111-release-blockers` branch runs the fixed baseline and candidate below.
Manual dispatch is available once registered on the default branch; the
selected ref must contain both exact commits. A maintainer reviews both input
revisions (including build scripts/dependencies) before manual dispatch.
Ancestry and matching lockfiles are safeguards, not evidence
of human approval. Do not extend this workflow to PR/fork triggers, external
artifacts, self-hosted runners, cloud credentials, or repository secrets. The
existing netns smoke needs root and runs both binaries with that privilege on
a new disposable GitHub-hosted runner. Checkout does not persist credentials;
permissions are only `contents: read`.

Example from an authenticated Actions client (dispatches remote CI, **not** a
local benchmark):

```sh
gh workflow run performance-ab.yml --repo Lanlan13-14/Boreas \
  --ref fix/v111-release-blockers \
  -f baseline_sha=4fce922a192eb811b6bb901927a081c100431a51 \
  -f candidate_sha=b921b68bc58749c01a2755ed3a95a549b5e78246
```

`main` is also an allowed dispatch ref. The defaults differ only by the
outbound memcpy-removal commit. Both sides already include the daemon/probe
lifetime fix; this is not a test of that fix or of the complete set of prior
performance changes. Future reviewed commit pairs must be distinct, ordered
by ancestry, have identical `Cargo.lock`, and support the same dispatch SHA's
harness and `openssl-inner-tls` build. No mutable branch names or user-supplied
binary paths are used as comparison inputs.

## Controls and results

- One `ubuntu-24.04` x64 VM, exact Rust 1.100.0, one native toolchain, one
  checked archive and verified static musl OpenSSL 4.1.1-dev installation
  (reviewed commit `941390af2ac35f41d2f95bb0bac823dbf0700845`). Exact-source
  `--locked --release` builds have separate build directories and do not format
  or otherwise alter the source. Static-linkage reports and hashes tie the two
  full-SHA-named executables to their build inputs. No cross-run artifacts
  or caches are consumed and the executables are never uploaded.
- Two sequential adjacent pairs (`A,B`, then `B,A`); each invocation gives both
  namespaces fresh state and uses the same strict harness and signing tools.
  Each run gets a freshly generated test root shared by identity and policy
  inside that run. The real TUN/veth path uses `e2e-required` and `pq768`.
  Existing PKI, verification, polling, integrity and daemon checks are not
  bypassed. 64 MiB of identical deterministic payload **per direction** is run
  simultaneously, with the existing 230 s Edge fixture lifetime and the same
  3 Mbps floor / 415 ms maximum ping / zero observed overlay ping-loss bound.
- The strict comparable profile applies **200 ms one-way to each egress**, so
  the configured base RTT is **400 ms**, not 200 ms. Each netem egress is
  configured for 0.1% loss and 100 Mbit/s. Look at the *observed* overlay ping
  average/max per sample; 400 ms is the configured round-trip component, not a
  promise of exactly 400 ms measured (queueing and processing add delay).
  Random loss realizations and fresh ephemeral keys differ across runs.
- Download `development-perf-ab-evidence-<run>-<attempt>` from the run even if
  it is red. `revisions.txt`, `runner.txt`, OpenSSL reports, build/linkage logs,
  `SHA256SUMS`, `profile.txt`, and four smoke logs record the
  conditions. `samples.csv` separates the daemon launch-to-connected observation
  (coarse polling), each sender's overlay TCP connect, send, digest return and
  end-to-end completion; completion seconds are the sum of rounded phases and
  completion Mbps is the strict smoke's connect-through-digest measure. Neither
  connect field is isolated TLS CPU time. `paired-deltas.csv` reports
  candidate-minus-baseline by pair and direction (negative is faster for time;
  positive is faster for Mbps); see the two smoke exit columns before using
  any delta. CSV blanks mean missing, not zero.
- A nonzero smoke exit remains red; both subsequent samples and diagnostics
  are attempted without substituting retries. When a transfer completed but
  a smoke bound failed, retained timings describe that run only, not a passing
  sample. On infrastructure or whole-job failure, logs may be partial and
  nothing can be inferred about a missing pair. Two pairs are a quick screen,
  not statistical proof, steady-state throughput, a cross-run hardware
  comparison, a WAN SLA, or a substitute for strict production evidence.
