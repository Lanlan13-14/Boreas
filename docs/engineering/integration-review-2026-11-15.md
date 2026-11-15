# Integration review — 2026-11-15

## Scope and execution boundary

The lead merged GitHub main through `1f98372` into `0ff6968` before new work.
Existing dirty work is preserved in Git stash
`lead-preserve-existing-work-before-upstream-sync-20261115`; applying it required
manual integration of overlapping CLI and Linux-device changes. This snapshot
is a working review log, not Phase acceptance. Builds and tests are restricted
to GitHub Actions; the lead has not run local compilation or tests.

The official stable Rust manifest was downloaded on 2026-11-15. It reports
manifest date 2026-11-12, Rust 1.100.0, commit
`0ef1bc386059596dada8fb65b50425aab2ea637a`. No toolchain was compiled locally.

## Previously completed Actions inspected

At source `39a1fabb9913843a8a1ae02be385a4cd501ebe50`:

- [Rust CI](https://github.com/Lanlan13-14/Boreas/actions/runs/43657068997)
  failed. Linux Clippy found an unnecessary `c_char -> i8` cast; Windows
  Clippy found an unused PKI variable, and a supervisor child-exit test failed.
- [Platform CI](https://github.com/Lanlan13-14/Boreas/actions/runs/43657068973)
  had successful native static Linux jobs but failed Windows and both macOS
  jobs. macOS enrollment tests failed opening their transaction store. A
  successful Linux build/test job is not full static production TLS or VPN
  acceptance.
- [Real Linux TUN CI](https://github.com/Lanlan13-14/Boreas/actions/runs/43657068968)
  stopped at the same Clippy issue before real-device test acceptance.
- [Sandbox audit/diagnostics](https://github.com/Lanlan13-14/Boreas/actions/runs/43657069009)
  succeeded. Its evidence is limited to the workflow's probes and diagnostics,
  not production daemon worker isolation.

The Linux name conversion has been adjusted to use the byte representation of
`c_char`, and isolated TUN tests now remount sysfs inside a private mount/network
namespace. These changes remain unverified until Actions runs them.

## Delegation and lead review

Implementation is delegated to DeepSeek V4.1 Flash in disjoint ownership scopes.
The lead reviews actual code and integration rather than accepting completion
messages. Findings sent back for correction include:

1. TLS `PemIdentity` derived Debug exposed private-key bytes. Require redacted
   diagnostics, bounded key/certificate reads, exact peer authorization and
   chain-depth limits; do not call a trusted certificate application authority.
2. Enrollment's private verified-request/result constructors made the transaction
   engine unusable from production CSR/signing paths. Require real DER CSR
   possession verification and a durable client retry path, not unchecked booleans.
3. Supervisor exit-code-only confirmation, missing process locking, repeatable
   failed trials and absent health/signal semantics leave upgrade recovery open.
4. Directory envelopes and writer proofs are caller assertions, not cryptographic
   evidence. A network adapter must obtain genuine signature/scope verification
   before passing input to convergence. Raw equivocation evidence persistence is
   still required; hash-only in-memory convergence does not satisfy that gate.
5. CLI configuration is connected to `config-check`, not to a daemon. Its candidate
   schema diverges from the master-plan template and needs unification before
   acceptance. The direct `parse_toml` API lacks a size check, and checking regular
   file metadata after a blocking open can hang on a FIFO. Symlink/ownership and
   Windows ACL behavior remain to be addressed. None of these are waived by a
   successful parser unit test.
6. Protocol control-message work must eliminate conflicting duplicate modules and
   use one bounded schema/state model. Tests cannot validate only their own encoder.
7. Native packet adapters need real device traffic and cleanup evidence on Windows
   and macOS. A successful platform build or doctor output is insufficient.

## Release posture

The machine-readable gate ledger starts open and production approval is false.
The metadata verifier requires exact-commit evidence for every mandatory gate
and native real packet I/O on all five targets. Its unit tests will run in
Actions. It is not an audit, a report authenticity verifier, or release signing
permission. Independent security review, offline ReleaseRoot dual signatures,
real CDN/topology workloads, sustained resource/performance measurements and
operational drills cannot be replaced by self-authored metadata.
