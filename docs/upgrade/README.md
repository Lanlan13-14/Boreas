# Upgrade transaction core, external supervisor and release-metadata boundary

`boreas-supervisor` is an independent Rust 2024, version `0.1.0`, GPL-3.0-only
crate: a crash-recoverable upgrade journal plus the external supervisor
executable (master plan §1.1/§10.3), and a strict release-metadata layer
(§10.2). It adds no daemon, installer command, downloader, or service unit, and
it does **not** claim `G-UPGRADE` or `G-SUPPLY`.

## Status at a glance

| Area | State |
| --- | --- |
| Journal / active pointer / recovery (Linux, macOS) | implemented, tested |
| Windows transaction backend | **not integrated**, store fails closed |
| Exclusive store lock | implemented (`File::try_lock` OS lock) |
| Trial liveness soak (not readiness) | implemented |
| Application health/readiness gate (AF_UNIX + peer credentials) | **not implemented** |
| Durable trial budget across restarts | implemented (`trial.state`) |
| Signal forwarding / graceful stop window | **not implemented**, contract documented |
| Strict manifest parsing + policy | implemented, dependency-free |
| Ed25519 + ML-DSA-65 verification | implemented behind `openssl-backend` (OpenSSL 3.5+); default build fails closed |
| Artifact size + SHA-256 check | implemented on `VerifiedManifest` behind the same feature |
| Durable anti-rollback / TUF roles / SBOM | **not implemented** |

Dependencies: `libc = "=0.2.191"` for macOS only (already locked by `boreas-tun`),
and `openssl = "=0.10.82"` as an **optional** dependency used only by the
`openssl-backend` feature (the same pin `boreas-pki`/`boreas-crypto` use). The
default workspace build compiles neither backend-specific path; `Cargo.lock`
must be regenerated once by the `Refresh Cargo.lock` workflow before `--locked`
jobs can resolve the new edges. `serde`/`serde_json` were deliberately not
added: the manifest reader is a small, strict, hand-written JSON subset.

## Transaction model

`UpgradeStore::open(root)` opens a trusted, already-existing, non-symlink store
root and creates `versions/`, `staging/`. `prepare(&Candidate, artifact_dir)`
accepts a simple version identifier and an *already authenticated* artifact
directory, copies regular files/directories to same-filesystem staging, rejects
symlinks/special files/hard links, flushes staged file data, then renames into
`versions/<version>` and durably writes a `Prepared` journal recording the
retained old version. `activate()` atomically replaces `active.version` and
records `Activated`. `confirm()` records `Confirmed` only after the supervisor's
liveness soak passes (see below — that is not a readiness check). `recover()`
rolls `Prepared`/`Activated` back to the retained
old version (or clears the pointer on first install). Old version directories
are deliberately never deleted.

Crash safety covers the pointer-rename / journal-update ordering: a crash after
the new pointer is durable but before the journal reaches `Activated` is
repaired from the durable `Prepared` record. `recover()` is a library state
transition, never a launcher; re-running a broken executable is not recovery.

### Exclusive store lock

`UpgradeStore::lock_exclusive()` takes an OS advisory lock (`File::try_lock`) on
`<root>/store.lock` and returns a `StoreLock` guard. Because the kernel drops
the lock with the process, there is no stale-pidfile failure mode; the file
content (`pid <n>`) is diagnostics only. `supervise`, `recover` and
`reset-trial` hold one for their whole run; a second supervisor fails fast
instead of racing the journal or the pointer. `status` is read-only and
deliberately does not lock, so it stays available for diagnosis during a
supervised launch.

### Durable trial ledger

`<root>/trial.state` records `BOREAS-TRIAL-1 / <version> / <attempts> /
in-flight|failed`. `reserve_trial(version, max)` increments and writes
*in-flight* **before** the candidate is launched, so a supervisor killed
mid-trial still consumes the attempt when the next one starts. `mark_trial_failed`
flips the record to `failed` (keeping the count); `clear_trial` removes it after
a confirmed upgrade, or when the operator runs `reset-trial`. A corrupt ledger
is `UpgradeError::CorruptTrial`, never "no attempts yet". The ledger can only
ever *restrict* launches, so tampering causes denial of upgrades, never
authorization.

Known bound, stated exactly: a kill in the narrow window between `activate()`
and the ledger reservation can allow **one** extra launch beyond the configured
budget. The loop is still bounded (≤ `max + 1` per activation cycle), and it is
never unbounded.

## External supervisor executable

The binary exposes four commands and has no `prepare`/`activate`, so no
unverified artifact can be staged through it:

* `supervise --store <DIR> [--trial-soak-ms <MS>] [--max-trial-attempts <N>] -- <argv...>`
  — take the store lock, run `begin_activation()` (which starts in `recover()`),
  then spawn `<argv...>` with inherited stdio. A leading `{version}` in `argv[0]`
  is replaced with the absolute active-version directory after
  recovery/activation; it fails closed when no version is active, when the
  pointer is dangling, or when `{version}` appears outside `argv[0]`.
* `recover --store <DIR> [--json]` — `open + recover()` under the store lock;
  launches nothing.
* `status --store <DIR> [--json]` — real journal, recorded pointer (including a
  dangling one via `pointer_ok: false`), retained version count, and the durable
  trial record.
* `reset-trial --store <DIR>` — operator acknowledgement: clears a spent trial
  budget after inspecting the candidate. Nothing else clears it.

### Liveness soak (this is not readiness, and not "exit 0 ⇒ confirmed")

A trial launch is confirmed only after the candidate has **stayed alive** for
`--trial-soak-ms` (default 30 000 ms). `confirm()` is written at the deadline
while the child is still running, so:

* exiting before the deadline — with **any** status, including `0` — is a failed
  attempt: the attempt stays consumed, the pointer is rolled back immediately,
  and the supervisor exits non-zero;
* after confirmation, a later exit (clean or crash) is an ordinary runtime stop:
  its status is propagated and the committed upgrade is not rolled back.

This closes the "exit 0 because it was stopped right away" hole. It is **not**
application health: a process that is alive but deadlocked, wedged before
binding its TUN device, missing workers, or serving a stale state schema passes
the soak. The real gate is the next round's authorized `AF_UNIX` health endpoint
with peer credentials, where the supervisor sends a random challenge bound to
the candidate SHA, state schema, worker count and TUN status, and only a
correct, fresh response confirms. There is no `sd_notify` readiness, liveness
probe, control socket or launch timeout yet.

The durable budget bounds the restart loop across process lifetimes:
`--max-trial-attempts` (default 3) attempts, then `supervise` refuses to even
activate the candidate and points the operator at `reset-trial`.

### Signals: the contract

No signal handler is installed, deliberately:

* the child is spawned into this process's group/console, so a group-directed
  `SIGTERM`/`SIGINT` (systemd's default cgroup-wide stop, or Ctrl+C in the same
  terminal) reaches the child directly;
* if the supervisor dies mid-trial, the durable `Activated` journal plus the
  `in-flight` reservation make the next `supervise` roll back and count the
  attempt — no `trap` is relied on (§10.3);
* a service unit must therefore use the default cgroup-wide kill
  (`KillMode=control-group`) and a bounded `Restart=`.

Not provided, and not claimed: forwarding a signal delivered only to the
supervisor, a graceful stop window, and per-signal exit mapping beyond `128+n`.
Those need reviewed `sigaction`/console-handler code per platform.

## Release metadata layer (`manifest.rs`)

Strict structure and policy only, plus one fail-closed verification seam:

* `parse_unsigned(bytes)` bounds the input (1 MiB) and parses a strict JSON
  subset: duplicate keys at every depth, unknown fields, non-integer numbers,
  trailing bytes, invalid UTF-8, excessive nesting, oversized collections,
  path traversal in asset names and non-conforming URLs are all rejected. The
  result is `UnsignedManifest` — structure **only**.
* Every field is private with read-only accessors, and there is no conversion
  to a trusted type, so a caller cannot patch `assets` after a verifier hashed
  `raw_bytes()` (the TOCTOU shape this design removes).
* `ReleasePolicy` applies freshness, maximum lifetime (≤ 90 days), minimum
  sequence and architecture selection; `select_asset` requires **exactly one**
  match and refuses ambiguity. This is preflight, never authorization.
* `verify_release(bytes, envelope, roots)` is the only route to
  `VerifiedManifest`. Order is fixed: size bound → resolve the key id against
  configured `ReleaseRoot`s (unknown id is refused before any crypto) → verify
  Ed25519 **AND** ML-DSA-65 over the exact raw bytes → parse *those same bytes*
  afterwards. `VerifiedManifest` has a private field and no public constructor.
* With `openssl-backend`, verification is real: `release_crypto` parses both
  anchors as SPKI DER, asserts `KeyType::ED25519` and `KeyType::ML_DSA_65`, and
  checks both signatures with `Verifier::new_without_digest(..).verify_oneshot`,
  requiring both to succeed. `VerifiedManifest::verify_asset_bytes` then checks
  the received artifact's exact size and SHA-256 against the authenticated
  manifest. `ReleaseRoot` keeps DER keys (not raw `[u8; 32]` blobs) precisely so
  the algorithm check is possible.
* `SequenceLedger` accepts only `VerifiedManifest` (equivocation = same sequence,
  different bytes; rollback = lower sequence). It is **in-memory only**.

Without the feature the crate compiles no crypto: `verify_release` returns
`ManifestError::VerificationUnavailable` and `verify_asset_bytes` still rejects a
wrong size but cannot hash, so it fails closed too. There is no `bool`
"verified" flag, no caller-implementable verifier trait, and no path from
`UnsignedManifest` to `VerifiedManifest`, so `prepare` stays unreachable from
any user-facing path. URL validation is a strict documented subset
(`https://` + dotted DNS host + optional decimal port 1–65535 + unreserved-only
path) rather than a hand-split of a general URL: no userinfo, query, fragment,
percent-encoding, backslash or dot segments can be expressed. `https://host?x@evil`
fails at the authority check instead of being mis-split.

Still open (next round): the actual Ed25519 + ML-DSA-65 provider and its test
vectors, TUF-style root/targets/snapshot/timestamp roles with threshold and
rotation, revocation, SBOM/provenance, the downloader (redirect policy, hash and
size check on the received bytes), and durable anti-rollback persistence. None
of these may be claimed from this module.

## Filesystem security and platform boundary

Version identifiers are restricted to ASCII alphanumeric plus `. _ + -`, cannot
start with `.`, and cannot contain path separators or traversal. Store root and
artifact paths reject symlink components; the artifact tree rejects symlinks,
hard-linked regular files, and special files. Copy is bounded to 2 GiB, 100,000
entries and 64 nested directory levels. Unix staged directories/files and
journal temporary files are created `0700`/`0600`; executable files keep an
executable bit. The root and its parents must still be trusted and not
attacker-writable, and the artifact source must stay immutable during the copy
because portable path-based traversal cannot close every source-side TOCTOU
race.

**Linux** flushes file data with `fsync` and orders namespace changes with
directory `fsync`.

**macOS** is now integrated (`src/macos.rs`, `libc` 0.2.191): file data goes
through `fcntl(F_FULLFSYNC)` (a failure is returned, never silently downgraded
to `fsync`), and namespace changes are followed by a directory sync. The same
transaction test suite that runs on Linux now runs on both macOS CI targets,
which is what turns the adapter from an untested draft into a tested backend.
Apple documents that some drives ignore cache-flush requests, so this is still
not an unconditional power-loss guarantee; the filesystem/hardware matrix is
open.

**Windows** remains **not integrated**: `src/windows.rs` is not declared as a
module and no `windows-sys` dependency exists in `Cargo.lock` (adding it means
new lock entries and a reviewed dependency decision). Two substantive blockers
remain beyond that: the store has no explicit-DACL creation/verification (an
inherited ACL is not accepted as a private-store policy), and there is no
documented parent-directory durability equivalent, so `sync_dir` must keep
failing closed and `UpgradeStore::open` cannot succeed. Windows CI therefore
covers only the pure parsing/reporting paths plus the explicit
`directory_fsync_fails_closed_on_windows` assertion.

The draft Windows notes below remain the design input for that work.

### Windows adapter findings (not enabled)

The target-specific dependency proposal is
`windows-sys = { version = "=0.61.2", default-features = false, features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }`;
exact API names and signatures were checked against [the versioned
bindings](https://docs.rs/windows-sys/0.61.2/windows_sys/Win32/Storage/FileSystem/).
Do not hand-write Win32 ABI items. `FlushFileBuffers` flushes buffers for a file
handle opened with write access, but is not by itself proof the physical device
honored the request
([Microsoft `FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)).
`MoveFileExW(MOVEFILE_WRITE_THROUGH)` is a namespace move option whose docs
specifically describe a copy/delete flush guarantee; do not infer it guarantees
metadata persistence for same-volume rename
([Microsoft `MoveFileExW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)).
`ReplaceFileW` is preferable when replacing an existing pointer, but Microsoft
documents `REPLACEFILE_WRITE_THROUGH` as unsupported, so pass no such flag and
make no write-through claim
([Microsoft `ReplaceFileW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)).
New destination and replacement-existing paths have separate error semantics.

For safety, Windows integration must use restrictive explicit security
attributes or verify inherited ACLs on the private store; a null security
attributes pointer inherits the parent directory's default security descriptor,
not an intrinsic private ACL. Inspect every path component and final handle for
reparse-point attributes without following them; prevent races with
handle-relative operations and the exclusive store lock. Use
`BY_HANDLE_FILE_INFORMATION.nNumberOfLinks` to reject hard-linked files and
volume/file IDs for same-volume validation. The draft adapter has path-based
inspection only and explicitly does not close hostile-writer TOCTOU races.

### macOS notes (now integrated)

The macOS implementation uses
`libc = { version = "=0.2.191" }`, whose generated Apple binding exports
`fcntl` and `F_FULLFSYNC` (see the [libc Apple
bindings](https://github.com/rust-lang/libc/blob/0.2.191/src/unix/bsd/apple/mod.rs));
no handwritten constants or ABI declarations are used. Apple's [`fsync(2)`
manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
states that fsync moves data/attributes to the device but the device may reorder
or retain cache contents, and points to F_FULLFSYNC for tighter guarantees.
Apple's [`fcntl(2)`
manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
describes F_FULLFSYNC as asking the drive to flush buffered data to permanent
storage, while noting device support limitations (some FireWire drives ignore
flush requests). Which macOS filesystems reliably support syncing directory
descriptors, and how unsupported errors must be handled, still has to be
validated on real hardware; the CI suite proves the code path runs, not that a
power cut is safe.

## Required CI gates before release

`cargo test --workspace --locked`, `cargo clippy --workspace --all-targets
--locked -- -D warnings` and the platform matrix
(`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
`x86_64-pc-windows-msvc`, both macOS targets) run in GitHub Actions; local runs
are development feedback only and are not release evidence.

Current supervisor tests cover: journal/pointer primitives; trial non-zero exit
and death-by-signal roll back; **early zero-exit does not confirm**; a candidate
that survives the soak is confirmed while running and a later crash is not
rolled back; the durable budget bounds repeated failures and `reset-trial`
clears it; the store lock rejects a second supervisor and a concurrent
`recover`; `status` reports the trial ledger; missing argv/program and a
dangling pointer fail closed. Manifest tests cover strict JSON (duplicate keys,
unknown fields, non-integers, trailing data, UTF-8, nesting), the URL subset,
timestamps, policy, asset selection, and the in-memory ledger.

Two CI obligations for the crypto path, both outside this file's scope:
`cargo test -p boreas-supervisor --features openssl-backend` must run on a runner
with **OpenSSL 3.5+** (the `rust-tls` workflow already pins 3.6.1), and
`Cargo.lock` must be regenerated once by the `Refresh Cargo.lock` workflow. Until
then the default (`--locked`) jobs exercise the fail-closed path only; that is a
build-coverage gap, not a claim that the backend has been validated here.

Still to expand before any gate claim: process-level crash injection at every
durable write boundary (including `SIGKILL` of the supervisor mid-trial and in
the activation→reservation window), disk-full/permission failures, symlink and
traversal races, supported-filesystem matrix, power-cut testing, real
service-manager restart integration, the signal-forwarding implementation, and
old-version executable recovery in the shipped layout. Then satisfy the master
plan's `G-UPGRADE` and `G-SUPPLY` gates plus the common production exit
conditions. This is an integrated core plus a tested supervision boundary, not
proof those gates pass.
