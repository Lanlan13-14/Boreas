# Upgrade transaction core (initial implementation)

`boreas-supervisor` is an independent Rust 2024, version `0.1.0`, GPL-3.0-only
library with no third-party dependencies, plus a minimal external-supervisor
executable (`[[bin]] boreas-supervisor`, master plan §1.1/§10.3). It is still
intended for later integration into the shipped filesystem layout; it does
**not** add a daemon, installer command, updater, download, or service unit,
and it does not claim the master plan's `G-UPGRADE` gate.

## Current API and transaction model

`UpgradeStore::open(root)` opens a trusted, already-existing, non-symlink
store root and creates `versions/` and `staging/`. `prepare(&Candidate,
artifact_dir)` accepts a simple version identifier and an already-authenticated
artifact directory, copies regular files/directories to same-filesystem staging,
rejects symlinks/special files, syncs staged file contents, then renames into
`versions/<version>` and durably writes a `Prepared` journal recording the
retained old version. `activate()` atomically replaces `active.version` with the
new version and records `Activated`. `confirm()` records `Confirmed` only after
the caller's external health policy passes. `recover()` is called by a separate
supervisor **before it launches any version**; Prepared or Activated journal
states roll the active pointer back to the retained old version (or no active
version on first install). Confirmed state preserves the selected new version.
Old version directories are deliberately not deleted.

Crash safety covers the pointer-rename / journal-update ordering: even if a crash
occurs after the new pointer is durable but before the journal reaches
`Activated`, the durable `Prepared` record directs recovery to restore the old
pointer. `recover()` itself is a library state transition, not a process
launcher: the external supervisor must invoke it before starting the program.
Restarting a broken active executable repeatedly is not recovery.

`UpgradeStore::begin_activation()` is the one reviewed composition of
"recover before launch" with the single permitted first launch of a
`Prepared` candidate: no journal or a consistent `Confirmed` journal reports
the steady version; an `Activated` journal (trial already consumed, never
confirmed) rolls back without retrying; a `Prepared` journal is recovered
first (repairing the crash-mid-`activate` window) and only then activated
once as a trial launch; a `Confirmed` journal whose pointer disagrees with
it is refused for operator inspection rather than retried. Existing
`prepare`/`activate`/`confirm`/`recover` semantics are unchanged.

## External supervisor executable (minimal real process slice)

The `boreas-supervisor` binary exposes exactly four commands — it has no
`prepare`/`activate`, so nobody can stage an unverified artifact through it:

* `supervise --store <DIR> -- <argv...>` — open the store, run
  `begin_activation()` (which starts in `recover()`), then spawn `<argv...>`
  as a real child process with inherited stdio and wait for it. A leading
  `{version}` in `argv[0]` is replaced with the absolute active-version
  directory *after* recovery/activation, so the program started is the one
  the pointer names (the candidate on a trial, the old program after a
  rollback); it fails closed when no version is active, when the pointer is
  dangling, or when `{version}` appears outside `argv[0]`. A trial launch
  calls `confirm()` only on a zero exit and `recover()` on any other
  outcome (non-zero exit, death by signal, spawn/wait failure), returning
  non-zero; a boot that starts from `Activated` runs the already
  rolled-back program and propagates its status (child code, `128+signal`
  when killed); an inconsistent journal refuses the launch. Old version
  directories are never deleted.
* `recover --store <DIR> [--json]` — `UpgradeStore::open + recover()` only;
  launches nothing.
* `status --store <DIR> [--json]` — prints the real journal, the recorded
  active pointer (including a dangling one, via `pointer_ok: false`), and
  the count of retained version directories. Nothing is synthesised.
* `--help`.

Documented gaps, deliberately not papered over: no signal forwarding to the
child yet; the only health signal is the child's exit status (a zero exit
at any time confirms — the §10.3/§10.5 health channel does not exist yet);
no store locking beyond the library's single-writer requirement; and no
cross-lifetime "candidate already failed" ledger — after a failed trial the
journal returns to `Prepared`, so a fresh `supervise` trials it again.
Bounding that loop is service policy (trial budget/cooldown/operator
acknowledgement) that belongs to the §10.5 systemd/OS integration; until
then the service manager must bound restarts. `G-UPGRADE` remains unproven
(power-cut/fault-injection matrix, real service wiring, full trial policy).

## Authenticity and integration boundary

There is **no release-signature or manifest verifier implemented** here. A
future independent verification layer must validate bounded raw manifest bytes,
strict parsing and release-root policy, signatures, artifact hash/size, target
architecture, freshness/sequence and downgrade constraints before `prepare` is
called. This crate accepts no `bool` “verified” flag and does not treat an
identifier, self-check, hash provided by the same untrusted source, HTTPS, or
caller assertion as proof. The artifact directory parameter is only a source
location; the API cannot establish it is authenticated. Do not expose this API
as a production install entry point until that real verification layer and
preflight are integrated. TUF-style metadata, Ed25519 + ML-DSA validation,
key rotation/revocation and anti-rollback state are not implemented.

Other unimplemented integration work includes executable-format/architecture
checks, preflight (state schema, seccomp/capability, disk space), health
supervision beyond exit status (health channel, timeouts, signal
forwarding), fingerprint state schema across exec, service manager wiring,
permissions and lock/concurrency policy, state migration, artifact cleanup,
fd handoff, and fault-injection/power-cut validation. The supervisor binary
above implements child spawn/wait and journal-driven confirm/rollback only;
it is not a service manager and does no restart loop of its own.

## Filesystem security and platform boundary

Version identifiers are restricted to ASCII alphanumeric plus `. _ + -`, cannot
start with `.`, and cannot contain path separators or traversal. Store root and
artifact paths reject symlink components; the artifact tree rejects symlinks,
hard-linked regular files, and special files. Copy is bounded to 2 GiB, 100,000
entries, and 64 nested directory levels. Unix staged directories/files and
journal temporary files are created mode `0700`/`0600`; executable files retain
an executable bit (staged mode `0700`), while non-executables are `0600`. The
root and its parents still must be trusted and not attacker-writable; the
artifact source must remain immutable/trusted during copying because portable
path-based traversal cannot close every source-side TOCTOU race. Concurrent
writers are not serialized; callers must ensure exclusive access.
This is not a defense against a malicious privileged writer racing the store.

The transaction uses same-filesystem staging, `File::sync_all`, same-directory
temporary files, atomic rename, and parent-directory fsync. **This initial
implementation currently supports successful durable transactions only on
Linux.** Windows and macOS are not intended to be permanently excluded; their
platform backends remain unimplemented and fail closed today. Before enabling
Windows, implement and review `ReplaceFileW`/`MoveFileExW` replacement semantics,
`FlushFileBuffers`, and a precise parent-directory durability strategy; before
enabling macOS, implement and review directory `fsync` and the required
`F_FULLFSYNC` policy. Add platform-specific GitHub Actions and fault/reboot
validation before claiming either platform's guarantees. There is no claim of
equivalent guarantees on Windows/macOS, network filesystems, FUSE, or unusual
storage devices in this initial version. Linux guarantees must still be tested
on supported filesystem/mount configurations, including actual power-loss
testing.

## Required CI gates before release

Run `cargo test -p boreas-supervisor`, `cargo clippy -p boreas-supervisor
--all-targets -- -D warnings`, and `cargo fmt --check` in CI; local runs are
development feedback only and are not release evidence. Current tests cover
the journal/pointer primitives plus the supervisor CLI driving real child
scripts: trial non-zero exit and death-by-signal roll back, zero exit
confirms and retains the old directory, an unconfirmed `Activated` journal
is rolled back before the old program launches (never confirming after
`recover()`), repeated `supervise` runs keep the pointer consistent, and
missing argv/program or a dangling pointer fail closed with `status`
reporting the on-disk truth. Still to expand before any gate claim:
process-level crash injection at each durable write boundary (including
`SIGKILL` of the supervisor itself mid-trial), disk-full/permission failures,
symlink and traversal races, concurrency, supported filesystem matrix,
power-cut testing, real service-manager restart integration, and
old-version executable recovery in the shipped layout. Then satisfy the
master plan's `G-UPGRADE` and `G-SUPPLY` gates plus the common production
exit conditions. The code here is an initial core plus a minimal supervisor
boundary, not proof those gates pass.
