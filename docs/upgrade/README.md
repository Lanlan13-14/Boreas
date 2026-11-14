# Upgrade transaction core (initial implementation)

`boreas-supervisor` is an independent Rust 2024, version `0.1.0`, GPL-3.0-only
library with no third-party dependencies. It is intended for later integration
into the existing single `boreas` CLI binary; it does **not** add a daemon,
installer command, updater, or service unit.

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
pointer. Recovery is a library state transition, not a process launcher: the
external supervisor must invoke it before starting the program. Restarting a
broken active executable repeatedly is not recovery.

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
supervision/timeout, process restart/exec, service manager wiring, permissions
and lock/concurrency policy, state migration, artifact cleanup, fd handoff,
and fault-injection/power-cut validation.

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

Run crate unit tests and formatting/lint checks in GitHub Actions only (per the
repository's development constraint; do not run cargo/rustc/test/formatter
locally). Expand tests to cover process-level crash injection at each durable
write boundary, corrupt/missing pointer and journal, disk-full/permission
failures, symlink and traversal races, concurrency, supported filesystem
matrix, real external supervisor restart, and old-version executable recovery.
Then satisfy the master plan's `G-UPGRADE` and `G-SUPPLY` gates plus the common
production exit conditions. The code here is an initial core, not proof those
gates pass.
