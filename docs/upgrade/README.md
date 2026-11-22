# Upgrade transaction core, external supervisor and release-metadata boundary

`boreas-supervisor` is an independent Rust 2024, version `0.1.0`, GPL-3.0-only
crate: a crash-recoverable upgrade journal plus the external supervisor
executable (master plan §1.1/§10.3), and a strict release-metadata layer
(§10.2). The Linux systemd tools wire it to the daemon for the offline operator
path below. It adds no downloader and does **not** claim `G-UPGRADE` or
`G-SUPPLY`. The component descriptions below also cover the generic store and
stub paths; those are not the verified systemd deployment recipe.

## Status at a glance

| Area | State |
| --- | --- |
| Journal / active pointer / recovery | present in source; CI/test evidence for the exact commit must be checked before deployment claims |
| Windows transaction backend | **not integrated**; store fails closed |
| Exclusive store lock | source uses `File::try_lock`; exact-commit validation required |
| Trial readiness (Unix AF_UNIX + peer credentials + challenge/schema policy) | generic stub tests; the verified Linux systemd fixture uses the real daemon and sealed-image binding |
| Signal forwarding + controlled stop | Unix source present; Windows fail-closed |
| Durable trial budget across restarts | source present (`trial.state`); exact-commit validation required |
| Strict manifest parsing + policy | source present; exact-commit validation required |
| Ed25519 + ML-DSA-65 verification | source present behind `openssl-backend` (OpenSSL 3.5+); default build fails closed; exact-commit crypto CI still must be verified |
| Artifact size + SHA-256 check | bounded in-memory bytes on `VerifiedAsset` behind that feature; no streaming downloader |
| Durable anti-rollback / TUF roles / SBOM | verified Linux local watermark present; snapshot-resistant state, TUF roles and SBOM not implemented here |

Dependencies: `libc = "=0.2.191"` for **Unix** (the macOS `F_FULLFSYNC` flush plus
the Linux/macOS readiness and signal backends; already locked by `boreas-tun`),
and `openssl = "=0.10.82"` as an **optional** dependency used only by the
`openssl-backend` feature (the same pin `boreas-pki`/`boreas-crypto` use). The
default workspace build compiles no crypto; `Cargo.lock` must be regenerated
once by the `Refresh Cargo.lock` workflow before `--locked` jobs resolve any new
edges. `serde`/`serde_json` were deliberately not added: the manifest reader is
a small, strict, hand-written JSON subset.

## Automatic update remains blocked

Plain `boreas update-check` and console entry 7 still perform [advisory tag discovery](../releases/README.md#13-只读更新检查). The release-branch JSON is the `{product,schema,stable,prerelease}` index, not the supervisor's strict signed `manifest_version:1` release manifest. GitHub metadata cannot bind an authenticated channel or version; the signed manifest has no SemVer or channel fields. The production promotion bundle is also distinct: its JSON envelopes, outer promotion manifest, and archive/platform vocabulary are not the verified service's raw signatures and bare static ELF. No source or format is implicitly upgraded or converted.

### Explicit signed metadata discovery

```sh
boreas update-check --signed-feed https://updates.example.test/candidate \
  --trust-dir /absolute/path/to/provisioned-public-release-trust
```

- Run a pretrusted Boreas CLI as an **unprivileged** user on x86-64 or AArch64 Linux, with `openssl-inner-tls` (which enables the existing supervisor `openssl-backend`, OpenSSL ≥3.5). The URL is illustrative. No approved endpoint, mirror list, key, or manifest is shipped or inferred. This mode is CLI-only and cannot be combined with `--channel`. Default builds and other platforms fail before networking.
- Obtain both ReleaseRoot public SPKI DER keys, key ID and the sequence floor independently of the feed, and verify the fingerprints through a trusted channel. Supply `ed25519.der`, `mldsa65.der`, one LF-terminated `key-id`, and one LF-terminated `min-sequence` (canonical positive decimal `u64`). Use a local directory (not a remote mount) separately provisioned for reading by the invoking user. Every directory in its ancestry and each regular input must be owned by root or the invoking UID, not group-/world-writable, and not a symlink. Prefer a root-maintained public directory; do not loosen the offline service's private `/etc/boreas/release-trust`. Writers with the same UID and administrators are in the trust boundary. Update local pins/floor administratively before running checks; do not edit them concurrently with a check. No online pin import, TOFU, fallback key, or signing private keys.
- Serve three direct HTTPS `200` responses under the specified base, without redirects: `release-manifest.json` (≤1 MiB), `release-manifest.ed25519.sig` (exactly 64 bytes) and `release-manifest.mldsa65.sig` (exactly 3309 bytes). Both signatures are raw detached bytes over the **same exact** supervisor manifest bytes. Use the offline staging manifest schema with one intended native `*-unknown-linux-musl` asset and current `boreas-node-state-v1` claim. Publish the three matching responses as a coherent set; mixed responses fail verification. The client uses bounded system curl with normal CA/TLS checks, TLS ≥1.2, no proxy, inherited credentials, configuration, or redirects, and one shared five-second check budget. No signed-mode failure triggers the advisory index or GitHub fallback.
- The supervisor verifies Ed25519 **AND** ML-DSA-65 against the local root and then parses strictly, checks the signed key ID, and applies expiry, ≤90-day lifetime, the configured sequence floor, and unique native target policy. The CLI additionally rejects a future issue time, incompatible schema claim, or size claim over the offline 64 MiB ELF bound. Host UTC must already be trustworthy. Success (`0`) reports only signed sequence, expiry, target and asset name, and raw manifest SHA-256; neither the URL inside the manifest nor any asset is fetched. Failure (`1`) is unavailable/rejected; invalid CLI syntax/base URL/path form on a supported build (`2`) is not a check. Nothing claims the manifest is the newest, promotion-approved, or locally admissible; the hash alone is not approval.
- Discovery does not read or update the install watermark, cache manifests, compare active versions, or remember equivocation. An old but unexpired manifest at/above the configured floor can still replay, and a network outage can withhold new releases. It does not mint a receipt or credential for installation.

### Administrator-approved online apply

After independently reviewing the release, its signed sequence and target, and the exact raw manifest SHA-256, run the pretrusted administrator CLI (replace the placeholders; do not pipe a check result into `apply`):

```sh
sudo /absolute/path/to/pretrusted/boreas update apply \
  --confirm-manifest-sha256 REVIEWED_64_LOWERCASE_HEX \
  --signed-feed https://updates.example.test/candidate
```

- Requires the verified Linux/systemd deployment, a feature-enabled, independently trusted CLI, and the installed offline ReleaseRoot and acceptance floor (`/etc/boreas/release-trust`). There is no apply-time `--trust-dir`, channel, default feed, or fallback. Review which hosts your approved feed uses: the signed asset URL may be on another HTTPS origin and must return a direct `200`, without redirects, credentials, or proxy. The existing public advisory index, GitHub Releases redirects/archives and production promotion envelopes are not this feed. Unless you already operate a compatible signed endpoint, provision one serving the three metadata objects above and the bare ELF at its signed URL; no publisher, production URL or signing key is added here.
- Each HTTPS request runs trusted system curl as the non-root `nobody` UID/GID (distinct from the dedicated `boreas` UID/GID), with an empty environment, no inherited extra file descriptors or supplementary groups, and no privilege gain. The CLI uses one 120-second download/verification deadline and authenticates both signatures, native target, freshness, floor and schema; only a matching reviewed manifest digest permits the asset request. Signed length (at most 64 MiB), SHA-256 and native static ELF are checked before writing. No archive extraction is performed.
- The CLI writes the exact signed bytes, both signatures, and non-executable asset into a fresh root-owned `/run/boreas-online.*` spool readable only by root and group `boreas`. The installed helper gets the four local paths and the same reviewed hash. It rechecks the inputs and local admission state as `boreas` before stopping the unit and again before staging. Its durable watermark, sealed-image readiness, minimum runnable sequence and retained-version rollback remain authoritative. This may restart the unit; it is not a seamless handover or post-confirmation health monitor. The CLI removes its temporary spool on normal return, including helper failure; after forced termination an administrator may remove a stale spool **once the operation is no longer running**. The download deadline is not a timeout on the helper's service operation.
- The [Linux/systemd local verify/apply procedure](../deployment/VERIFIED-SERVICE.md) is unchanged; it needs no network or curl. Use it if the signed feed or online command is unavailable. `boreas update verify` checks the files and local admission state without stopping service or writing the store.

Regression coverage belongs to the existing workspace and Rust TLS workflows (`boreas-cli/openssl-inner-tls` on Linux). Test-key fixtures inject metadata and asset replies, exercise bad/mixed signatures, exact approval gating, freshness, policy, transport errors, size/digest/ELF checks, and the four-file handoff. These fixtures do not imply live HTTP, systemd or production-feed evidence.

Before an automatic action can be considered:

1. Establish an approved production feed and lifecycle for independent ReleaseRoot pins (bootstrap, rotation, revocation and trusted UTC). Explicit signed discovery makes no such approval or provisioning decision and grants no unattended credentials.
2. Cryptographically bind release version/channel and promotion evidence to exactly one deployable asset per platform. Reconcile the promotion tool's archive/envelope and platform vocabulary with the deployment path's raw signed manifest, detached signatures, native Rust target and bare static ELF; no automatic conversion or claim of promotion verification. If archives are supported in a future automated flow, define controlled extraction into verified staging. The explicit online bridge only handles bare signed ELF bytes; an advisory tag, same-origin digest or HTTPS is insufficient.
3. Protect monotonic admission state against snapshots/restores and administrative or same-UID tampering; the current durable watermark assumes trusted local storage/ancestry and is not a hardware monotonic counter. Define revocation and safe state migration/rollback for supported platforms, and an explicit automation/service-manager authorization policy.
4. Verify the exact shipped binaries, trust provisioning and supported platform matrix in CI and deployment evidence, including recovery under power loss, disk failures and interruption, and complete promotion review. The Linux offline fixture does not confer production approval; Windows/macOS/OpenWrt have no offline execution bridge.

## Transaction model

`UpgradeStore::open(root)` opens a trusted, already-existing, non-symlink store
root and creates `versions/`, `staging/`. `prepare(&Candidate, artifact_dir)`
accepts a simple version identifier and an *already authenticated* artifact
directory, copies regular files/directories to same-filesystem staging, rejects
symlinks/special files/hard links, flushes staged file data, then renames into
`versions/<version>` and durably writes a `Prepared` journal recording the
retained old version. `activate()` atomically replaces `active.version` and
records `Activated`. `confirm()` records `Confirmed` only after the supervisor's
readiness handshake succeeds (see below). `recover()`
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
*in-flight* **before the active pointer can move** — `supervise` reserves from
the journal's `Prepared` candidate and only then calls `begin_activation`, so a
kill at any point after the reservation (including between `activate()` and the
spawn) still consumes the attempt when the next supervisor starts. An exhausted
budget therefore fails before activation: the candidate is never briefly
selected just to be rolled back. `mark_trial_failed` flips the record to
`failed` (keeping the count); `clear_trial` removes it after a confirmed
upgrade, or when the operator runs the confirmed `reset-trial`. A corrupt
ledger is `UpgradeError::CorruptTrial`, never "no attempts yet". The ledger can
only ever *restrict* launches, so tampering causes denial of upgrades, never
authorization.

The attempt counter uses checked arithmetic, so overflow does not grant extra
trials; corrupted or failed ledger I/O must be treated as an operational refusal
and investigated, not as a reason to bypass the budget.

## External supervisor executable

The binary exposes four commands and has no `prepare`/`activate`, so no
unverified artifact can be staged through it:

* `supervise --store <DIR> --ready-expected-schema <ID> [--ready-timeout-ms <MS>]
  [--ready-require-tun <yes|no>] [--ready-min-workers <N>] [--stop-grace-ms <MS>]
  [--max-trial-attempts <N>] -- <argv...>` (`--ready-expected-schema` is required;
  other bracketed flags are optional)
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
* `reset-trial --store <DIR> --confirm <VERSION>` — operator acknowledgement:
  `--confirm` must repeat the exact candidate version recorded in `trial.state`;
  an audit line is appended to `trial.audit` **before** the budget is cleared,
  and a failed audit write leaves the ledger untouched. Nothing else clears a
  spent budget.

CLI outcomes: `0` means command success (or child exit 0); supervisor-side errors,
including usage/store/spawn/readiness/rollback errors, return `1`. For steady,
confirmed, and rolled-back child launches, the child's exit code is propagated;
a child killed by signal `n` maps to `128+n`. Check stderr and `status` for
context; the CLI does not define richer machine-readable error codes.

### Trial readiness (the gate; liveness alone confirms nothing)

A trial launch is confirmed only after an **authorized readiness answer**. Before
spawning the candidate the supervisor:

1. binds `<store>/ready.sock` as an `AF_UNIX` stream socket with mode `0600` and
   exports the path as `BOREAS_READY_SOCKET` (Unix only; Windows trial readiness
   is unavailable and fails closed);
2. accepts one connection and checks peer credentials — same uid in all cases
   (`SO_PEERCRED` on Linux, `getpeereid` on macOS) and, on Linux, the **exact
   spawned pid**;
3. sends a fresh 32-byte random challenge (from `/dev/urandom`) and requires the
   candidate to echo it together with its state schema, ready-worker count and
   TUN status.

`--ready-timeout-ms` (default 30 000) bounds the whole exchange;
`--ready-min-workers` (default 1) and `--ready-require-tun` (default `yes`)
define acceptance. `--ready-expected-schema <ID>` is **required** (1–64 ASCII
identifier bytes; alphanumeric plus `._+-`, not starting with `.`); the candidate
must report this exact schema. A silence, foreign peer, wrong echo or schema,
malformed framing, worker count below policy or absent required TUN all fail the
trial and trigger rollback/attempt accounting (subject to successful store I/O).

That is what closes two holes the old behaviour had: "exit 0 immediately" and
"alive but deadlocked/unready" both used to look like success. A process that is
alive but wedged can no longer be confirmed, because it cannot produce a valid
answer.

Deliberate limits, stated rather than implied:

* the challenge is **not yet bound to the candidate artifact SHA-256** — that
  belongs with the `verify_release` → `prepare` wiring, which is not done;
* the Linux Boreas daemon exists, but it does not answer the supervisor's
  trial-readiness challenge. Integration tests exercise the protocol against
  the hidden `__ready-stub` candidate (`tests/readiness.rs`); they do not verify
  readiness or rollback of the deployed daemon;
* there is no `sd_notify` readiness, no launch timeout beyond the readiness
  deadline, and no health probing after confirmation.

The durable budget bounds trial launches across process lifetimes:
`--max-trial-attempts` (default 3), then `supervise` refuses to activate the
candidate and the operator may inspect the store before considering the audited
`reset-trial` procedure. This is a CLI component, not a complete deployment
recipe: without an installer, daemon integration, or shipped service unit, do not
copy an illustrative invocation into production.

### Signals: forwarding and controlled stop

`supervise` installs handlers for `SIGTERM`/`SIGINT`/`SIGHUP`. The handler only
stores the signal number in an atomic (async-signal-safe), and the wait loop:

* forwards the signal to the child, then gives it `--stop-grace-ms` (default
  10 000) before escalating to `SIGKILL`;
* fails the trial and rolls back if the stop arrives **before** readiness —
  an interrupted candidate never proved itself;
* after confirmation, treats the stop as an ordinary runtime stop and exits
  `128+n` when the child dies from the forwarded signal.

The group/console contract still applies underneath: a cgroup-wide stop reaches
the child directly, and a supervisor killed mid-trial leaves the durable
`Activated` journal plus the `in-flight` reservation for the next boot (§10.3).
A service unit should still use `KillMode=control-group` and a bounded
`Restart=`.

Not provided, and not claimed: Windows signal semantics (its store path stays
fail-closed), per-signal exit mapping beyond `128+n`, and any graceful drain of
an already-confirmed daemon past the forwarded signal.

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
* With `openssl-backend`, source implements dual verification: `release_crypto`
  parses both anchors as SPKI DER, checks `KeyType::ED25519` and
  `KeyType::ML_DSA_65`, and checks both signatures over the exact bytes. Its
  artifact helper checks size and SHA-256 for an already-bounded in-memory byte
  slice against the authenticated manifest. This is not a downloader or a
  streaming file verifier. `ReleaseRoot` stores DER keys to permit algorithm
  checks. Do not describe this feature as release-validated until the exact
  commit has passed the required OpenSSL 3.5+ CI job.
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

Still open: TUF-style root/targets/snapshot/timestamp roles with threshold and
rotation, revocation, SBOM/provenance, downloader and redirect policy, bounded
streaming artifact verification wired to staging, and durable anti-rollback
persistence. The OpenSSL provider implementation exists in source behind the
feature, but its exact-commit CI/test status is not established by this document;
do not claim it passed until verified.

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

**macOS** source (`src/macos.rs`, `libc` 0.2.191) uses `fcntl(F_FULLFSYNC)`
(failure is returned, never silently downgraded to `fsync`), and namespace
changes are followed by a directory sync. The same transaction suite is configured for Linux and both macOS CI targets;
check the exact commit's completed Actions results before calling this backend
tested or using CI configuration as deployment evidence.
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

The repository configures `cargo test --workspace --locked`,
`cargo clippy --workspace --all-targets --locked -- -D warnings` and a platform
matrix (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
`x86_64-pc-windows-msvc`, both macOS targets) in GitHub Actions. Configuration is
not evidence that a run passed: verify the completed Actions results for the
exact release commit. Compilation, formatting and tests are Actions-only under
repository policy; do not run them locally.

Source tests are present for journal/pointer behavior, trial failure and
readiness, the Unix `__ready-stub` subprocess protocol, trial accounting,
operator reset, locking, status and fail-closed CLI cases. Manifest tests cover
strict parsing, URL subset, timestamps, policy, asset selection and the
in-memory ledger. This list describes checked-in test coverage, not a passing run:
verify the exact commit's Actions results before claiming tests passed. There is
no real daemon readiness integration.

Crypto validation remains an explicit release check: run
`cargo test -p boreas-supervisor --features openssl-backend` on a runner with
**OpenSSL 3.5+**, and confirm the exact commit's result. The default build has no
crypto and exercises only the fail-closed path. A configured workflow or a
successful default build does not validate the crypto feature.

Still to expand before any gate claim: process-level crash injection at every
durable write boundary (including `SIGKILL` of the supervisor mid-readiness),
disk-full/permission failures, symlink and traversal races, supported-filesystem
matrix, power-cut testing, real service-manager restart integration, a real
daemon that answers the readiness challenge (the protocol currently has only the
stub counterpart), binding the challenge to the candidate artifact SHA, and
old-version executable recovery in the shipped layout. Then satisfy the master
plan's `G-UPGRADE` and `G-SUPPLY` gates plus the common production exit
conditions. The checked-in source is an upgrade/supervision core, not proof that
those gates pass or that it is ready for production deployment.
