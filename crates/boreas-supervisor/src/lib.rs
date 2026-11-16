//! Minimal, self-contained primitives and an external-supervisor entrypoint
//! for Boreas upgrades.
//!
//! This crate does not download a release and exposes no install entry point.
//! Manifest bytes can be authenticated through [`manifest::verify_release`]
//! (see below), but nothing here wires authentication to
//! [`UpgradeStore::prepare`], so no artifact is stageable through a user-facing
//! path. There is no `bool`/"verified" escape hatch: the trusted types
//! ([`manifest::VerifiedManifest`], [`manifest::VerifiedCandidate`]) have
//! private fields and are produced only by the verifier.
//!
//! The bundled `boreas-supervisor` binary is the real process boundary for
//! those primitives: it takes an exclusive store lock, recovers the store
//! before launching anything, launches the selected program as a real child,
//! confirms a trial candidate only after a liveness soak (survival, not
//! readiness and not merely exit status 0), and rolls back via
//! [`UpgradeStore::recover`] on any other outcome. Failed trials are bounded by
//! a durable per-candidate budget in `trial.state`, so a crash loop cannot
//! retry a candidate forever.
//!
//! Strict release-metadata parsing, deployment policy and the single
//! signature-verification choke point live in [`manifest`]. With the
//! `openssl-backend` feature that choke point performs real Ed25519 **and**
//! ML-DSA-65 verification (SPKI DER key parsing + `KeyType` checks) plus
//! SHA-256 asset hashes through [`release_crypto`]; the default build compiles
//! no crypto and fails verification closed. That backend is implemented but
//! **not yet validated in CI** — it needs an OpenSSL 3.5+ job — so no release
//! authenticity claim is made here.
//!
//! Still NOT implemented: preflight (ELF/architecture/state-schema/seccomp/disk
//! checks), signal forwarding and graceful stop handling, an application
//! readiness channel (authorized `AF_UNIX` + peer credentials, challenge bound
//! to candidate SHA/schema/workers/TUN) and launch timeouts, TUF-style role
//! separation with durable anti-rollback, OS service integration (systemd et
//! al.), and the fault-injection / power-cut matrix. Nothing here satisfies the
//! master plan's `G-UPGRADE` or `G-SUPPLY` gate.
//!
//! Transactions use a durable journal and one atomically replaced active
//! pointer. Unconfirmed activations are rolled back by
//! [`UpgradeStore::recover`], which an external supervisor process must
//! invoke before starting the selected version; the supervisor binary calls
//! [`UpgradeStore::begin_activation`], the single reviewed composition of
//! that recovery with the one permitted first launch of a `Prepared`
//! candidate.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

/// macOS `F_FULLFSYNC` flush plus directory-fsync ordering. Compiled only on
/// macOS; every symbol comes from the pinned `libc` binding in `Cargo.toml`.
#[cfg(target_os = "macos")]
mod macos;

// `src/windows.rs` is intentionally not declared here: it needs
// `windows-sys` (absent from `Cargo.lock`) and the store still has no
// explicit-DACL verification or documented parent-directory durability, so
// `UpgradeStore::open` must keep failing closed on Windows. See
// `docs/upgrade/README.md` for the exact remaining gate.

pub mod control_auth;
pub mod drain;
pub mod install;
pub mod manifest;
pub mod preflight;
pub mod sandbox;

/// Shared private constants for the supervisor readiness wire protocol.
#[cfg(target_os = "linux")]
mod readiness_protocol;
/// Bounded client for applications reporting trial readiness.
pub mod ready_client;

/// Real Ed25519 + ML-DSA-65 verification and artifact SHA-256. Compiled only
/// with the `openssl-backend` feature (OpenSSL 3.5+); `manifest::verify_release`
/// delegates to it and stays fail-closed in the default build.
#[cfg(feature = "openssl-backend")]
mod release_crypto;

const JOURNAL_FILE: &str = "upgrade.journal";
const ACTIVE_FILE: &str = "active.version";
const LOCK_FILE: &str = "store.lock";
const TRIAL_FILE: &str = "trial.state";
const AUDIT_FILE: &str = "trial.audit";
const FORMAT: &str = "BOREAS-UPGRADE-1";
const TRIAL_FORMAT: &str = "BOREAS-TRIAL-1";
const MAX_JOURNAL_BYTES: u64 = 512;
const MAX_ACTIVE_BYTES: u64 = 129;
const MAX_TRIAL_BYTES: u64 = 256;
const MAX_AUDIT_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 64;
const MAX_TREE_ENTRIES: usize = 100_000;

#[derive(Debug)]
pub enum UpgradeError {
    Io(io::Error),
    Invalid(&'static str),
    CorruptJournal,
    /// The durable trial ledger is unreadable or corrupt. A spent trial budget
    /// must never be silently treated as "no attempts yet".
    CorruptTrial,
    NoTransaction,
    WrongState,
    /// Another process already holds the store's exclusive supervisor lock.
    Locked(String),
    /// The durable trial ledger shows every permitted launch of this candidate
    /// was consumed. Only an operator (`reset-trial`) may clear it.
    TrialExhausted {
        version: String,
        attempts: u32,
    },
    UnsupportedPlatform(&'static str),
}
impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "upgrade I/O error: {e}"),
            Self::Invalid(s) => write!(f, "invalid upgrade input: {s}"),
            Self::CorruptJournal => f.write_str("upgrade journal is corrupt or unsupported"),
            Self::CorruptTrial => f.write_str("trial ledger is corrupt or unsupported"),
            Self::NoTransaction => f.write_str("no upgrade transaction exists"),
            Self::WrongState => f.write_str("operation is invalid in the current state"),
            Self::Locked(detail) => write!(
                f,
                "store is locked by another supervisor process ({detail})"
            ),
            Self::TrialExhausted { version, attempts } => write!(
                f,
                "trial budget exhausted for candidate {version} after {attempts} attempt(s); \
                 inspect the store, then run `reset-trial` to allow another trial"
            ),
            Self::UnsupportedPlatform(s) => write!(f, "unsupported durability operation: {s}"),
        }
    }
}
impl Error for UpgradeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}
impl From<io::Error> for UpgradeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
pub type Result<T> = std::result::Result<T, UpgradeError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Phase {
    Prepared,
    Activated,
    Confirmed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Journal {
    pub old_version: Option<String>,
    pub new_version: String,
    pub phase: Phase,
}

/// Caller-supplied release facts. Strings are identifiers only, not evidence of
/// authenticity. `prepare` enforces safe layout but does not validate the binary.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub version: String,
}

/// Filesystem-backed transaction store rooted in an administrator-chosen directory.
/// The root and all its parents must be trusted and not writable by attackers.
/// Linux flushes file data with `fsync` and orders namespace changes with
/// directory `fsync`; macOS asks for `F_FULLFSYNC` on file data and then syncs
/// the directory. Windows still fails closed rather than claiming equivalent
/// parent-directory durability. No platform's power-loss behaviour is proven
/// by this crate's tests, and no paths outside `root` are accepted.
pub struct UpgradeStore {
    root: PathBuf,
    versions: PathBuf,
    staging: PathBuf,
}

impl UpgradeStore {
    /// Create/open a store. Root must already exist and be a real directory (not a symlink).
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        reject_symlink_components(&root)?;
        let meta = fs::symlink_metadata(&root)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(UpgradeError::Invalid(
                "root must be a non-symlink directory",
            ));
        }
        let versions = root.join("versions");
        let staging = root.join("staging");
        ensure_child_dir(&root, &versions)?;
        ensure_child_dir(&root, &staging)?;
        restrict_private_dir(&versions)?;
        restrict_private_dir(&staging)?;
        sync_dir(&root)?;
        Ok(Self {
            root,
            versions,
            staging,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Install an already-verified candidate directory. `artifact` must be a
    /// real directory on the same filesystem as this store; files are copied
    /// without following symlinks, then synced before an atomic rename.
    /// Authenticity MUST be established by a genuine verifier before this call.
    pub fn prepare(&self, candidate: &Candidate, artifact: impl AsRef<Path>) -> Result<Journal> {
        validate_version(&candidate.version)?;
        let old = self.active_version()?;
        if old.as_deref() == Some(candidate.version.as_str()) {
            return Err(UpgradeError::Invalid("candidate is already active"));
        }
        if self
            .read_journal()?
            .is_some_and(|j| j.phase != Phase::Confirmed)
        {
            return Err(UpgradeError::WrongState);
        }
        let src = artifact.as_ref();
        reject_symlink_components(src)?;
        let src_meta = fs::symlink_metadata(src)?;
        if !src_meta.is_dir() || src_meta.file_type().is_symlink() {
            return Err(UpgradeError::Invalid("artifact must be a real directory"));
        }
        if !same_device(&self.root, src)? {
            return Err(UpgradeError::Invalid(
                "artifact must be on the store filesystem",
            ));
        }
        let stage = self.staging.join(format!("{}.tmp", candidate.version));
        let dest = self.versions.join(&candidate.version);
        if path_entry_exists(&stage)? || path_entry_exists(&dest)? {
            return Err(UpgradeError::Invalid(
                "candidate stage/version already exists",
            ));
        }
        let mut budget = CopyBudget {
            bytes: 0,
            entries: 0,
        };
        if let Err(error) = copy_tree_no_symlinks(src, &stage, 0, &mut budget) {
            let _ = fs::remove_dir_all(&stage);
            let _ = sync_dir(&self.staging);
            return Err(error);
        }
        sync_tree(&stage)?;
        sync_dir(&self.staging)?;
        fs::rename(&stage, &dest)?;
        // Rename crosses two directories on the same filesystem; persist both
        // directory entries before recording Prepared.
        sync_dir(&self.staging)?;
        sync_dir(&self.versions)?;
        let journal = Journal {
            old_version: old,
            new_version: candidate.version.clone(),
            phase: Phase::Prepared,
        };
        self.write_journal(&journal)?;
        Ok(journal)
    }

    /// Atomically select the prepared version. The old version directory remains intact.
    pub fn activate(&self) -> Result<()> {
        let mut j = self.read_journal()?.ok_or(UpgradeError::NoTransaction)?;
        if j.phase != Phase::Prepared {
            return Err(UpgradeError::WrongState);
        }
        self.ensure_version_exists(&j.new_version)?;
        self.write_active(Some(&j.new_version))?;
        j.phase = Phase::Activated;
        self.write_journal(&j)
    }

    /// Mark the new version healthy. Only the running new program should request this
    /// after its externally defined health gate; this API alone does not prove health.
    pub fn confirm(&self) -> Result<()> {
        let mut j = self.read_journal()?.ok_or(UpgradeError::NoTransaction)?;
        if j.phase != Phase::Activated || self.active_version()?.as_deref() != Some(&j.new_version)
        {
            return Err(UpgradeError::WrongState);
        }
        j.phase = Phase::Confirmed;
        self.write_journal(&j)
    }

    /// Recover before launching anything. Any unconfirmed journal rolls the active
    /// pointer back to the retained old version (or clears it for first install).
    /// Prepared candidates are left on disk for diagnosis/retry; they are never run.
    pub fn recover(&self) -> Result<Recovery> {
        let Some(mut j) = self.read_journal()? else {
            return Ok(Recovery::NoTransaction);
        };
        if j.phase == Phase::Confirmed {
            let active = self.active_version().ok().flatten();
            if active.as_deref() == Some(j.new_version.as_str()) {
                return Ok(Recovery::Confirmed { active });
            }
            // A confirmed record with a missing/malformed/mismatched pointer is
            // inconsistent. Fail safe by restoring the retained previous version
            // rather than reporting success or launching an uncertain target.
            self.write_active(j.old_version.as_deref())?;
            let old = j.old_version.clone();
            j.phase = Phase::Prepared;
            self.write_journal(&j)?;
            return Ok(Recovery::RolledBack { active: old });
        }
        // Do not parse/follow the current pointer here: it may reference a
        // missing or malformed candidate after a crash. Replace it directly
        // with the journal's validated retained version (or an empty pointer).
        self.write_active(j.old_version.as_deref())?;
        let old = j.old_version.clone();
        j.phase = Phase::Prepared;
        self.write_journal(&j)?;
        Ok(Recovery::RolledBack { active: old })
    }

    pub fn active_version(&self) -> Result<Option<String>> {
        let path = self.root.join(ACTIVE_FILE);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => Err(UpgradeError::Invalid(
                "active pointer is not a regular file",
            )),
            Ok(m) => {
                if m.len() > MAX_ACTIVE_BYTES {
                    return Err(UpgradeError::Invalid("active pointer exceeds size limit"));
                }
                let mut s = String::new();
                File::open(path)?
                    .take(MAX_ACTIVE_BYTES + 1)
                    .read_to_string(&mut s)?;
                if s.len() as u64 > MAX_ACTIVE_BYTES {
                    return Err(UpgradeError::Invalid("active pointer exceeds size limit"));
                }
                let s = s.strip_suffix('\n').unwrap_or(&s);
                if s.contains('\n') || s.contains('\r') {
                    return Err(UpgradeError::Invalid("active pointer has trailing data"));
                }
                if s.is_empty() {
                    Ok(None)
                } else {
                    validate_version(s)?;
                    self.ensure_version_exists(s)?;
                    Ok(Some(s.to_owned()))
                }
            }
        }
    }
    pub fn journal(&self) -> Result<Option<Journal>> {
        self.read_journal()
    }

    /// Return the absolute directory of a stored version after validating the
    /// identifier. This is a pure path computation: it does not require, or
    /// prove, that the version exists or that its contents are authentic.
    pub fn version_dir(&self, version: &str) -> Result<PathBuf> {
        validate_version(version)?;
        Ok(self.versions.join(version))
    }

    /// Return the active version for display/status **without** requiring the
    /// target directory to still exist.
    ///
    /// [`active_version`](Self::active_version) refuses a dangling pointer,
    /// which is the right fail-closed behaviour for *launching*; but a status
    /// report must still be able to show the operator that the pointer names
    /// a vanished version so they can diagnose it. Never use this to select a
    /// program to run: prefer [`active_version`](Self::active_version) and
    /// let its error stop the launch.
    pub fn recorded_active_version(&self) -> Result<Option<String>> {
        let path = self.root.join(ACTIVE_FILE);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => Err(UpgradeError::Invalid(
                "active pointer is not a regular file",
            )),
            Ok(m) => {
                if m.len() > MAX_ACTIVE_BYTES {
                    return Err(UpgradeError::Invalid("active pointer exceeds size limit"));
                }
                let mut s = String::new();
                File::open(path)?
                    .take(MAX_ACTIVE_BYTES + 1)
                    .read_to_string(&mut s)?;
                if s.len() as u64 > MAX_ACTIVE_BYTES {
                    return Err(UpgradeError::Invalid("active pointer exceeds size limit"));
                }
                let s = s.strip_suffix('\n').unwrap_or(&s);
                if s.contains('\n') || s.contains('\r') {
                    return Err(UpgradeError::Invalid("active pointer has trailing data"));
                }
                if s.is_empty() {
                    Ok(None)
                } else {
                    validate_version(s)?;
                    Ok(Some(s.to_owned()))
                }
            }
        }
    }

    /// How many distinct versions are currently stored under `versions/`.
    /// Used by status reporting to show that old versions are retained.
    pub fn stored_version_count(&self) -> Result<usize> {
        let mut count = 0usize;
        for entry in fs::read_dir(&self.versions)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() && !kind.is_symlink() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Take the store's exclusive single-writer lock.
    ///
    /// The lock is an OS advisory lock on `store.lock` (see [`StoreLock`]), so
    /// it disappears with the process instead of leaving a stale pidfile that
    /// would block every later upgrade. A second supervisor — or a concurrent
    /// `recover`, which mutates the journal — fails fast instead of racing the
    /// durable state.
    ///
    /// The lock file is untrusted input: its content is never read and never
    /// echoed into an error, so a hostile file cannot inject terminal escapes or
    /// log lines. Only the OS error text (which this crate does not control but
    /// also does not obtain from the file) is reported.
    pub fn lock_exclusive(&self) -> Result<StoreLock> {
        let path = self.root.join(LOCK_FILE);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
                return Err(UpgradeError::Invalid(
                    "lock file is not a regular, non-symlink file",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if let Err(error) = file.try_lock() {
            return Err(UpgradeError::Locked(error.to_string()));
        }
        Ok(StoreLock { _file: file })
    }

    /// The durable trial record, if any. Strictly parsed: a corrupt ledger is an
    /// error, never "this candidate has no attempts yet".
    pub fn trial_state(&self) -> Result<Option<TrialState>> {
        self.read_trial()
    }

    /// Durably reserve one more trial launch of `version`, enforcing
    /// `max_attempts`.
    ///
    /// The reservation is written *before* the candidate is launched, so a
    /// supervisor killed mid-trial still consumes its attempt when the next one
    /// starts. The ledger only ever *restricts* launches: an attacker who can
    /// write it can cause a denial of upgrades, never authorise one.
    pub fn reserve_trial(&self, version: &str, max_attempts: u32) -> Result<TrialState> {
        validate_version(version)?;
        if max_attempts == 0 {
            return Err(UpgradeError::Invalid("trial budget must be at least one"));
        }
        let current = self.read_trial()?;
        let previous = current
            .as_ref()
            .filter(|state| state.version == version)
            .map_or(0, |state| state.attempts);
        // `checked_add`, never saturating: at `u32::MAX` a saturating counter
        // would pin attempts at MAX and a caller passing `max_attempts = MAX`
        // would then grant unlimited trials. An overflow is a corrupt/absurd
        // ledger and fails closed instead.
        let attempts = previous
            .checked_add(1)
            .ok_or(UpgradeError::Invalid("trial attempt counter overflow"))?;
        if attempts > max_attempts {
            return Err(UpgradeError::TrialExhausted {
                version: version.to_owned(),
                attempts: previous,
            });
        }
        let state = TrialState {
            version: version.to_owned(),
            attempts,
            in_flight: true,
        };
        self.write_trial(&state)?;
        Ok(state)
    }

    /// Record that the reserved trial failed, or that its supervisor died while
    /// it ran. The attempt count is kept, so the budget is never reset by a
    /// crash or a failed launch.
    pub fn mark_trial_failed(&self) -> Result<()> {
        match self.read_trial()? {
            Some(mut state) => {
                if !state.in_flight {
                    return Ok(());
                }
                state.in_flight = false;
                self.write_trial(&state)
            }
            None => Ok(()),
        }
    }

    /// Forget the trial record: called after a confirmed upgrade, and by the
    /// operator-only `reset-trial` acknowledgement.
    pub fn clear_trial(&self) -> Result<()> {
        let path = self.root.join(TRIAL_FILE);
        match fs::remove_file(&path) {
            Ok(()) => sync_dir(&self.root),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Append one bounded audit record for an operator trial reset.
    ///
    /// The log is append-only and capped at `MAX_AUDIT_BYTES`. It is never
    /// truncated or rotated implicitly: silently discarding the history of a
    /// high-risk action is worse than refusing to write. Operator identity is
    /// deliberately not invented here — it comes from the OS audit trail
    /// (systemd journal / Windows event log) that invokes this command.
    pub fn record_trial_reset(&self, version: &str, attempts: u32) -> Result<()> {
        validate_version(version)?;
        let path = self.root.join(AUDIT_FILE);
        let existing_len = match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
                return Err(UpgradeError::Invalid(
                    "trial audit log is not a regular, non-symlink file",
                ));
            }
            Ok(m) => m.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        let line = format!("reset-trial version={version} attempts={attempts}\n");
        if existing_len > MAX_AUDIT_BYTES
            || existing_len.saturating_add(line.len() as u64) > MAX_AUDIT_BYTES
        {
            return Err(UpgradeError::Invalid(
                "trial audit log is full; archive it before resetting again",
            ));
        }
        let mut file = OpenOptions::new().append(true).create(true).open(&path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        sync_dir(&self.root)
    }

    fn read_trial(&self) -> Result<Option<TrialState>> {
        let path = self.root.join(TRIAL_FILE);
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_TRIAL_BYTES {
            return Err(UpgradeError::CorruptTrial);
        }
        let mut s = String::new();
        File::open(&path)?
            .take(MAX_TRIAL_BYTES + 1)
            .read_to_string(&mut s)?;
        if s.len() as u64 > MAX_TRIAL_BYTES {
            return Err(UpgradeError::CorruptTrial);
        }
        let mut lines = s.lines();
        if lines.next() != Some(TRIAL_FORMAT) {
            return Err(UpgradeError::CorruptTrial);
        }
        let version = lines.next().ok_or(UpgradeError::CorruptTrial)?.to_owned();
        validate_version(&version).map_err(|_| UpgradeError::CorruptTrial)?;
        let attempts: u32 = lines
            .next()
            .ok_or(UpgradeError::CorruptTrial)?
            .parse()
            .map_err(|_| UpgradeError::CorruptTrial)?;
        if attempts == 0 {
            return Err(UpgradeError::CorruptTrial);
        }
        let in_flight = match lines.next() {
            Some("in-flight") => true,
            Some("failed") => false,
            _ => return Err(UpgradeError::CorruptTrial),
        };
        if lines.next().is_some() {
            return Err(UpgradeError::CorruptTrial);
        }
        Ok(Some(TrialState {
            version,
            attempts,
            in_flight,
        }))
    }

    fn write_trial(&self, state: &TrialState) -> Result<()> {
        let outcome = if state.in_flight {
            "in-flight"
        } else {
            "failed"
        };
        let data = format!(
            "{TRIAL_FORMAT}\n{}\n{}\n{outcome}\n",
            state.version, state.attempts
        );
        atomic_write(&self.root, TRIAL_FILE, data.as_bytes())
    }

    /// Compose "recover before launch" with the single permitted first launch
    /// of a `Prepared` candidate, for the external supervisor process.
    ///
    /// State machine (master plan §10.3, `docs/upgrade/README.md`):
    ///
    /// * **No journal** — `recover()` reports [`Recovery::NoTransaction`]; the
    ///   existing active pointer (if any) is reported through
    ///   [`Activation::Steady`].
    /// * **journal `Confirmed`, pointer consistent** — the current version is
    ///   reported through [`Activation::Steady`].
    /// * **journal `Activated`** — a previous activation was never confirmed,
    ///   i.e. the candidate already had its one trial launch (or died trying
    ///   to). `recover()` rolls the pointer back to the retained old version,
    ///   and this composition reports [`Activation::RolledBack`] *without*
    ///   re-activating the candidate: the supervisor runs the old program,
    ///   and the candidate is not automatically retried.
    /// * **journal `Prepared`** — the candidate has never been launched.
    ///   `recover()` first restores/validates the retained-old pointer (it
    ///   also repairs the crash-mid-`activate` window: pointer already moved
    ///   while the journal still says `Prepared`), and only then does this
    ///   composition call [`activate`](Self::activate) exactly once and
    ///   report [`Activation::TrialLaunch`].
    /// * **journal `Confirmed` but pointer inconsistent** — `recover()` rolls
    ///   back and resets the journal to `Prepared`. This composition refuses
    ///   the launch ([`Activation::Refused`]) rather than silently treating
    ///   the reset as "never launched": corruption gets operator attention,
    ///   not an automatic retry.
    ///
    /// Limitation, stated plainly: `recover()` resets a rolled-back journal
    /// to `Prepared`, and `prepare()` also ends at `Prepared`, so from
    /// journal+pointer alone a pre-launch caller cannot distinguish "a
    /// candidate that was just prepared" from "a candidate whose trial
    /// already failed and was rolled back by an earlier `recover()`" —
    /// immediately after `prepare()` the pointer still names the old
    /// version, exactly as it does after a rollback; and once `activate()`
    /// has moved the pointer it also advances the journal to `Activated`,
    /// which is the one state this composition *can* refuse to retry. The
    /// supervisor CLI built on this method therefore never relies on this
    /// composition alone to avoid re-trialling a failed candidate across
    /// process lifetimes; see that binary's documented boot protocol.
    pub fn begin_activation(&self) -> Result<Activation> {
        let Some(before) = self.read_journal()? else {
            return Ok(Activation::Steady {
                active: self.active_version()?,
            });
        };
        match before.phase {
            Phase::Confirmed => match self.recover()? {
                Recovery::Confirmed { active } => Ok(Activation::Steady { active }),
                Recovery::RolledBack { active } => Ok(Activation::Refused {
                    active,
                    candidate: before.new_version,
                }),
                Recovery::NoTransaction => Err(UpgradeError::WrongState),
            },
            Phase::Activated => match self.recover()? {
                Recovery::RolledBack { active } => Ok(Activation::RolledBack {
                    active,
                    candidate: before.new_version,
                }),
                _ => Err(UpgradeError::WrongState),
            },
            Phase::Prepared => {
                // Recover first. This repairs the crash-mid-activate window
                // (pointer already at the candidate, journal still Prepared)
                // by restoring the retained pointer, and validates that the
                // old version a failing trial would fall back to really
                // exists. Only then is the one trial launch permitted.
                match self.recover()? {
                    Recovery::RolledBack { .. } => {}
                    _ => return Err(UpgradeError::WrongState),
                }
                self.activate()?;
                Ok(Activation::TrialLaunch {
                    candidate: before.new_version,
                    previous: before.old_version,
                })
            }
        }
    }

    fn ensure_version_exists(&self, v: &str) -> Result<()> {
        validate_version(v)?;
        let p = self.versions.join(v);
        let m = fs::symlink_metadata(&p)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(UpgradeError::Invalid(
                "version target is not a real directory",
            ));
        }
        Ok(())
    }
    fn read_journal(&self) -> Result<Option<Journal>> {
        let p = self.root.join(JOURNAL_FILE);
        let meta = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_JOURNAL_BYTES {
            return Err(UpgradeError::CorruptJournal);
        }
        let f = File::open(&p)?;
        let mut s = String::new();
        f.take(MAX_JOURNAL_BYTES + 1).read_to_string(&mut s)?;
        if s.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(UpgradeError::CorruptJournal);
        }
        let lines: Vec<_> = s.lines().collect();
        if lines.len() != 4 || lines[0] != FORMAT {
            return Err(UpgradeError::CorruptJournal);
        }
        let old = if lines[1] == "-" {
            None
        } else {
            validate_version(lines[1]).map_err(|_| UpgradeError::CorruptJournal)?;
            Some(lines[1].to_owned())
        };
        validate_version(lines[2]).map_err(|_| UpgradeError::CorruptJournal)?;
        if old.as_deref() == Some(lines[2]) {
            return Err(UpgradeError::CorruptJournal);
        }
        let phase = match lines[3] {
            "Prepared" => Phase::Prepared,
            "Activated" => Phase::Activated,
            "Confirmed" => Phase::Confirmed,
            _ => return Err(UpgradeError::CorruptJournal),
        };
        Ok(Some(Journal {
            old_version: old,
            new_version: lines[2].to_owned(),
            phase,
        }))
    }
    fn write_journal(&self, j: &Journal) -> Result<()> {
        let old = j.old_version.as_deref().unwrap_or("-");
        let data = format!("{FORMAT}\n{old}\n{}\n{:?}\n", j.new_version, j.phase);
        atomic_write(&self.root, JOURNAL_FILE, data.as_bytes())
    }
    fn write_active(&self, v: Option<&str>) -> Result<()> {
        if let Some(v) = v {
            self.ensure_version_exists(v)?;
        }
        atomic_write(&self.root, ACTIVE_FILE, v.unwrap_or("").as_bytes())
    }
}

/// Exclusive single-writer guard returned by [`UpgradeStore::lock_exclusive`].
///
/// Backed by the operating system's advisory file lock, so it cannot go stale:
/// the kernel releases it when the process exits, however it exits. Keep the
/// value alive for the whole recover → activate → launch sequence; dropping it
/// releases the lock.
pub struct StoreLock {
    _file: File,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // `File::unlock` is the std-documented way to release the advisory
        // lock held by this file. Attempt it before closing the descriptor,
        // rather than relying only on close/handle cleanup; Drop cannot return
        // an unlock error, so normal descriptor cleanup remains the fallback. On Unix the lock belongs to the open file description, and
        // `fork(2)` duplicates that description into a child until the child
        // execs (CLOEXEC only applies at exec), so closing just this
        // descriptor could leave the lock alive through another thread's
        // forked child. LOCK_UN on any duplicate releases the shared lock
        // immediately. The supervisor CLI retains this guard until its child
        // has been reaped. Library callers must likewise retain it for the
        // entire protected operation; dropping it intentionally ends ownership.
        let _ = self._file.unlock();
    }
}

/// Durable record of trial launches for one candidate version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrialState {
    pub version: String,
    /// 1-based number of trial launches reserved for `version`.
    pub attempts: u32,
    /// A reservation whose outcome was never recorded. Because only one
    /// supervisor can hold the store lock, an `in_flight` record seen by a new
    /// supervisor always belongs to a previous one that died mid-trial.
    pub in_flight: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recovery {
    NoTransaction,
    Confirmed { active: Option<String> },
    RolledBack { active: Option<String> },
}

/// Outcome of [`UpgradeStore::begin_activation`]: the one pre-launch decision
/// an external supervisor acts on. Every variant preserves the existing
/// crash-recovery contract — no variant launches anything by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Activation {
    /// No upgrade transaction is in flight (no journal, or a confirmed one
    /// with a consistent pointer). Run `active`, if any.
    Steady { active: Option<String> },
    /// A `Prepared` candidate has just been activated for its single trial
    /// launch. Run `candidate`; afterwards call [`UpgradeStore::confirm`]
    /// only on a healthy (zero-exit) outcome, [`UpgradeStore::recover`]
    /// otherwise. `previous` is the retained version a rollback restores.
    TrialLaunch {
        candidate: String,
        previous: Option<String>,
    },
    /// A previously `Activated` candidate was never confirmed and has been
    /// rolled back by recovery. Do not auto-retry it; run `active` (the
    /// retained version), if any.
    RolledBack {
        active: Option<String>,
        candidate: String,
    },
    /// The journal was inconsistent (a `Confirmed` record whose active
    /// pointer did not match). Recovery restored `active`; the launch is
    /// refused so an operator can inspect the store instead of the
    /// supervisor silently re-trialling `candidate`.
    Refused {
        active: Option<String>,
        candidate: String,
    },
}

fn validate_version(v: &str) -> Result<()> {
    if v.is_empty()
        || v.len() > 128
        || v == "."
        || v == ".."
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        || v.starts_with('.')
    {
        return Err(UpgradeError::Invalid(
            "version must be a simple safe identifier",
        ));
    }
    Ok(())
}
fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn ensure_child_dir(root: &Path, path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(UpgradeError::Invalid(
            "store child must be a real directory",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            create_private_dir(path)?;
            sync_dir(root)
        }
        Err(e) => Err(e.into()),
    }
}
fn reject_symlink_components(path: &Path) -> Result<()> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(UpgradeError::Invalid("path contains parent traversal"));
            }
            Component::Normal(n) => {
                current.push(n);
                if let Ok(m) = fs::symlink_metadata(&current)
                    && m.file_type().is_symlink()
                {
                    return Err(UpgradeError::Invalid("symlink path component"));
                }
            }
            _ => current.push(c.as_os_str()),
        }
    }
    Ok(())
}
struct CopyBudget {
    bytes: u64,
    entries: usize,
}
fn copy_tree_no_symlinks(
    src: &Path,
    dst: &Path,
    depth: usize,
    budget: &mut CopyBudget,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(UpgradeError::Invalid(
            "artifact directory nesting exceeds limit",
        ));
    }
    create_private_dir(dst)?;
    for entry in fs::read_dir(src)? {
        budget.entries += 1;
        if budget.entries > MAX_TREE_ENTRIES {
            return Err(UpgradeError::Invalid("artifact has too many entries"));
        }
        let e = entry?;
        let ty = e.file_type()?;
        let from = e.path();
        let to = dst.join(e.file_name());
        if ty.is_symlink() {
            return Err(UpgradeError::Invalid("artifact contains symlink"));
        }
        if ty.is_dir() {
            copy_tree_no_symlinks(&from, &to, depth + 1, budget)?;
        } else if ty.is_file() {
            let meta = fs::symlink_metadata(&from)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(UpgradeError::Invalid("artifact contains hard-linked file"));
                }
            }
            if meta.len() > MAX_ARTIFACT_BYTES.saturating_sub(budget.bytes) {
                return Err(UpgradeError::Invalid("artifact exceeds total size limit"));
            }
            let i = File::open(&from)?;
            let mut builder = OpenOptions::new();
            builder.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                let exec = meta.mode() & 0o111 != 0;
                builder.mode(if exec { 0o700 } else { 0o600 });
            }
            let mut o = builder.open(&to)?;
            let remaining = MAX_ARTIFACT_BYTES.saturating_sub(budget.bytes);
            let copied = io::copy(&mut i.take(remaining.saturating_add(1)), &mut o)?;
            if copied > remaining {
                return Err(UpgradeError::Invalid("artifact exceeds total size limit"));
            }
            budget.bytes = budget
                .bytes
                .checked_add(copied)
                .ok_or(UpgradeError::Invalid("artifact size overflow"))?;
            flush_file(&o)?;
        } else {
            return Err(UpgradeError::Invalid("artifact contains special file"));
        }
    }
    sync_dir(dst)
}
fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = fs::DirBuilder::new();
        b.mode(0o700);
        b.create(path)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)?;
    }
    Ok(())
}
fn restrict_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
fn sync_tree(path: &Path) -> Result<()> {
    for e in fs::read_dir(path)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            sync_tree(&e.path())?;
        } else {
            // Open writable: macOS `F_FULLFSYNC` is a flush request on the
            // descriptor, and staged files are always owner-writable here.
            let f = OpenOptions::new().write(true).open(e.path())?;
            flush_file(&f)?;
        }
    }
    sync_dir(path)
}
fn atomic_write(root: &Path, name: &str, data: &[u8]) -> Result<()> {
    let tmp = root.join(format!(".{name}.tmp"));
    // A crash can leave the uncommitted temporary file behind. Under the
    // documented single-writer/trusted-root model it is safe to discard and
    // recreate it; never remove a symlink or non-regular object.
    match fs::symlink_metadata(&tmp) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => {
            fs::remove_file(&tmp)?;
            sync_dir(root)?;
        }
        Ok(_) => {
            return Err(UpgradeError::Invalid(
                "temporary path is not a regular file",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut builder = OpenOptions::new();
    builder.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        builder.mode(0o600);
    }
    let mut f = builder.open(&tmp)?;
    f.write_all(data)?;
    flush_file(&f)?;
    drop(f);
    fs::rename(&tmp, root.join(name))?;
    sync_dir(root)
}

/// Push staged file data to stable storage before the namespace rename.
///
/// Linux and Windows use the standard `fsync`/`FlushFileBuffers` path; macOS
/// asks for `F_FULLFSYNC` so a drive firmware cache is not silently trusted.
/// A failure is returned, never downgraded to a weaker `fsync` that would make
/// the durability claim false.
#[cfg(target_os = "macos")]
fn flush_file(file: &File) -> Result<()> {
    macos::flush_file(file)?;
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn flush_file(file: &File) -> Result<()> {
    file.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_dir(p: &Path) -> Result<()> {
    File::open(p)?.sync_all()?;
    Ok(())
}
#[cfg(target_os = "macos")]
fn sync_dir(p: &Path) -> Result<()> {
    macos::sync_directory(p)?;
    Ok(())
}
#[cfg(windows)]
fn sync_dir(_p: &Path) -> Result<()> {
    Err(UpgradeError::UnsupportedPlatform(
        "Windows directory fsync semantics are not implemented",
    ))
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn sync_dir(_p: &Path) -> Result<()> {
    Err(UpgradeError::UnsupportedPlatform(
        "only Linux and macOS directory fsync is supported",
    ))
}
#[cfg(unix)]
fn same_device(a: &Path, b: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(fs::metadata(a)?.dev() == fs::metadata(b)?.dev())
}
#[cfg(not(unix))]
fn same_device(_a: &Path, _b: &Path) -> Result<bool> {
    Err(UpgradeError::UnsupportedPlatform(
        "same-filesystem identity check is not implemented",
    ))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn directory_fsync_fails_closed_on_windows() {
        let err = sync_dir(Path::new(".")).unwrap_err();
        assert!(matches!(err, UpgradeError::UnsupportedPlatform(_)));
    }
}

/// Transaction-store coverage for the platforms with an integrated backend.
/// macOS runs the same suite as Linux, which is exactly what turns the macOS
/// adapter from an unreviewed draft into a tested backend (namespace ordering,
/// F_FULLFSYNC failure propagation, symlink/hardlink rejection). Windows has
/// no backend, so only `windows_tests` applies there.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let thread = std::thread::current().id();
            let p = std::env::temp_dir().join(format!(
                "boreas-supervisor-test-{}-{}-{:?}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                thread
            ));
            fs::create_dir(&p).unwrap();
            // The store rejects symlinked path components, and macOS keeps
            // `temp_dir()` under `/var` (a symlink to `/private/var`), so the
            // fixture canonicalises before use on every Unix target.
            let p = p.canonicalize().unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn artifact(t: &Temp, name: &str) {
        let p = t.path().join(name);
        fs::create_dir(&p).unwrap();
        fs::write(p.join("boreas"), b"test binary").unwrap();
    }
    fn setup() -> (Temp, UpgradeStore, Temp) {
        let t = Temp::new();
        let root = t.path().join("store");
        fs::create_dir(&root).unwrap();
        let store = UpgradeStore::open(root).unwrap_or_else(|_| {
            panic!("platform must support directory fsync for success-path tests")
        });
        let a = Temp::new();
        artifact(&a, "candidate");
        (t, store, a)
    }

    /// The lock is released explicitly, not merely by closing the descriptor:
    /// on Unix a `fork(2)` child inherits a duplicate of the same open file
    /// description until it execs, and that duplicate would keep the flock
    /// alive after this guard is dropped.
    #[cfg(unix)]
    #[test]
    fn dropping_the_lock_releases_it_even_with_an_inherited_duplicate_fd() {
        let (_t, s, _a) = setup();
        let guard = s.lock_exclusive().expect("first lock");
        // dup(2) shares the open file description exactly as fork(2) does for
        // a child that has not exec'd yet.
        let inherited = guard._file.try_clone().expect("duplicate the lock fd");
        // A live guard still refuses a second owner, even with the duplicate.
        assert!(matches!(s.lock_exclusive(), Err(UpgradeError::Locked(_))));
        drop(guard);
        // The duplicate is still open, so this only succeeds if Drop released
        // the shared flock explicitly.
        let relocked = s
            .lock_exclusive()
            .expect("dropping the guard must release the shared lock");
        // The new guard is real and keeps refusing a second owner.
        assert!(matches!(s.lock_exclusive(), Err(UpgradeError::Locked(_))));
        drop(relocked);
        drop(inherited);
    }

    #[test]
    fn first_install_prepare_activate_crash_rolls_back_to_empty() {
        let (_t, s, a) = setup();
        s.prepare(
            &Candidate {
                version: "1.0.0".into(),
            },
            a.path().join("candidate"),
        )
        .unwrap();
        s.activate().unwrap();
        assert_eq!(s.active_version().unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(s.recover().unwrap(), Recovery::RolledBack { active: None });
        assert_eq!(s.active_version().unwrap(), None);
    }
    #[test]
    fn confirmed_upgrade_preserves_old_version_and_active_new() {
        let (_t, s, a) = setup();
        let old = s.versions.join("1.0.0");
        fs::create_dir(&old).unwrap();
        s.write_active(Some("1.0.0")).unwrap();
        s.prepare(
            &Candidate {
                version: "2.0.0".into(),
            },
            a.path().join("candidate"),
        )
        .unwrap();
        s.activate().unwrap();
        s.confirm().unwrap();
        assert!(old.is_dir());
        assert_eq!(s.active_version().unwrap().as_deref(), Some("2.0.0"));
        assert_eq!(
            s.recover().unwrap(),
            Recovery::Confirmed {
                active: Some("2.0.0".into())
            }
        );
    }
    #[test]
    fn crash_after_pointer_rename_before_journal_activated_still_rolls_back() {
        let (_t, s, a) = setup();
        let old = s.versions.join("1.0.0");
        fs::create_dir(&old).unwrap();
        s.write_active(Some("1.0.0")).unwrap();
        s.prepare(
            &Candidate {
                version: "2.0.0".into(),
            },
            a.path().join("candidate"),
        )
        .unwrap();
        s.write_active(Some("2.0.0")).unwrap();
        assert_eq!(
            s.recover().unwrap(),
            Recovery::RolledBack {
                active: Some("1.0.0".into())
            }
        );
    }
    #[test]
    fn unsafe_version_and_symlink_artifact_rejected() {
        let (_t, s, a) = setup();
        assert!(
            s.prepare(
                &Candidate {
                    version: "../oops".into()
                },
                a.path().join("candidate")
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = a.path().join("link");
            symlink(a.path().join("candidate"), &link).unwrap();
            assert!(
                s.prepare(
                    &Candidate {
                        version: "1.0.0".into()
                    },
                    &link
                )
                .is_err()
            );
        }
    }
    #[test]
    fn journal_parser_rejects_traversal() {
        let (_t, s, _a) = setup();
        fs::write(
            s.root.join(JOURNAL_FILE),
            format!("{FORMAT}\n-\n../evil\nPrepared\n"),
        )
        .unwrap();
        assert!(matches!(s.journal(), Err(UpgradeError::CorruptJournal)));
    }
    #[test]
    fn journal_rejects_same_old_and_new_and_oversized_files() {
        let (_t, s, _a) = setup();
        fs::write(
            s.root.join(JOURNAL_FILE),
            format!("{FORMAT}\n1.0.0\n1.0.0\nPrepared\n"),
        )
        .unwrap();
        assert!(matches!(s.journal(), Err(UpgradeError::CorruptJournal)));
        fs::write(
            s.root.join(JOURNAL_FILE),
            vec![b'x'; MAX_JOURNAL_BYTES as usize + 1],
        )
        .unwrap();
        assert!(matches!(s.journal(), Err(UpgradeError::CorruptJournal)));
    }
    #[test]
    fn inconsistent_confirmed_journal_rolls_back_instead_of_claiming_success() {
        let (_t, s, _a) = setup();
        fs::create_dir(s.versions.join("1.0.0")).unwrap();
        s.write_journal(&Journal {
            old_version: None,
            new_version: "1.0.0".into(),
            phase: Phase::Confirmed,
        })
        .unwrap();
        assert_eq!(s.recover().unwrap(), Recovery::RolledBack { active: None });
        assert_eq!(s.journal().unwrap().unwrap().phase, Phase::Prepared);
    }
    #[test]
    fn copied_binary_retains_executable_bit_and_private_mode() {
        let (_t, s, a) = setup();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                a.path().join("candidate/boreas"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        s.prepare(
            &Candidate {
                version: "1.0.0".into(),
            },
            a.path().join("candidate"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(s.versions.join("1.0.0/boreas"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
    #[test]
    fn active_pointer_rejects_oversized_content() {
        let (_t, s, _a) = setup();
        fs::write(
            s.root.join(ACTIVE_FILE),
            vec![b'x'; MAX_ACTIVE_BYTES as usize + 1],
        )
        .unwrap();
        assert!(s.active_version().is_err());
    }
    #[test]
    fn artifact_size_limit_enforced_and_partial_stage_cleaned() {
        let (_t, s, a) = setup();
        let big = a.path().join("candidate/too-large");
        let f = File::create(&big).unwrap();
        f.set_len(MAX_ARTIFACT_BYTES + 1).unwrap();
        let result = s.prepare(
            &Candidate {
                version: "1.0.0".into(),
            },
            a.path().join("candidate"),
        );
        assert!(result.is_err());
        assert!(!s.staging.join("1.0.0.tmp").exists());
    }
    fn with_old_active(s: &UpgradeStore) {
        fs::create_dir(s.versions.join("1.0.0")).unwrap();
        s.write_active(Some("1.0.0")).unwrap();
    }
    #[test]
    fn begin_activation_empty_store_is_steady_without_active() {
        let (_t, s, _a) = setup();
        assert_eq!(
            s.begin_activation().unwrap(),
            Activation::Steady { active: None }
        );
        assert_eq!(s.journal().unwrap(), None);
    }
    #[test]
    fn begin_activation_without_journal_keeps_current_active() {
        let (_t, s, _a) = setup();
        with_old_active(&s);
        assert_eq!(
            s.begin_activation().unwrap(),
            Activation::Steady {
                active: Some("1.0.0".into())
            }
        );
        assert_eq!(s.active_version().unwrap().as_deref(), Some("1.0.0"));
    }
    #[test]
    fn begin_activation_prepared_candidate_gets_one_trial() {
        let (_t, s, a) = setup();
        with_old_active(&s);
        s.prepare(
            &Candidate {
                version: "2.0.0".into(),
            },
            a.path().join("candidate"),
        )
        .unwrap();
        assert_eq!(
            s.begin_activation().unwrap(),
            Activation::TrialLaunch {
                candidate: "2.0.0".into(),
                previous: Some("1.0.0".into()),
            }
        );
        assert_eq!(s.active_version().unwrap().as_deref(), Some("2.0.0"));
        assert_eq!(s.journal().unwrap().unwrap().phase, Phase::Activated);
    }
    #[test]
    fn begin_activation_unconfirmed_candidate_rolls_back_instead_of_retrying() {
        let (_t, s, a) = setup();
        with_old_active(&s);
        s.prepare(
            &Candidate {
                version: "2.0.0".into(),
            },
            a.path().join("candidate"),
        )
        .unwrap();
        // First boot consumes the trial; the process "crashes" (no
        // confirm/recover). The next boot must roll back, not retrial.
        assert!(matches!(
            s.begin_activation().unwrap(),
            Activation::TrialLaunch { .. }
        ));
        assert_eq!(
            s.begin_activation().unwrap(),
            Activation::RolledBack {
                active: Some("1.0.0".into()),
                candidate: "2.0.0".into(),
            }
        );
        assert_eq!(s.active_version().unwrap().as_deref(), Some("1.0.0"));
    }
    #[test]
    fn begin_activation_inconsistent_confirmed_journal_is_refused() {
        let (_t, s, _a) = setup();
        fs::create_dir(s.versions.join("1.0.0")).unwrap();
        s.write_journal(&Journal {
            old_version: None,
            new_version: "1.0.0".into(),
            phase: Phase::Confirmed,
        })
        .unwrap();
        assert_eq!(
            s.begin_activation().unwrap(),
            Activation::Refused {
                active: None,
                candidate: "1.0.0".into(),
            }
        );
        assert_eq!(s.journal().unwrap().unwrap().phase, Phase::Prepared);
    }
    #[test]
    fn recorded_active_version_reports_dangling_pointer_but_launch_read_fails() {
        let (_t, s, _a) = setup();
        fs::write(s.root.join(ACTIVE_FILE), "9.9.9\n").unwrap();
        assert_eq!(
            s.recorded_active_version().unwrap().as_deref(),
            Some("9.9.9")
        );
        assert!(s.active_version().is_err());
    }
    #[test]
    fn version_dir_and_stored_count_reflect_retained_versions() {
        let (_t, s, a) = setup();
        assert!(s.version_dir("../nope").is_err());
        assert_eq!(s.stored_version_count().unwrap(), 0);
        with_old_active(&s);
        s.prepare(
            &Candidate {
                version: "2.0.0".into(),
            },
            a.path().join("candidate"),
        )
        .unwrap();
        assert_eq!(s.stored_version_count().unwrap(), 2);
        assert_eq!(s.version_dir("2.0.0").unwrap(), s.versions.join("2.0.0"));
    }
    #[cfg(unix)]
    #[test]
    fn hardlinked_artifact_file_rejected() {
        let (_t, s, a) = setup();
        fs::hard_link(
            a.path().join("candidate/boreas"),
            a.path().join("candidate/alias"),
        )
        .unwrap();
        assert!(
            s.prepare(
                &Candidate {
                    version: "1.0.0".into()
                },
                a.path().join("candidate")
            )
            .is_err()
        );
    }
}
