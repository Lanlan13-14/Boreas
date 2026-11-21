//! Durable signed-status freshness store with a bounded, **test-only model** of
//! revocation entries.
//!
//! This module persists the exact signed `StatusSnapshot` envelope plus its
//! verified freshness metadata, a monotonic trusted-UTC floor and a rollback latch.
//! A candidate v1 revocation payload may travel in the same envelope, but it is a
//! model, not an enabled runtime:
//!
//! - Production [`StatusStore::open`] authorizes **no** revocation class. A
//!   snapshot whose `revocations` byte string is non-empty is refused with
//!   [`Error::RevocationPermission`] before the trusted verifier records replay
//!   state. A `StatusSnapshot` is signed only by the network `StatusSigner`;
//!   that signature is **not** evidence that the `IdentityAuthority`,
//!   `NetworkRoot`, `RouteAuthority` or a Core's `CoreOperationalKey` issued an
//!   entry (§3.4).
//! - The accepting entry point is compiled only for Linux unit tests.
//!   `RevocationRelayPolicy` exposes no constructor that enables a class; its
//!   fields are private, so a non-`none` policy can only be built inside this
//!   crate's test modules. None of this is deployment configuration, daemon
//!   enablement or a production trust input.
//! - `Direct` is refused by the schema and by [`crate::revoke_cleanup`]: the
//!   subject's home Core is not the issuer of its `DirectGrant`, and a roaming Core
//!   may sign a grant for the same subject.
//! - Revocation state is **in-memory only**. The state image keeps the
//!   pre-feature `BRSS\0\0\0\x01` format: no new flag and no revocation block, so
//!   an older decoder cannot silently misread a new image. On open, revocation
//!   state is rebuilt only from the persisted signed snapshot's exact TBS and is
//!   re-verified with that envelope. Decisions contributed by earlier payloads are
//!   not persisted, are not re-verified and are not claimed as `Verified`; after a
//!   restart they are absent. A same-scope conflict latch is likewise process-local.
//! - [`StatusStore::peer_revocation`] answers a model query about an already
//!   authenticated peer. It is not wired into the daemon and this slice does not
//!   claim the `G-REVOKE` gate.
//! - This slice does not close sockets, remove kernel routes or verify a live
//!   handle. [`crate::revoke_cleanup`] applies class-limited drops to an in-memory
//!   id registry only.
//!
//! Independent IdentityAuthority objects use a separate, Linux-only v2 image
//! extension. The legacy status-relay behavior above is unchanged.
//!
//! Linux is the only durable target in this slice. Other targets expose the
//! same API but every operation fails closed with [`Error::Unsupported`].
//!
//! Trust boundary:
//! - [`StatusStore::open`] takes ownership of a [`ManagementTrust`]. The store
//!   never accepts a caller boolean, a timestamp-only "verified" value or an
//!   arbitrary pluggable verifier.
//! - [`StatusStore::accept_signed_snapshot`] passes the exact raw envelope to
//!   `ManagementTrust::verify_and_authorize`, which verifies the issuer
//!   authority, both Ed25519 and ML-DSA signatures over the original TBS bytes,
//!   network binding, issuer generation, object type and signed validity window
//!   before it can return `Equivocation`. The store then persists exact bytes
//!   and watermarks atomically before returning success.
//! - The `ManagementTrust` replay table is process-local and advances during
//!   verification. If persistence fails after that point, the whole store is
//!   poisoned; it is never used again for business decisions.
//!
//! Freshness:
//! - Snapshot lifetime ends at the earlier of signed `next_update` and any
//!   verified issuer delegation expiry. Receiving the same snapshot never renews it.
//! - A persisted snapshot is cryptographically re-verified at its own signed
//!   `issued_at` boundary on restart; that only authenticates stored bytes and
//!   never grants current freshness.
//! - [`StatusStore::current_fresh`] takes trusted UTC and re-derives the
//!   remaining signed lifetime, taking the minimum with an in-process
//!   `Instant` deadline. A restart therefore does not require a new snapshot
//!   while both the snapshot and its issuer delegation are still current.
//! - [`FreshStatus::check`] is a read-only business check. It cannot persist a
//!   rollback latch; after it rejects for clock rollback the owner must drop the
//!   token and call [`StatusStore::observe_trusted_utc`] (or
//!   `recover_trusted_utc` after an independently trusted recovery decision) so
//!   the latch is durable.
//! - The token borrows the store, while `accept_signed_snapshot` and
//!   `current_fresh` require `&mut self`. A new snapshot therefore cannot be
//!   accepted while a token is alive; the token is not a concurrently updated
//!   handle that "auto-invalidates". `check` still rechecks state defensively at
//!   each use.
//!
//! Honest boundary: the API cannot tell whether the caller's UTC really came
//! from a trusted time source. The caller must provide it from an independent
//! trusted boundary. Without an external monotonic anchor, restoring an older
//! whole-disk image (including the floor and latch) cannot be detected here.
#![cfg(feature = "openssl-backend")]

use std::{
    fmt, io,
    path::Path,
    time::{Duration, Instant},
};

use boreas_proto::{
    messages::SignedObject,
    objects::{self, ObjectBody, ObjectType, SubjectIdentity},
    revocation::{self, IssuerClass, RevocationEntry, RevocationPayload},
};
use openssl::hash::{MessageDigest, hash};

#[cfg(target_os = "linux")]
mod identity;
#[cfg(target_os = "linux")]
pub use identity::{IDENTITY_REVOCATION_MAGIC, MAX_IDENTITY_REVOCATION_BYTES};
#[cfg(target_os = "linux")]
use crate::authority_revocation::AuthorityRevocationTrust;

use crate::{
    CLOCK_ROLLBACK_TOLERANCE_US, PolicyError, STATUS_MAX_AGE_US, SnapshotResult,
    management::{self, MAX_SIGNED_OBJECT_BYTES, ManagementTrust, VerifiedObject},
    revoke_cleanup::VerifiedRevocationScope,
};

#[cfg(target_os = "linux")]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, PathBuf},
};

#[cfg(target_os = "linux")]
const MAGIC: &[u8; 8] = b"BRSS\0\0\0\x01";
#[cfg(target_os = "linux")]
const IDENTITY_MAGIC: &[u8; 8] = b"BRSS\0\0\0\x02";
#[cfg(target_os = "linux")]
const MAX_STATE_WITH_IDENTITY_BYTES: usize = MAX_STATUS_STATE_BYTES + identity::MAX_EXTENSION_BYTES;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const LINUX_O_NOFOLLOW: i32 = 0o100_000;
#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
const LINUX_O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_os = "linux")]
const LINUX_O_NONBLOCK: i32 = 0x800;
#[cfg(target_os = "linux")]
const LINUX_O_CLOEXEC: i32 = 0x80000;

#[cfg(target_os = "linux")]
struct ExclusiveLock(File);

#[cfg(target_os = "linux")]
impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

const MAX_ISSUER_ID_BYTES: usize = 64;
/// Maximum encoded state image accepted by the Linux store.
pub const MAX_STATUS_STATE_BYTES: usize = 64 * 1024;
/// Maximum number of distinct revoked scopes retained in the in-memory model.
///
/// This is also the schema's per-payload entry bound, so a single snapshot can
/// always be merged into an empty store. A store that already holds this many
/// scopes refuses a payload that would add another one. Nothing here is persisted:
/// after restart only the latest persisted snapshot's payload is rebuilt.
pub const MAX_REVOCATION_SCOPES: usize = 64;

#[cfg(target_os = "linux")]
const FLAG_ROLLBACK_LATCHED: u8 = 1 << 0;
#[cfg(target_os = "linux")]
const FLAG_HAS_SNAPSHOT: u8 = 1 << 1;
#[cfg(target_os = "linux")]
const FLAG_HAS_EQUIVOCATION: u8 = 1 << 2;
#[cfg(target_os = "linux")]
const KNOWN_FLAGS: u8 = FLAG_ROLLBACK_LATCHED | FLAG_HAS_SNAPSHOT | FLAG_HAS_EQUIVOCATION;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Unsupported,
    UnsafePath,
    Busy,
    TooLarge,
    Corrupt,
    WrongNetwork,
    BadStatus,
    Policy(PolicyError),
    Poisoned,
    Frozen,
    ClockRollback,
    NotFresh,
    /// A revocation entry is refused by the current policy, its class/scope rules,
    /// or the fact that no per-authority issuer evidence exists.
    RevocationPermission,
    /// A revocation entry's `epoch` is below the in-memory watermark for its scope.
    RevocationStale,
    /// Two verified decisions claim one scope at one epoch; permanently latched.
    RevocationConflict,
    /// The bounded revocation state or payload bound was exceeded.
    RevocationTooLarge,
    /// A fresh independent authority object did not verify.
    #[cfg(target_os = "linux")]
    AuthorityRevocation(crate::authority_revocation::Error),
    /// A different TBS claims the same identity-scope sequence. The prior denial remains.
    #[cfg(target_os = "linux")]
    IdentityRevocationConflict,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Snapshot {
    issuer: Vec<u8>,
    generation: u64,
    seq: u64,
    object_id: [u8; 32],
    issued: u64,
    next: u64,
    raw: Vec<u8>,
}

/// One in-memory revoked scope, keyed by `(class, origin_core, node_id, generation)`.
#[derive(Clone, Copy, Eq, PartialEq)]
struct RevokedScope {
    class: IssuerClass,
    origin_core: u8,
    node_id: u16,
    generation: u64,
    target_id: u64,
    epoch: u64,
    /// SHA-256 of the canonical entry bytes that produced this decision.
    digest: [u8; 32],
}
impl RevokedScope {
    fn key(&self) -> (u64, u8, u16, u64) {
        (
            self.class.code(),
            self.origin_core,
            self.node_id,
            self.generation,
        )
    }

    fn scope(&self) -> VerifiedRevocationScope {
        VerifiedRevocationScope {
            class: self.class,
            origin_core: self.origin_core,
            node_id: self.node_id,
            generation: self.generation,
            target_id: self.target_id,
            epoch: self.epoch,
        }
    }
}

/// In-memory evidence that one scope and epoch carried two different decisions.
#[derive(Clone, Copy, Eq, PartialEq)]
struct RevocationConflictRecord {
    /// The first decision, which stays in force.
    scope: RevokedScope,
    second_digest: [u8; 32],
}

/// In-memory revocation model state.
///
/// `scopes` only grows during one process lifetime: a decision is never withdrawn
/// by a later payload, which is what makes an omission unable to un-revoke a
/// subject in that process. Nothing here is persisted. Ordering is the schema's
/// scope-key ordering so lookups are a binary search and the in-memory image is
/// canonical.
#[derive(Clone, Default, Eq, PartialEq)]
struct RevocationState {
    scopes: Vec<RevokedScope>,
    conflict: Option<RevocationConflictRecord>,
}

impl RevocationState {
    fn position(&self, key: (u64, u8, u16, u64)) -> Result<usize, usize> {
        self.scopes.binary_search_by(|scope| scope.key().cmp(&key))
    }

    fn scope(&self, key: (u64, u8, u16, u64)) -> Option<&RevokedScope> {
        self.position(key).ok().map(|index| &self.scopes[index])
    }

    fn insert(&mut self, scope: RevokedScope) -> Result<(), Error> {
        match self.position(scope.key()) {
            Ok(_) => Err(Error::Corrupt),
            Err(index) => {
                if self.scopes.len() >= MAX_REVOCATION_SCOPES {
                    return Err(Error::RevocationTooLarge);
                }
                self.scopes.insert(index, scope);
                Ok(())
            }
        }
    }

    fn supersede(&mut self, scope: RevokedScope) -> Result<(), Error> {
        match self.position(scope.key()) {
            Ok(index) => {
                self.scopes[index] = scope;
                Ok(())
            }
            Err(_) => Err(Error::Corrupt),
        }
    }
}

/// One planned mutation from a verified payload.
enum RevocationChange {
    Insert(RevokedScope),
    Supersede(RevokedScope),
}

#[derive(Clone, Eq, PartialEq)]
struct State {
    net: [u8; 16],
    utc_floor: u64,
    rollback_latched: bool,
    snapshot: Option<Snapshot>,
    /// The second exact signed envelope of a same-sequence conflict.
    equivocation: Option<Vec<u8>>,
    revocation: RevocationState,
    #[cfg(target_os = "linux")]
    identity: Option<identity::Decisions>,
}
#[cfg(target_os = "linux")]
impl State {
    fn empty(net: [u8; 16]) -> Self {
        Self {
            net,
            utc_floor: 0,
            rollback_latched: false,
            snapshot: None,
            equivocation: None,
            revocation: RevocationState::default(),
            identity: None,
        }
    }
}

/// Test-only model of which revocation classes a harness may feed to the store.
///
/// Authority separation in §3.4 assigns identity revocation to the
/// `IdentityAuthority`, Core revocation to the `NetworkRoot`, route revocation to
/// the `RouteAuthority` and direct-grant revocation to a `CoreOperationalKey` of
/// that Core. A `StatusSnapshot` envelope is signed only by the network's
/// `StatusSigner` and `ObjectKind::StatusSnapshot` is the single object kind that
/// authority may issue, so the envelope itself proves nothing about the other four
/// authorities. A Core's ability to sign its own `CoreLsa` is explicitly **not**
/// treated as authority to revoke anything.
///
/// This type is model plumbing, not deployment configuration:
/// - [`Self::none`] is the only production value; [`StatusStore::open`] uses it and
///   refuses every non-empty revocation payload.
/// - There is no constructor that enables a class. The fields are private, so
///   production code cannot build a non-`none` value at all; test code constructs
///   the struct inside this crate's test modules only. No enabling constructor is
///   part of the public API, and none may be presented as a trust input or daemon
///   configuration.
/// - Even in tests, the schema rejects `Direct`, and the class/scope rules are only
///   structural. Nothing here proves that the `IdentityAuthority`, `NetworkRoot`,
///   `RouteAuthority` or a Core key signed an entry.
///
/// Unifying this with per-authority revocation objects is an open protocol question
/// recorded in `docs/protocol/revocations-v1.md`; the safe production value is
/// "none".
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RevocationRelayPolicy {
    identity: bool,
    core: bool,
    route: bool,
}
impl RevocationRelayPolicy {
    /// Refuse every revocation class. This is the only production value.
    pub const fn none() -> Self {
        Self {
            identity: false,
            core: false,
            route: false,
        }
    }

    /// Whether this policy authorizes relaying `class`.
    ///
    /// `Direct` is always `false`: the schema refuses it before policy code, and
    /// the subject's home Core is not the grant issuer.
    pub const fn allows(&self, class: IssuerClass) -> bool {
        match class {
            IssuerClass::Identity => self.identity,
            IssuerClass::Core => self.core,
            IssuerClass::Route => self.route,
            IssuerClass::Direct => false,
        }
    }

    /// `true` when no class is authorized.
    pub const fn is_none(&self) -> bool {
        !self.identity && !self.core && !self.route
    }
}

/// Facts about a peer that the TLS/PKI layer already authenticated.
///
/// The daemon must fill this from the verified certificate chain and never from a
/// peer-supplied message. Revocation is scoped by network, node slot and identity
/// generation only, so no role, prefix or session handle is part of the query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    net_id: [u8; 16],
    node_id: u16,
    identity_generation: u64,
}
impl AuthenticatedPeer {
    /// `None` unless the node id is a permanent overlay slot and the generation is
    /// non-zero, so a malformed caller value cannot silently match nothing.
    pub fn new(net_id: [u8; 16], node_id: u16, identity_generation: u64) -> Option<Self> {
        if !valid_peer_node_id(node_id) || identity_generation == 0 {
            return None;
        }
        Some(Self {
            net_id,
            node_id,
            identity_generation,
        })
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    pub fn node_id(&self) -> u16 {
        self.node_id
    }

    pub fn identity_generation(&self) -> u64 {
        self.identity_generation
    }
}

/// Verified revocation state that covers one authenticated peer.
///
/// Each class is reported separately on purpose: a route-only or direct-only
/// decision is not a claim that the peer's sessions were cleared, and one
/// identity decision is not a claim that every route of the peer was removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerRevocationState {
    /// Sequence of the verified snapshot that produced this answer.
    pub sequence: u64,
    /// An authority-issued identity decision covers this node and generation.
    pub identity: bool,
    /// A decision from this node's own home Core covers it.
    pub core: bool,
    /// An authority-issued route decision covers this node and generation.
    pub route: bool,
    /// Always `false` in v1: `Direct` entries are refused because the subject's
    /// home Core is not the grant issuer. The field is kept for the query shape.
    pub direct: bool,
}
impl PeerRevocationState {
    /// `true` when a verified decision covers the peer's sessions, circuits or
    /// attachment leases. This is the admission-relevant answer.
    pub const fn sessions_revoked(&self) -> bool {
        self.identity || self.core
    }

    /// `true` when any category is covered.
    pub const fn any(&self) -> bool {
        self.identity || self.core || self.route || self.direct
    }
}

/// Why a revocation question cannot be answered from the verified model state.
///
/// Every variant is a fail-closed answer: the daemon must not treat it as
/// "not revoked".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationUnknown {
    /// No signed snapshot has been accepted yet.
    NoSnapshot,
    /// The peer belongs to a different network than this store.
    WrongNetwork,
    /// The store is frozen on snapshot or revocation equivocation evidence.
    Frozen,
    /// A durable commit failed; the store must be reopened.
    Poisoned,
    /// The trusted-UTC rollback latch is set.
    ClockLatched,
}

/// Answer to "what does the verified revocation model say about this peer?".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRevocation {
    /// The model's verified state covers this exact node and generation.
    ///
    /// The verification is of the enclosing snapshot; the entry is not a
    /// per-authority signature and the state is not durable across restart.
    Verified(PeerRevocationState),
    /// Fail closed; the caller must not admit or keep business traffic.
    Unknown(RevocationUnknown),
}

/// In-memory revocation equivocation evidence: one scope, one epoch, two decisions.
///
/// This is model evidence, not a durable record: only digests are kept and the
/// revocation model does not persist a state block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationConflict {
    /// The first decision, which stays in force.
    pub scope: VerifiedRevocationScope,
    /// SHA-256 of the canonical bytes of the first decision.
    pub first_digest: [u8; 32],
    /// SHA-256 of the canonical bytes of the conflicting decision.
    pub second_digest: [u8; 32],
}

/// Exclusive, network-bound durable freshness store.
///
/// The store owns the stateful verifier because its process-local replay table
/// cannot be rolled back after a failed durable commit. Destroy/reopen after a
/// [`Error::Poisoned`] result.
pub struct StatusStore {
    #[cfg(target_os = "linux")]
    path: PathBuf,
    #[cfg(target_os = "linux")]
    _lock: ExclusiveLock,
    #[cfg(target_os = "linux")]
    owner: u32,
    #[cfg(target_os = "linux")]
    identity_trust: Option<([u8; 32], AuthorityRevocationTrust)>,
    net: [u8; 16],
    trust: ManagementTrust,
    revocation_relay: RevocationRelayPolicy,
    state: State,
    poisoned: bool,
    /// The authenticated snapshot cutoff, recomputed on open rather than read from disk.
    snapshot_valid_until: Option<u64>,
    runtime_deadline: Option<Instant>,
    #[cfg(all(test, target_os = "linux"))]
    fail_next_commit: bool,
}
impl fmt::Debug for StatusStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusStore")
            .field("net_id", &self.net)
            .field("has_snapshot", &self.state.snapshot.is_some())
            .field(
                "sequence",
                &self.state.snapshot.as_ref().map(|snapshot| snapshot.seq),
            )
            .field("poisoned", &self.poisoned)
            .field("clock_latched", &self.state.rollback_latched)
            .field("frozen", &self.is_frozen())
            .field("revoked_scopes", &self.state.revocation.scopes.len())
            .finish()
    }
}

impl StatusStore {
    /// Open a Linux-durable store with every revocation class refused.
    ///
    /// `path` must be absolute. Its canonical parent must be owned by
    /// `trusted_owner_uid` with no group/other permissions; `trusted_owner_uid`
    /// is an independent deployment input and this API never discovers the
    /// process effective UID. `trust` must belong to `net_id` and is owned by
    /// the store for its lifetime.
    ///
    /// Production always uses [`RevocationRelayPolicy::none`]. A snapshot carrying
    /// revocation entries is refused with [`Error::RevocationPermission`] before
    /// verification/replay mutation instead of being consumed. There is no
    /// production constructor for a policy that enables a class; the accepting
    /// helper is `#[cfg(test)]` only.
    ///
    /// On non-Linux this returns [`Error::Unsupported`] without touching the
    /// filesystem.
    pub fn open(
        path: impl AsRef<Path>,
        net_id: [u8; 16],
        trusted_owner_uid: u32,
        trust: ManagementTrust,
    ) -> Result<Self, Error> {
        Self::open_inner(
            path,
            net_id,
            trusted_owner_uid,
            trust,
            RevocationRelayPolicy::none(),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    /// Open with independent IdentityAuthority trust. The caller must bind both
    /// verifiers to the exact same verified NetworkRoot before calling this API.
    /// This does not authorize any entries carried inside a status snapshot.
    #[cfg(target_os = "linux")]
    pub fn open_with_identity_revocations(
        path: impl AsRef<Path>,
        net_id: [u8; 16],
        trusted_owner_uid: u32,
        trust: ManagementTrust,
        root_fingerprint: [u8; 32],
        identity_trust: AuthorityRevocationTrust,
    ) -> Result<Self, Error> {
        if identity_trust.net_id() != net_id {
            return Err(Error::WrongNetwork);
        }
        Self::open_inner(
            path,
            net_id,
            trusted_owner_uid,
            trust,
            RevocationRelayPolicy::none(),
            Some((root_fingerprint, identity_trust)),
        )
    }

    /// Test-only accepting model with an explicit relay policy.
    ///
    /// This is not a production entry point and not deployment configuration. It
    /// exists only for Linux unit tests so they can exercise the bounded schema and
    /// merge logic. The `StatusSigner` is not the `IdentityAuthority`,
    /// `NetworkRoot`, `RouteAuthority` or a Core key, so a policy built here is not
    /// authority evidence. Production code can only call [`StatusStore::open`],
    /// which always uses [`RevocationRelayPolicy::none`].
    #[cfg(all(test, target_os = "linux"))]
    fn open_with_revocation_relay(
        path: impl AsRef<Path>,
        net_id: [u8; 16],
        trusted_owner_uid: u32,
        trust: ManagementTrust,
        revocation_relay: RevocationRelayPolicy,
    ) -> Result<Self, Error> {
        Self::open_inner(path, net_id, trusted_owner_uid, trust, revocation_relay, None)
    }

    fn open_inner(
        path: impl AsRef<Path>,
        net_id: [u8; 16],
        trusted_owner_uid: u32,
        trust: ManagementTrust,
        revocation_relay: RevocationRelayPolicy,
        #[cfg(target_os = "linux")]
        identity_trust: Option<([u8; 32], AuthorityRevocationTrust)>,
    ) -> Result<Self, Error> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, net_id, trusted_owner_uid, trust, revocation_relay);
            return Err(Error::Unsupported);
        }
        #[cfg(target_os = "linux")]
        {
            if trust.net_id() != net_id {
                return Err(Error::WrongNetwork);
            }
            let path = checked_path(path.as_ref(), trusted_owner_uid)?;
            let lock_path = suffix(&path, ".lock");
            let staging_path = suffix(&path, ".staging");
            reject_staging(&staging_path)?;
            reject_symlink_or_nonfile(&lock_path)?;
            let lock = open_private(&lock_path, true)?;
            validate_file(&lock_path, &lock, trusted_owner_uid)?;
            match lock.try_lock() {
                Ok(()) => (),
                Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Busy),
                Err(std::fs::TryLockError::Error(error)) => return Err(Error::Io(error)),
            }
            let lock = ExclusiveLock(lock);
            File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
            let mut store = Self {
                path,
                _lock: lock,
                owner: trusted_owner_uid,
                identity_trust,
                net: net_id,
                trust,
                revocation_relay,
                state: State::empty(net_id),
                poisoned: false,
                snapshot_valid_until: None,
                runtime_deadline: None,
                #[cfg(all(test, target_os = "linux"))]
                fail_next_commit: false,
            };
            let state = store.read_state()?;
            store.state = state;
            if store.state.net != net_id {
                return Err(Error::WrongNetwork);
            }
            store.verify_loaded()?;
            if let Some(decisions) = &store.state.identity {
                let (root, trust) = store.identity_trust.as_ref().ok_or(Error::RevocationPermission)?;
                decisions.verify_loaded(*root, trust)?;
            }
            Ok(store)
        }
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net
    }

    /// Compare configured authorities, including delegation validity, without
    /// exposing or comparing verifier replay state.
    pub fn has_same_authorities(&self, expected: &ManagementTrust) -> bool {
        self.trust.same_issuers(expected)
    }

    pub fn sequence(&self) -> Option<u64> {
        self.state.snapshot.as_ref().map(|snapshot| snapshot.seq)
    }

    pub fn last_trusted_utc(&self) -> u64 {
        self.state.utc_floor
    }

    /// Recheck a process-local, already-armed snapshot's clock cutoffs without
    /// refreshing it or advancing its durable floor. The caller must persist
    /// a rollback latch via `observe_trusted_utc` if this reports rollback.
    pub fn check_active_snapshot(&self, observed: u64, mono_now: Instant) -> Result<(), Error> {
        let seq = self.sequence().ok_or(Error::NotFresh)?;
        let deadline = self.runtime_deadline.ok_or(Error::NotFresh)?;
        FreshStatus {
            store: self,
            seq,
            deadline,
        }
        .check(observed, mono_now)
    }

    pub fn is_clock_latched(&self) -> bool {
        self.state.rollback_latched
    }

    /// A same-sequence snapshot equivocation is persisted and latched until an
    /// operator handles the evidence. A same-scope revocation conflict is latched
    /// only in memory: the revocation model does not persist a conflict block.
    /// Neither is cleared by clock recovery.
    pub fn is_frozen(&self) -> bool {
        self.state.equivocation.is_some() || self.state.revocation.conflict.is_some()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// `(persisted primary raw envelope, conflicting raw envelope)`.
    ///
    /// The primary envelope comes from this store's own persisted snapshot, not
    /// from `ManagementTrust`'s single overwritten `conflict_evidence` slot.
    pub fn equivocation_evidence(&self) -> Option<(&[u8], &[u8])> {
        let snapshot = self.state.snapshot.as_ref()?;
        let second = self.state.equivocation.as_ref()?;
        Some((snapshot.raw.as_slice(), second.as_slice()))
    }

    /// `true` when a same-scope, same-epoch revocation conflict is latched in this
    /// process. The latch is not persisted.
    pub fn is_revocation_conflicted(&self) -> bool {
        self.state.revocation.conflict.is_some()
    }

    /// In-memory revocation equivocation evidence, if latched.
    ///
    /// Only the two entry digests are retained. Because the revocation model does
    /// not persist either signed payload, this is not durable evidence and is not
    /// re-verified after restart.
    pub fn revocation_conflict(&self) -> Option<RevocationConflict> {
        let conflict = self.state.revocation.conflict.as_ref()?;
        Some(RevocationConflict {
            scope: conflict.scope.scope(),
            first_digest: conflict.scope.digest,
            second_digest: conflict.second_digest,
        })
    }

    /// Number of distinct revoked scopes in this process's model state.
    pub fn revoked_scope_count(&self) -> usize {
        self.state.revocation.scopes.len()
    }

    /// Bounded copy of the model's revocation scopes, in schema order.
    ///
    /// These are identifiers, not live sockets or installed routes. The list is not
    /// durable: after restart it contains only entries rebuilt from the persisted
    /// signed snapshot. An entry contributed by an earlier payload is neither
    /// present nor claimed verified.
    pub fn revocation_scopes(&self) -> Vec<VerifiedRevocationScope> {
        self.state
            .revocation
            .scopes
            .iter()
            .map(|scope| scope.scope())
            .collect()
    }

    /// What the model's verified revocation state says about an authenticated peer.
    ///
    /// Read-only and clock-free. A `Verified` answer means this process accepted an
    /// entry in a dual-signature-verified snapshot, or rebuilt it from the persisted
    /// signed snapshot at open. It does not mean the entry carries its own
    /// authority signature, and it does not cover decisions from earlier payloads
    /// that were not persisted. A `Verified` answer that is *not* revoked is only as
    /// good as the freshness of the snapshot, so a business admission must also hold
    /// a live [`FreshStatus`] (its `check` covers freshness) obtained from the same
    /// boundary. Every [`PeerRevocation::Unknown`] reason is fail-closed.
    pub fn peer_revocation(&self, peer: &AuthenticatedPeer) -> PeerRevocation {
        if self.poisoned {
            return PeerRevocation::Unknown(RevocationUnknown::Poisoned);
        }
        if peer.net_id != self.net {
            return PeerRevocation::Unknown(RevocationUnknown::WrongNetwork);
        }
        let Some(snapshot) = self.state.snapshot.as_ref() else {
            return PeerRevocation::Unknown(RevocationUnknown::NoSnapshot);
        };
        if self.is_frozen() {
            return PeerRevocation::Unknown(RevocationUnknown::Frozen);
        }
        if self.state.rollback_latched {
            return PeerRevocation::Unknown(RevocationUnknown::ClockLatched);
        }
        let mut state = PeerRevocationState {
            sequence: snapshot.seq,
            identity: false,
            core: false,
            route: false,
            direct: false,
        };
        for scope in &self.state.revocation.scopes {
            if scope.node_id != peer.node_id || scope.generation != peer.identity_generation {
                continue;
            }
            match scope.class {
                IssuerClass::Identity => state.identity = true,
                IssuerClass::Core => state.core = true,
                IssuerClass::Route => state.route = true,
                // Unreachable: the schema refuses Direct before a scope exists.
                // Never turn a home-Core coincidence into a direct-grant claim.
                IssuerClass::Direct => {}
            }
        }
        PeerRevocation::Verified(state)
    }

    /// Persist a trusted UTC observation before using it.
    ///
    /// The caller must supply UTC from an independently trusted source. This
    /// method only maintains the durable monotonic floor and rollback latch; it
    /// does not attest the source. A rollback beyond
    /// [`CLOCK_ROLLBACK_TOLERANCE_US`] persists the latch and returns
    /// [`Error::ClockRollback`]. While latched, further observations also fail:
    /// a fresh caller-side `TrustedUtc` cannot clear this store's latch.
    pub fn observe_trusted_utc(&mut self, utc_us: u64) -> Result<u64, Error> {
        self.supported()?;
        self.healthy()?;
        if self.state.rollback_latched {
            return Err(Error::ClockRollback);
        }
        let floor = self.state.utc_floor;
        if utc_us.saturating_add(CLOCK_ROLLBACK_TOLERANCE_US) < floor {
            self.state.rollback_latched = true;
            // Recovery may release the latch, but must not rearm the same
            // snapshot past its previously captured monotonic deadline.
            self.commit_or_poison()?;
            return Err(Error::ClockRollback);
        }
        if utc_us > floor {
            self.state.utc_floor = utc_us;
            self.commit_or_poison()?;
        }
        Ok(self.state.utc_floor)
    }

    /// Explicit clock recovery after an independently trusted time decision.
    ///
    /// This can release only the rollback latch. It never lowers the persisted
    /// floor, extends an in-process snapshot deadline, or clears an equivocation
    /// freeze or revocation conflict latch.
    pub fn recover_trusted_utc(&mut self, utc_us: u64) -> Result<u64, Error> {
        self.supported()?;
        self.healthy()?;
        let floor = self.state.utc_floor;
        if utc_us < floor {
            return Err(Error::ClockRollback);
        }
        if utc_us > floor || self.state.rollback_latched {
            self.state.utc_floor = utc_us;
            self.state.rollback_latched = false;
            self.commit_or_poison()?;
        }
        Ok(self.state.utc_floor)
    }

    /// Verify the exact raw signed envelope and durably commit before success.
    ///
    /// `raw_signed` is the original `SignedObject` envelope bytes; the verifier
    /// checks both signatures over the original TBS bytes. `trusted_utc_us` must
    /// come from the caller's independent trusted boundary. `mono_now` is used
    /// only to establish the process-local deadline for the effective cutoff.
    ///
    /// Ordering:
    /// 1. persist a trusted UTC observation/rollback latch;
    /// 2. detect a same-sequence/different-content candidate structurally;
    /// 3. let the owned `ManagementTrust` verify authority + both signatures at
    ///    the candidate's signed `issued_at` (evidence path) or at the current
    ///    effective UTC (normal path); the issuer delegation must also be
    ///    current at effective UTC in both paths;
    /// 4. require a real `management::Error::Equivocation` for the evidence path,
    ///    then persist both exact envelopes atomically and freeze;
    /// 5. otherwise persist exact raw envelope + issuer id/generation + seq +
    ///    TBS SHA-256 + signed issued/next_update + UTC floor atomically;
    /// 6. decode the bounded `revocations` payload out of that exact verified TBS and
    ///    merge it into the in-memory model state, refusing a stale epoch
    ///    ([`Error::RevocationStale`]), a class the policy does not authorize
    ///    ([`Error::RevocationPermission`]), or a bound overflow
    ///    ([`Error::RevocationTooLarge`]) before the snapshot is stored. A same-scope,
    ///    same-epoch conflict latches in-memory evidence and returns
    ///    [`Error::RevocationConflict`]; neither the scopes nor the latch are
    ///    persisted. In production the policy is always `none`, so step 6 refuses
    ///    any non-empty payload.
    ///
    /// A payload that cannot be decoded is refused with [`Error::BadStatus`] before
    /// the verifier records replay state; it is never silently ignored. A duplicate
    /// (same sequence and same `object_id`) returns
    /// [`SnapshotResult::DuplicateNotRenewed`] and never extends lifetime. A persist
    /// failure poisons the store.
    pub fn accept_signed_snapshot(
        &mut self,
        raw_signed: &[u8],
        trusted_utc_us: u64,
        mono_now: Instant,
    ) -> Result<SnapshotResult, Error> {
        self.supported()?;
        self.healthy()?;
        if self.is_frozen() {
            return Err(Error::Frozen);
        }
        if raw_signed.is_empty() || raw_signed.len() > MAX_SIGNED_OBJECT_BYTES {
            return Err(Error::TooLarge);
        }
        // Reject an unreadable or unauthorized revocation payload before the owned
        // ManagementTrust records replay state. Otherwise a signed object we must
        // refuse could still advance the verifier's replay slot and make a later
        // legitimate snapshot look like equivocation.
        self.check_revocation_payload(raw_signed)?;
        let now = self.observe_trusted_utc(trusted_utc_us)?;
        let old = self.state.snapshot.clone();

        // Structural pre-check for a same-sequence conflict. We do not trust
        // this decode for acceptance; it only selects the evidence path.
        let candidate = decode_conflict_candidate(raw_signed, self.net).ok();
        if let (Some(old), Some(candidate)) = (old.as_ref(), candidate.as_ref())
            && candidate.seq == old.seq
            && candidate.object_id != old.object_id
        {
            if candidate.issuer.as_slice() != old.issuer.as_slice()
                || candidate.generation != old.generation
            {
                // A different StatusSigner identity at the same sequence is
                // not attributed as equivocation. The master plan's
                // StatusSigner rotation/global-sequence semantics are not
                // frozen here, and `ManagementTrust` currently keys the
                // StatusSnapshot replay slot globally. Reject without
                // touching that replay slot so a valid signer rotation
                // cannot freeze this store by mistake. A higher sequence
                // from another authorized signer follows the verifier's
                // normal global-slot path.
                return Err(Error::BadStatus);
            }
            if candidate.issued > now {
                return Err(Error::Policy(PolicyError::SnapshotFromFuture));
            }
            // The verifier checks issuer authority, network,
            // object type, the signed validity window and both Ed25519 +
            // ML-DSA signatures before `record_replay` can return
            // `Equivocation`. Therefore this error is evidence of a valid
            // dual-signed, authorized conflicting object, not arbitrary
            // bad bytes. We retain the older envelope ourselves; the
            // verifier's single `conflict_evidence` slot is not used as
            // storage.
            match self
                .trust
                .verify_with_issuer_time(raw_signed, candidate.issued, now)
            {
                Err(management::Error::Equivocation) => {
                    self.persist_equivocation(raw_signed, old.seq)?;
                    return Err(Error::Policy(PolicyError::SnapshotEquivocation));
                }
                Err(error) => return Err(map_management_error(error)),
                Ok(_) => {
                    // The owned verifier had no replay slot for our
                    // persisted snapshot, so a conflict cannot be
                    // attributed. Fail closed without freezing.
                    self.poisoned = true;
                    self.runtime_deadline = None;
                    return Err(Error::BadStatus);
                }
            }
        }

        let verified = match self.trust.verify_and_authorize(raw_signed, now) {
            Ok(verified) => verified,
            Err(management::Error::Equivocation) => {
                // A conflict the persisted state cannot attribute. Never
                // freeze on unattributed evidence; poison the inconsistent
                // store instead.
                self.poisoned = true;
                self.runtime_deadline = None;
                return Err(Error::BadStatus);
            }
            Err(error) => return Err(map_management_error(error)),
        };
        let snapshot = snapshot_from_verified(&verified, self.net)?;
        // Decode the bounded payload out of the exact verified TBS bytes and merge
        // it into the in-memory model. A stale epoch is refused before any
        // mutation; a same-scope/same-epoch conflict latches in-memory evidence and
        // freezes this process. The model state is not part of the durable image.
        let revocations = verified_revocations(&verified)?;
        if let Some(old) = old.as_ref() {
            if old.seq == snapshot.seq {
                if old.object_id == snapshot.object_id {
                    return Ok(SnapshotResult::DuplicateNotRenewed);
                }
                if old.issuer.as_slice() != snapshot.issuer.as_slice()
                    || old.generation != snapshot.generation
                {
                    return Err(Error::BadStatus);
                }
                // Defensive: the pre-check did not select the evidence path,
                // but the verifier returned a currently valid, signature-
                // verified object at the same sequence. Persist both sides.
                self.persist_equivocation(raw_signed, old.seq)?;
                return Err(Error::Policy(PolicyError::SnapshotEquivocation));
            }
            if snapshot.seq < old.seq {
                return Err(Error::Policy(PolicyError::SequenceNotIncreasing));
            }
            if snapshot.issued < old.issued {
                return Err(Error::Policy(PolicyError::SnapshotIssuedAtRegression));
            }
        }
        if snapshot.issued > now {
            return Err(Error::Policy(PolicyError::SnapshotFromFuture));
        }
        let valid_until = verified.valid_until();
        if now >= valid_until {
            return Err(Error::Policy(PolicyError::SnapshotExpired));
        }
        let remaining = valid_until - now;
        let deadline = mono_now
            .checked_add(Duration::from_micros(remaining))
            .ok_or(Error::NotFresh)?;
        self.apply_revocations(&revocations)?;
        self.state.snapshot = Some(snapshot);
        self.commit_or_poison()?;
        self.snapshot_valid_until = Some(valid_until);
        self.runtime_deadline = Some(deadline);
        Ok(SnapshotResult::Accepted)
    }

    /// Obtain a private, non-Clone freshness capability.
    ///
    /// This first persists the trusted UTC observation (including a rollback
    /// latch), then uses the earlier of signed `next_update` and the verified
    /// issuer delegation expiry to tighten any in-process `Instant` deadline.
    /// A restart with a still-valid persisted snapshot becomes fresh without a
    /// new `accept_signed_snapshot`; an already-expired snapshot remains
    /// expired. This may write the floor, so it is an admission/refresh call,
    /// not a per-packet call.
    pub fn current_fresh(
        &mut self,
        trusted_utc_us: u64,
        mono_now: Instant,
    ) -> Result<FreshStatus<'_>, Error> {
        self.supported()?;
        self.healthy()?;
        if self.is_frozen() {
            return Err(Error::Frozen);
        }
        let now = self.observe_trusted_utc(trusted_utc_us)?;
        let snapshot = self.state.snapshot.as_ref().ok_or(Error::NotFresh)?;
        let seq = snapshot.seq;
        let valid_until = self.snapshot_valid_until.ok_or(Error::NotFresh)?;
        // `now` is the monotonic UTC floor; a tolerated rollback cannot extend
        // the lifetime of either the object or its delegation.
        if now < snapshot.issued || now >= valid_until {
            return Err(Error::NotFresh);
        }
        let remaining = valid_until - now;
        let candidate = mono_now
            .checked_add(Duration::from_micros(remaining))
            .ok_or(Error::NotFresh)?;
        let deadline = match self.runtime_deadline {
            Some(existing) => existing.min(candidate),
            None => candidate,
        };
        if mono_now >= deadline {
            return Err(Error::NotFresh);
        }
        self.runtime_deadline = Some(deadline);
        Ok(FreshStatus {
            store: &*self,
            seq,
            deadline,
        })
    }

    /// Signature-independent structural gate for a snapshot candidate.
    ///
    /// A payload we cannot decode, or a class this store's policy does not allow,
    /// is refused before the owned verifier can advance its replay slot. The
    /// production policy is always `none`, so any non-empty payload fails closed.
    fn check_revocation_payload(&self, raw_signed: &[u8]) -> Result<(), Error> {
        let Ok(signed) = SignedObject::decode(raw_signed) else {
            return Ok(());
        };
        let Ok(object) = objects::decode_tbs(&signed.raw_tbs) else {
            return Ok(());
        };
        let payload = revocation_payload_bytes(&object);
        if payload.is_empty() {
            return Ok(());
        }
        let decoded = RevocationPayload::decode(payload).map_err(map_revocation_error)?;
        self.check_relay_policy(&decoded)
    }

    fn check_relay_policy(&self, payload: &RevocationPayload) -> Result<(), Error> {
        for entry in payload.entries() {
            if !self.revocation_relay.allows(entry.class) {
                return Err(Error::RevocationPermission);
            }
        }
        Ok(())
    }

    /// Merge one verified payload into the in-memory revocation model.
    ///
    /// Phase 1 is read-only. A stale epoch rejects the whole payload without
    /// touching state; two different decisions for one scope and epoch latch
    /// in-memory evidence and freeze the store. Phase 2 applies the planned
    /// insert/replace operations. The caller commits only the signed snapshot; the
    /// model state is deliberately not part of the durable image.
    fn apply_revocations(&mut self, payload: &RevocationPayload) -> Result<(), Error> {
        self.check_relay_policy(payload)?;
        let mut changes: Vec<RevocationChange> = Vec::new();
        let mut inserted: usize = 0;
        let mut latched: Option<RevocationConflictRecord> = None;
        for entry in payload.entries() {
            let digest = entry_digest(entry)?;
            let scope = RevokedScope {
                class: entry.class,
                origin_core: entry.origin_core,
                node_id: entry.node_id,
                generation: entry.identity_generation,
                target_id: entry.target_id,
                epoch: entry.epoch,
                digest,
            };
            match self.state.revocation.scope(scope.key()) {
                None => {
                    inserted += 1;
                    changes.push(RevocationChange::Insert(scope));
                }
                Some(existing) => {
                    if entry.epoch < existing.epoch {
                        return Err(Error::RevocationStale);
                    }
                    if entry.epoch == existing.epoch {
                        if existing.digest == digest {
                            continue;
                        }
                        latched = Some(RevocationConflictRecord {
                            scope: *existing,
                            second_digest: digest,
                        });
                        break;
                    }
                    changes.push(RevocationChange::Supersede(scope));
                }
            }
        }
        if let Some(record) = latched {
            self.state.revocation.conflict = Some(record);
            self.runtime_deadline = None;
            self.commit_or_poison()?;
            return Err(Error::RevocationConflict);
        }
        // Only genuinely new scopes consume the bounded budget; replacing a scope's
        // epoch is not growth.
        if self.state.revocation.scopes.len() + inserted > MAX_REVOCATION_SCOPES {
            return Err(Error::RevocationTooLarge);
        }
        for change in changes {
            match change {
                RevocationChange::Insert(scope) => self.state.revocation.insert(scope)?,
                RevocationChange::Supersede(scope) => self.state.revocation.supersede(scope)?,
            }
        }
        Ok(())
    }

    fn healthy(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    fn supported(&self) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }

    fn commit_or_poison(&mut self) -> Result<(), Error> {
        if let Err(error) = self.commit() {
            self.poisoned = true;
            self.runtime_deadline = None;
            return Err(error);
        }
        Ok(())
    }

    fn persist_equivocation(&mut self, second_raw: &[u8], expected_seq: u64) -> Result<(), Error> {
        if self.state.equivocation.is_some() {
            return Err(Error::Frozen);
        }
        let old = self.state.snapshot.as_ref().ok_or(Error::Corrupt)?;
        let candidate = decode_conflict_candidate(second_raw, self.net)?;
        if candidate.seq != expected_seq || candidate.seq != old.seq {
            return Err(Error::Corrupt);
        }
        if candidate.object_id == old.object_id {
            return Err(Error::Corrupt);
        }
        if candidate.issuer.as_slice() != old.issuer.as_slice()
            || candidate.generation != old.generation
        {
            // Equivocation evidence is only retained for the same signer
            // identity. Different signers at the same sequence are a separate,
            // unfrozen sequence-scope question.
            return Err(Error::BadStatus);
        }
        self.state.equivocation = Some(second_raw.to_vec());
        self.runtime_deadline = None;
        self.commit_or_poison()
    }

    #[cfg(target_os = "linux")]
    fn read_state(&self) -> Result<State, Error> {
        let file = match open_existing(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(State::empty(self.net));
            }
            Err(error) => return Err(error.into()),
        };
        validate_file(&self.path, &file, self.owner)?;
        let len = usize::try_from(file.metadata()?.len()).map_err(|_| Error::TooLarge)?;
        if len > MAX_STATE_WITH_IDENTITY_BYTES {
            return Err(Error::TooLarge);
        }
        let mut bytes = Vec::with_capacity(len);
        file.take(MAX_STATE_WITH_IDENTITY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STATE_WITH_IDENTITY_BYTES
            || (bytes.len() > MAX_STATUS_STATE_BYTES && !bytes.starts_with(IDENTITY_MAGIC))
        {
            return Err(Error::TooLarge);
        }
        decode(&bytes)
    }

    #[cfg(target_os = "linux")]
    fn verify_loaded(&mut self) -> Result<(), Error> {
        let snapshot = self.state.snapshot.clone();
        let equivocation = self.state.equivocation.clone();
        let Some(snapshot) = snapshot else {
            if equivocation.is_some() {
                return Err(Error::Corrupt);
            }
            return Ok(());
        };
        if snapshot.raw.is_empty() || snapshot.raw.len() > MAX_SIGNED_OBJECT_BYTES {
            return Err(Error::TooLarge);
        }
        // Authenticate already-persisted evidence at its own signed not-before
        // boundary. This does not grant current freshness.
        let verified = match self
            .trust
            .verify_and_authorize(&snapshot.raw, snapshot.issued)
        {
            Ok(verified) => verified,
            Err(management::Error::WrongNetwork) => return Err(Error::WrongNetwork),
            Err(_) => return Err(Error::Corrupt),
        };
        let rebuilt = snapshot_from_verified(&verified, self.net).map_err(|_| Error::Corrupt)?;
        if rebuilt != snapshot {
            return Err(Error::Corrupt);
        }
        // The persisted floor is the latest trusted observation, so it must be
        // at or above the signed issued_at. It is never lowered.
        if self.state.utc_floor < rebuilt.issued {
            return Err(Error::Corrupt);
        }
        if let Some(second) = equivocation {
            if second.is_empty() || second.len() > MAX_SIGNED_OBJECT_BYTES {
                return Err(Error::TooLarge);
            }
            let candidate =
                decode_conflict_candidate(&second, self.net).map_err(|_| Error::Corrupt)?;
            if candidate.seq != rebuilt.seq
                || candidate.object_id == rebuilt.object_id
                || candidate.issuer.as_slice() != rebuilt.issuer.as_slice()
                || candidate.generation != rebuilt.generation
            {
                return Err(Error::Corrupt);
            }
            match self.trust.verify_and_authorize(&second, candidate.issued) {
                Err(management::Error::Equivocation) => (),
                Err(management::Error::WrongNetwork) => return Err(Error::WrongNetwork),
                _ => return Err(Error::Corrupt),
            }
        }
        // Revocation state is not part of the durable image. Rebuild it only from
        // this re-verified signed snapshot, so the model never presents a
        // digest-only historical scope as verified.
        self.rebuild_loaded_revocations(&verified)?;
        self.snapshot_valid_until = Some(verified.valid_until());
        Ok(())
    }

    /// Rebuild the in-memory model from the persisted, re-verified signed snapshot.
    ///
    /// The durable image has no revocation block and no historical scopes. Only
    /// entries present in this exact TBS are reconstructed, so every model entry at
    /// this point is covered by the snapshot signature just checked. A digest left
    /// over from an earlier payload is never treated as verified because it is
    /// never persisted. A test policy that no longer allows a class fails closed
    /// with [`Error::RevocationPermission`].
    #[cfg(target_os = "linux")]
    fn rebuild_loaded_revocations(&mut self, verified: &VerifiedObject) -> Result<(), Error> {
        let payload = verified_revocations(verified)?;
        self.check_relay_policy(&payload)?;
        let mut state = RevocationState::default();
        for entry in payload.entries() {
            let digest = entry_digest(entry)?;
            state.insert(RevokedScope {
                class: entry.class,
                origin_core: entry.origin_core,
                node_id: entry.node_id,
                generation: entry.identity_generation,
                target_id: entry.target_id,
                epoch: entry.epoch,
                digest,
            })?;
        }
        self.state.revocation = state;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn commit(&self) -> Result<(), Error> {
        #[cfg(test)]
        if self.fail_next_commit {
            return Err(Error::Io(io::Error::other(
                "injected status commit failure",
            )));
        }
        let bytes = encode(&self.state)?;
        let staging = suffix(&self.path, ".staging");
        match fs::symlink_metadata(&staging) {
            Ok(_) => return Err(Error::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        let mut file = open_staging(&staging)?;
        validate_file(&staging, &file, self.owner)?;
        let result = (|| -> io::Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&staging, &self.path)?;
            File::open(
                self.path
                    .parent()
                    .ok_or_else(|| io::Error::other("parent"))?,
            )?
            .sync_all()
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&staging);
            return Err(Error::Io(error));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn commit(&self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}

/// Private, non-Clone freshness capability tied to the store borrow.
///
/// The capability borrows the store immutably, while accepting a snapshot or
/// refreshing the capability requires `&mut self`. A new snapshot therefore
/// cannot be accepted while this token is alive: the token is not a concurrently
/// updated handle and this API makes no "auto-invalidates on a concurrent
/// update" claim. An older token simply cannot coexist with a newer accept.
///
/// The capability remains subject to [`FreshStatus::check`] at every business
/// use. `check` is read-only and rechecks the current sequence/epoch, expiry,
/// persisted floor, rollback latch and captured monotonic deadline defensively.
/// It cannot persist a latch; after it rejects for a clock rollback, the owner
/// must drop the token and call `StatusStore::observe_trusted_utc` so the latch
/// becomes durable.
pub struct FreshStatus<'a> {
    store: &'a StatusStore,
    seq: u64,
    deadline: Instant,
}
impl FreshStatus<'_> {
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Captured process-local deadline. A watchdog must not sleep past this
    /// instant, even when its normal poll interval is longer.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn check(&self, trusted_utc_us: u64, mono_now: Instant) -> Result<(), Error> {
        self.store.supported()?;
        if self.store.poisoned {
            return Err(Error::Poisoned);
        }
        if self.store.is_frozen() {
            return Err(Error::Frozen);
        }
        if self.store.state.rollback_latched {
            return Err(Error::ClockRollback);
        }
        if trusted_utc_us.saturating_add(CLOCK_ROLLBACK_TOLERANCE_US) < self.store.state.utc_floor {
            return Err(Error::ClockRollback);
        }
        // Match `current_fresh`/`observe`: a tolerated rollback is evaluated at
        // the persisted floor, not at the lower raw input. A large rollback was
        // rejected above.
        let effective_now = trusted_utc_us.max(self.store.state.utc_floor);
        let snapshot = self.store.state.snapshot.as_ref().ok_or(Error::NotFresh)?;
        let valid_until = self.store.snapshot_valid_until.ok_or(Error::NotFresh)?;
        if snapshot.seq != self.seq
            || effective_now < snapshot.issued
            || effective_now >= valid_until
            || mono_now >= self.deadline
        {
            return Err(Error::NotFresh);
        }
        Ok(())
    }

    /// Revocation answer for an authenticated peer, from the same store snapshot
    /// that this capability made fresh.
    ///
    /// The token's borrow prevents a new snapshot from being accepted while it is
    /// alive, so this answer describes the sequence the token covers. The caller
    /// must still run [`FreshStatus::check`] at the same business boundary; this
    /// method does not re-read the clock.
    pub fn peer_revocation(&self, peer: &AuthenticatedPeer) -> PeerRevocation {
        self.store.peer_revocation(peer)
    }
}

fn snapshot_from_verified(verified: &VerifiedObject, net: [u8; 16]) -> Result<Snapshot, Error> {
    let object = verified.object();
    if verified.signed_object().object_type != ObjectType::StatusSnapshot {
        return Err(Error::BadStatus);
    }
    if object.net_id != net {
        return Err(Error::WrongNetwork);
    }
    if object.issuer_key_id.is_empty()
        || object.issuer_key_id.len() > MAX_ISSUER_ID_BYTES
        || object.issuer_generation == 0
    {
        return Err(Error::BadStatus);
    }
    if object.subject_identity != SubjectIdentity::Network {
        return Err(Error::BadStatus);
    }
    let ObjectBody::StatusSnapshot(body) = &object.body else {
        return Err(Error::BadStatus);
    };
    // The revocation payload itself is validated, decoded and merged separately by
    // `verified_revocations`/`apply_revocations`; it is never accepted as an opaque
    // byte string and never silently ignored.
    if object.seq != body.sequence
        || object.issued_at != body.issued_at
        || object.expires != body.next_update
    {
        return Err(Error::BadStatus);
    }
    if body.issued_at >= body.next_update || body.next_update - body.issued_at > STATUS_MAX_AGE_US {
        return Err(Error::Policy(PolicyError::InvalidSnapshotWindow));
    }
    Ok(Snapshot {
        issuer: object.issuer_key_id.clone(),
        generation: object.issuer_generation,
        seq: body.sequence,
        object_id: verified.object_id(),
        issued: body.issued_at,
        next: body.next_update,
        raw: verified.raw_signed_object().to_vec(),
    })
}

struct ConflictCandidate {
    issuer: Vec<u8>,
    generation: u64,
    seq: u64,
    issued: u64,
    object_id: [u8; 32],
}

/// `true` for a permanent overlay node slot: home Core 1..=16 and a host octet of
/// 1 (Core slot) or 2..=251 (Edge slot).
fn valid_peer_node_id(node_id: u16) -> bool {
    let home_core = (node_id >> 8) + 1;
    let octet = (node_id & 0xff) as u8;
    (1..=16).contains(&home_core) && (octet == 1 || (2..=251).contains(&octet))
}

/// The exact signed revocation payload bytes of a decoded snapshot object.
fn revocation_payload_bytes(object: &objects::ManagementObject) -> &[u8] {
    match &object.body {
        ObjectBody::StatusSnapshot(body) => &body.revocations,
        _ => &[],
    }
}

fn map_revocation_error(error: revocation::Error) -> Error {
    match error {
        revocation::Error::ScopeNotPermitted | revocation::Error::DirectIssuerUnverifiable => {
            Error::RevocationPermission
        }
        revocation::Error::TooLarge | revocation::Error::TooManyEntries => {
            Error::RevocationTooLarge
        }
        _ => Error::BadStatus,
    }
}

fn entry_digest(entry: &RevocationEntry) -> Result<[u8; 32], Error> {
    let bytes = entry.canonical_bytes().map_err(map_revocation_error)?;
    sha256(&bytes)
}

/// Decode the bounded payload from the exact verified TBS bytes.
///
/// The payload is taken from the decoded body of the exact signed TBS, and the
/// decode is only accepted when re-encoding that body reproduces the verified TBS
/// byte for byte. No re-encoded substitute and no caller-supplied bytes are used.
fn verified_revocations(verified: &VerifiedObject) -> Result<RevocationPayload, Error> {
    let object = verified.object();
    if verified.signed_object().object_type != ObjectType::StatusSnapshot {
        return Err(Error::BadStatus);
    }
    let regenerated = objects::encode_tbs(object).map_err(|_| Error::BadStatus)?;
    if regenerated.as_slice() != verified.raw_tbs() {
        return Err(Error::BadStatus);
    }
    let payload = revocation_payload_bytes(object);
    if payload.is_empty() {
        return Ok(RevocationPayload::empty());
    }
    RevocationPayload::decode(payload).map_err(map_revocation_error)
}

fn decode_conflict_candidate(raw_signed: &[u8], net: [u8; 16]) -> Result<ConflictCandidate, Error> {
    if raw_signed.is_empty() || raw_signed.len() > MAX_SIGNED_OBJECT_BYTES {
        return Err(Error::TooLarge);
    }
    let signed = SignedObject::decode(raw_signed).map_err(|_| Error::BadStatus)?;
    if signed.object_type != ObjectType::StatusSnapshot {
        return Err(Error::BadStatus);
    }
    let object = objects::decode_tbs(&signed.raw_tbs).map_err(|_| Error::BadStatus)?;
    if object.net_id != net {
        return Err(Error::WrongNetwork);
    }
    if object.issuer_key_id.is_empty()
        || object.issuer_key_id.len() > MAX_ISSUER_ID_BYTES
        || object.issuer_generation == 0
    {
        return Err(Error::BadStatus);
    }
    if object.subject_identity != SubjectIdentity::Network {
        return Err(Error::BadStatus);
    }
    let ObjectBody::StatusSnapshot(body) = &object.body else {
        return Err(Error::BadStatus);
    };
    if object.seq != body.sequence
        || object.issued_at != body.issued_at
        || object.expires != body.next_update
    {
        return Err(Error::BadStatus);
    }
    if body.issued_at >= body.next_update || body.next_update - body.issued_at > STATUS_MAX_AGE_US {
        return Err(Error::Policy(PolicyError::InvalidSnapshotWindow));
    }
    Ok(ConflictCandidate {
        issuer: object.issuer_key_id.clone(),
        generation: object.issuer_generation,
        seq: body.sequence,
        issued: body.issued_at,
        object_id: sha256(&signed.raw_tbs)?,
    })
}

fn map_management_error(error: management::Error) -> Error {
    match error {
        management::Error::WrongNetwork => Error::WrongNetwork,
        management::Error::ObjectTooLarge => Error::TooLarge,
        management::Error::StaleSequence => Error::Policy(PolicyError::SequenceNotIncreasing),
        management::Error::IssuedAtRegression => {
            Error::Policy(PolicyError::SnapshotIssuedAtRegression)
        }
        management::Error::Expired => Error::Policy(PolicyError::SnapshotExpired),
        management::Error::IssuerNotValid => Error::NotFresh,
        management::Error::NotYetValid => Error::Policy(PolicyError::SnapshotFromFuture),
        _ => Error::BadStatus,
    }
}

fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    let digest = hash(MessageDigest::sha256(), data).map_err(|_| Error::BadStatus)?;
    let bytes: &[u8] = digest.as_ref();
    bytes.try_into().map_err(|_| Error::BadStatus)
}

#[cfg(target_os = "linux")]
fn encode(state: &State) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(if state.identity.is_some() { IDENTITY_MAGIC } else { MAGIC });
    bytes.extend_from_slice(&state.net);
    bytes.extend_from_slice(&state.utc_floor.to_be_bytes());
    let mut flags = 0u8;
    if state.rollback_latched {
        flags |= FLAG_ROLLBACK_LATCHED;
    }
    if state.snapshot.is_some() {
        flags |= FLAG_HAS_SNAPSHOT;
    }
    if state.snapshot.is_some() && state.equivocation.is_some() {
        flags |= FLAG_HAS_EQUIVOCATION;
    }
    bytes.push(flags);
    if let Some(snapshot) = &state.snapshot {
        put_u16_blob(&mut bytes, &snapshot.issuer, MAX_ISSUER_ID_BYTES)?;
        bytes.extend_from_slice(&snapshot.generation.to_be_bytes());
        bytes.extend_from_slice(&snapshot.seq.to_be_bytes());
        bytes.extend_from_slice(&snapshot.object_id);
        bytes.extend_from_slice(&snapshot.issued.to_be_bytes());
        bytes.extend_from_slice(&snapshot.next.to_be_bytes());
        put_u32_blob(&mut bytes, &snapshot.raw, MAX_SIGNED_OBJECT_BYTES)?;
        if let Some(second) = &state.equivocation {
            put_u32_blob(&mut bytes, second, MAX_SIGNED_OBJECT_BYTES)?;
        }
    } else if state.equivocation.is_some() {
        return Err(Error::Corrupt);
    }
    // The status relay model is never serialized. Only separately authenticated
    // identity evidence permits the v2 extension; the status portion retains its cap.
    if bytes.len() > MAX_STATUS_STATE_BYTES {
        return Err(Error::TooLarge);
    }
    if let Some(identity) = &state.identity {
        identity.encode(&mut bytes)?;
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn decode(bytes: &[u8]) -> Result<State, Error> {
    let mut reader = Reader { bytes, position: 0 };
    let magic = reader.take(8)?;
    let has_identity = magic == IDENTITY_MAGIC;
    if magic != MAGIC && !has_identity {
        return Err(Error::Corrupt);
    }
    let net: [u8; 16] = reader.take(16)?.try_into().map_err(|_| Error::Corrupt)?;
    let utc_floor = reader.u64()?;
    let flags = reader.u8()?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::Corrupt);
    }
    let has_snapshot = flags & FLAG_HAS_SNAPSHOT != 0;
    let has_equivocation = flags & FLAG_HAS_EQUIVOCATION != 0;
    let rollback_latched = flags & FLAG_ROLLBACK_LATCHED != 0;
    if !has_snapshot && has_equivocation {
        return Err(Error::Corrupt);
    }
    let snapshot = if has_snapshot {
        let issuer = reader.blob_u16(MAX_ISSUER_ID_BYTES)?.to_vec();
        if issuer.is_empty() {
            return Err(Error::Corrupt);
        }
        let generation = reader.u64()?;
        if generation == 0 {
            return Err(Error::Corrupt);
        }
        let seq = reader.u64()?;
        let object_id: [u8; 32] = reader.take(32)?.try_into().map_err(|_| Error::Corrupt)?;
        let issued = reader.u64()?;
        let next = reader.u64()?;
        if issued >= next || next - issued > STATUS_MAX_AGE_US {
            return Err(Error::Corrupt);
        }
        let raw = reader.blob_u32(MAX_SIGNED_OBJECT_BYTES)?.to_vec();
        if raw.is_empty() {
            return Err(Error::Corrupt);
        }
        Some(Snapshot {
            issuer,
            generation,
            seq,
            object_id,
            issued,
            next,
            raw,
        })
    } else {
        None
    };
    let equivocation = if has_equivocation {
        let second = reader.blob_u32(MAX_SIGNED_OBJECT_BYTES)?.to_vec();
        if second.is_empty() {
            return Err(Error::Corrupt);
        }
        Some(second)
    } else {
        None
    };
    if reader.position > MAX_STATUS_STATE_BYTES {
        return Err(Error::TooLarge);
    }
    let identity = if has_identity {
        Some(identity::Decisions::decode(&mut reader, utc_floor)?)
    } else {
        None
    };
    if reader.position != bytes.len() {
        return Err(Error::Corrupt);
    }
    if let Some(snapshot) = &snapshot
        && utc_floor < snapshot.issued
    {
        return Err(Error::Corrupt);
    }
    Ok(State {
        net,
        utc_floor,
        rollback_latched,
        snapshot,
        equivocation,
        // Model relay entries still come only from the re-verified snapshot.
        revocation: RevocationState::default(),
        identity,
    })
}

#[cfg(target_os = "linux")]
fn put_u16_blob(bytes: &mut Vec<u8>, value: &[u8], max: usize) -> Result<(), Error> {
    if value.len() > max {
        return Err(Error::TooLarge);
    }
    let length = u16::try_from(value.len()).map_err(|_| Error::TooLarge)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

#[cfg(target_os = "linux")]
fn put_u32_blob(bytes: &mut Vec<u8>, value: &[u8], max: usize) -> Result<(), Error> {
    if value.len() > max {
        return Err(Error::TooLarge);
    }
    let length = u32::try_from(value.len()).map_err(|_| Error::TooLarge)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

#[cfg(target_os = "linux")]
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
#[cfg(target_os = "linux")]
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Corrupt)?;
        if end > self.bytes.len() {
            return Err(Error::Corrupt);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    fn blob_u16(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let length = usize::from(self.u16()?);
        if length > max {
            return Err(Error::TooLarge);
        }
        self.take(length)
    }

    fn blob_u32(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let length = usize::try_from(self.u32()?).map_err(|_| Error::TooLarge)?;
        if length > max {
            return Err(Error::TooLarge);
        }
        self.take(length)
    }
}

#[cfg(target_os = "linux")]
fn suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(target_os = "linux")]
fn checked_path(path: &Path, owner: u32) -> Result<PathBuf, Error> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(Error::UnsafePath);
    }
    let parent = path.parent().ok_or(Error::UnsafePath)?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::RootDir | Component::Normal(_) => (),
            _ => return Err(Error::UnsafePath),
        }
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::UnsafePath);
        }
        let mode = metadata.permissions().mode();
        let trusted_ancestor = metadata.uid() == 0 && mode & 0o1000 != 0;
        if mode & 0o022 != 0 && !trusted_ancestor {
            return Err(Error::UnsafePath);
        }
    }
    let canonical_parent = fs::canonicalize(parent)?;
    let metadata = fs::symlink_metadata(&canonical_parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != owner
    {
        return Err(Error::UnsafePath);
    }
    let output = canonical_parent.join(path.file_name().ok_or(Error::UnsafePath)?);
    match fs::symlink_metadata(&output) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1 =>
        {
            return Err(Error::UnsafePath);
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
        _ => (),
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn reject_staging(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn reject_symlink_or_nonfile(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::UnsafePath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn open_private(path: &Path, create: bool) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(LINUX_O_NOFOLLOW | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::UnsafePath);
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_existing(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(LINUX_O_NOFOLLOW | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_staging(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(LINUX_O_NOFOLLOW | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::UnsafePath);
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn validate_file(path: &Path, file: &File, owner: u32) -> Result<(), Error> {
    let path_metadata = fs::symlink_metadata(path)?;
    let file_metadata = file.metadata()?;
    let parent_metadata = fs::metadata(path.parent().ok_or(Error::UnsafePath)?)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
        || file_metadata.mode() & 0o777 != 0o600
        || file_metadata.uid() != owner
        || parent_metadata.uid() != owner
    {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{
        Authority,
        management::{IssuerRecord, IssuerScope, MANAGEMENT_SCHEMA_VERSION},
    };
    use boreas_proto::{
        messages::{SignedObject, SignerRole, SignerSignatures},
        objects::{
            ManagementObject, MldsaParameterSet, ObjectType,
            StatusSnapshot as ObjectStatusSnapshot, SubjectIdentity,
        },
    };
    use openssl::{
        pkey::{KeyType, PKey, Private},
        sign::Signer,
    };
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    const NET: [u8; 16] = [0x42; 16];
    static ID: AtomicU64 = AtomicU64::new(1);

    struct TestSigner {
        net: [u8; 16],
        key_id: Vec<u8>,
        generation: u64,
        authority: Authority,
        ed25519: PKey<Private>,
        mldsa: PKey<Private>,
    }
    impl TestSigner {
        fn new(key_id: u8, authority: Authority) -> Self {
            Self {
                net: NET,
                key_id: vec![key_id],
                generation: 1,
                authority,
                ed25519: PKey::generate_ed25519().unwrap(),
                mldsa: PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[key_id; 32])
                    .unwrap(),
            }
        }

        fn with_net(mut self, net: [u8; 16]) -> Self {
            self.net = net;
            self
        }

        fn record(&self) -> IssuerRecord {
            IssuerRecord {
                issuer_key_id: self.key_id.clone(),
                issuer_generation: self.generation,
                authority: self.authority,
                ed25519_public_key_der: self.ed25519.public_key_to_der().unwrap(),
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                mldsa_public_key_der: self.mldsa.public_key_to_der().unwrap(),
                scope: IssuerScope::default(),
            }
        }

        /// Normal fixture: every accepted snapshot in this slice has an empty
        /// revocation payload. The argument is retained so existing call sites
        /// continue to compile; use `sign_snapshot_with_revocations` for the
        /// explicit revocation tests.
        fn sign_snapshot(&self, issued: u64, next: u64, seq: u64, _revocations: &[u8]) -> Vec<u8> {
            self.sign_snapshot_with_revocations(issued, next, seq, b"")
        }

        /// Sign a snapshot whose `revocations` byte string is exactly `revocations`.
        /// Both real signatures cover the TBS that contains those bytes.
        fn sign_snapshot_with_revocations(
            &self,
            issued: u64,
            next: u64,
            seq: u64,
            revocations: &[u8],
        ) -> Vec<u8> {
            let object = ManagementObject {
                net_id: self.net,
                issuer_key_id: self.key_id.clone(),
                issuer_generation: self.generation,
                subject_identity: SubjectIdentity::Network,
                seq,
                issued_at: issued,
                expires: next,
                extensions: Vec::new(),
                body: ObjectBody::StatusSnapshot(ObjectStatusSnapshot {
                    issued_at: issued,
                    next_update: next,
                    sequence: seq,
                    revocations: revocations.to_vec(),
                }),
            };
            let raw_tbs = objects::encode_tbs(&object).unwrap();
            let message = objects::signature_input(
                &raw_tbs,
                ObjectType::StatusSnapshot,
                MANAGEMENT_SCHEMA_VERSION,
            )
            .unwrap();
            let mut ed_signer = Signer::new_without_digest(&self.ed25519).unwrap();
            let ed25519: [u8; 64] = ed_signer
                .sign_oneshot_to_vec(&message)
                .unwrap()
                .try_into()
                .unwrap();
            let mut mldsa_signer = Signer::new_without_digest(&self.mldsa).unwrap();
            let mldsa = mldsa_signer.sign_oneshot_to_vec(&message).unwrap();
            SignedObject {
                object_type: ObjectType::StatusSnapshot,
                raw_tbs,
                signers: vec![SignerSignatures {
                    role: SignerRole::Primary,
                    ed25519,
                    mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                    mldsa,
                }],
            }
            .encode()
            .unwrap()
        }
    }

    fn trust_for(signer: &TestSigner) -> ManagementTrust {
        trust_for_net(signer, NET)
    }

    fn trust_for_net(signer: &TestSigner, net: [u8; 16]) -> ManagementTrust {
        let mut trust = ManagementTrust::new(net);
        trust.add_issuer(signer.record()).unwrap();
        trust
    }

    fn trust_with(signers: &[&TestSigner]) -> ManagementTrust {
        let mut trust = ManagementTrust::new(NET);
        for signer in signers {
            trust.add_issuer(signer.record()).unwrap();
        }
        trust
    }

    fn dir() -> (PathBuf, PathBuf) {
        let id = ID.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("boreas-status-{}-{id}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("state");
        (directory, path)
    }

    fn owner(directory: &Path) -> u32 {
        fs::metadata(directory).unwrap().uid()
    }

    fn open_store(path: &Path, owner: u32, signer: &TestSigner) -> StatusStore {
        StatusStore::open(path, NET, owner, trust_for(signer)).unwrap()
    }

    /// Test-only literal for every consumable class. There is deliberately no
    /// `RevocationRelayPolicy::all()` constructor in the crate API; the private
    /// fields are reachable only from a descendant test module. `Direct` has no
    /// field because the schema refuses it.
    const ALL: RevocationRelayPolicy = RevocationRelayPolicy {
        identity: true,
        core: true,
        route: true,
    };

    fn try_open_relay(
        path: &Path,
        owner: u32,
        signer: &TestSigner,
        relay: RevocationRelayPolicy,
    ) -> Result<StatusStore, Error> {
        StatusStore::open_with_revocation_relay(path, NET, owner, trust_for(signer), relay)
    }

    fn open_relay_store(
        path: &Path,
        owner: u32,
        signer: &TestSigner,
        relay: RevocationRelayPolicy,
    ) -> StatusStore {
        try_open_relay(path, owner, signer, relay).unwrap()
    }

    fn entry(
        class: IssuerClass,
        origin_core: u8,
        node_id: u16,
        generation: u64,
        target_id: u64,
        epoch: u64,
    ) -> RevocationEntry {
        RevocationEntry::new(class, origin_core, node_id, generation, target_id, epoch, 1).unwrap()
    }

    fn payload_bytes(entries: Vec<RevocationEntry>) -> Vec<u8> {
        RevocationPayload::new(entries).unwrap().encode().unwrap()
    }

    fn peer(node_id: u16, generation: u64) -> AuthenticatedPeer {
        AuthenticatedPeer::new(NET, node_id, generation).unwrap()
    }

    fn write_state(path: &Path, state: &State) {
        fs::write(path, encode(state).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn accept_duplicate_restart_and_expiry() {
        let signer = TestSigner::new(1, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw = signer.sign_snapshot(1_000_000, 2_000_000, 1, b"rev-a");
        let start = Instant::now();
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(matches!(
                store.accept_signed_snapshot(&raw, 1_500_000, start),
                Ok(SnapshotResult::Accepted)
            ));
            assert_eq!(store.sequence(), Some(1));
            let fresh = store.current_fresh(1_500_000, start).unwrap();
            assert_eq!(fresh.sequence(), 1);
            assert!(fresh.check(1_500_000, start).is_ok());
            assert!(matches!(
                fresh.check(1_500_000, start + Duration::from_millis(600)),
                Err(Error::NotFresh)
            ));
            // UTC 1.6 s is still inside the signed window (next_update 2.0 s),
            // but the process-local deadline from the original accept is
            // start + 500 ms. A duplicate at mono `start + 1000 ms` must not
            // renew or replace that deadline.
            let after_original_deadline = start + Duration::from_millis(1000);
            assert!(matches!(
                store.accept_signed_snapshot(&raw, 1_600_000, after_original_deadline),
                Ok(SnapshotResult::DuplicateNotRenewed)
            ));
            assert!(matches!(
                store.current_fresh(1_600_000, after_original_deadline),
                Err(Error::NotFresh)
            ));
        }
        {
            let mut store = open_store(&path, uid, &signer);
            assert_eq!(store.sequence(), Some(1));
            let fresh = store.current_fresh(1_700_000, Instant::now()).unwrap();
            assert_eq!(fresh.sequence(), 1);
            assert!(matches!(
                store.current_fresh(2_000_000, Instant::now()),
                Err(Error::NotFresh)
            ));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn verified_status_delegation_bounds_freshness_and_restart() {
        use crate::provisioning::{
            CaInitParams, init_ca_dir, sign_status_file, status_trust_from_roots,
            verify_status_freshness_from_roots,
        };

        const SECOND: u64 = 1_000_000;
        let (directory, path) = dir();
        let uid = owner(&directory);
        let ca_dir = directory.join("ca");
        let summary = init_ca_dir(
            &ca_dir,
            &CaInitParams {
                net_id: NET,
                issuer_generation: 1,
                now_us: 1_800_000_000 * SECOND,
                validity_days: 1,
            },
        )
        .unwrap();
        let expires = summary.expires_us;
        let issued = expires - 10 * SECOND;
        let observed = expires - 9 * SECOND;
        let roots = ca_dir.join("roots.cbor");
        let status = directory.join("status.signed");
        let signed = sign_status_file(&ca_dir, &status, 1, issued, 20).unwrap();
        assert_eq!(signed.next_update_us, expires + 10 * SECOND);
        assert!(matches!(
            verify_status_freshness_from_roots(&roots, &status, NET, issued - 1),
            Err(crate::provisioning::ProvisionError::Management(
                management::Error::NotYetValid
            ))
        ));
        assert_eq!(
            verify_status_freshness_from_roots(&roots, &status, NET, observed).unwrap(),
            (1, issued, expires)
        );

        let raw = fs::read(&status).unwrap();
        let open_at = |now| {
            let trust = status_trust_from_roots(&roots, NET, now).unwrap();
            StatusStore::open(&path, NET, uid, trust).unwrap()
        };
        let start = Instant::now();
        let deadline = start + Duration::from_secs(9);
        {
            let mut store = open_at(observed);
            assert!(matches!(
                store.accept_signed_snapshot(&raw, observed, start),
                Ok(SnapshotResult::Accepted)
            ));
            let fresh = store.current_fresh(observed, start).unwrap();
            assert_eq!(fresh.sequence(), 1);
            assert_eq!(fresh.deadline(), deadline);
            assert!(matches!(
                fresh.check(expires - 1, deadline),
                Err(Error::NotFresh)
            ));
            assert!(
                fresh
                    .check(expires - 1, deadline - Duration::from_micros(1))
                    .is_ok()
            );
            assert!(matches!(fresh.check(expires, start), Err(Error::NotFresh)));

            // A later monotonic sample with a lower, tolerated UTC cannot
            // turn the original deadline into a later wakeup time.
            let later = start + Duration::from_secs(1);
            assert!(matches!(
                store.accept_signed_snapshot(&raw, observed - 1, later),
                Ok(SnapshotResult::DuplicateNotRenewed)
            ));
            let fresh = store.current_fresh(observed - 1, later).unwrap();
            assert_eq!(fresh.deadline(), deadline);
        }
        {
            let before_expiry = expires - SECOND;
            let mut store = open_at(before_expiry);
            let fresh = store.current_fresh(before_expiry, start).unwrap();
            let deadline = start + Duration::from_secs(1);
            assert_eq!(fresh.deadline(), deadline);
            assert!(fresh.check(before_expiry, start).is_ok());
            assert!(matches!(
                store.observe_trusted_utc(before_expiry - CLOCK_ROLLBACK_TOLERANCE_US - 1),
                Err(Error::ClockRollback)
            ));
            assert_eq!(
                store.recover_trusted_utc(before_expiry).unwrap(),
                before_expiry
            );
            assert!(matches!(
                store.current_fresh(before_expiry, deadline),
                Err(Error::NotFresh)
            ));
        }
        {
            // Observe the UTC cutoff and then tolerate a subsequent wall-clock
            // rollback without bringing the persisted snapshot back to life.
            let mut store = open_at(expires - 1);
            let fresh = store.current_fresh(expires - 1, start).unwrap();
            assert!(fresh.check(expires - 1, start).is_ok());
            assert!(matches!(
                store.current_fresh(expires, start),
                Err(Error::NotFresh)
            ));
            assert!(matches!(
                store.accept_signed_snapshot(&raw, expires - 1, start),
                Err(Error::NotFresh)
            ));
        }
        {
            let mut store = open_at(expires - 1);
            assert_eq!(store.sequence(), Some(1));
            assert!(matches!(
                store.current_fresh(expires - 1, start),
                Err(Error::NotFresh)
            ));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn undecodable_revocations_fail_closed_without_replay_mutation() {
        let signer = TestSigner::new(9, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw = signer.sign_snapshot_with_revocations(1_000_000, 2_000_000, 1, b"rev-a");
        let mut store = open_store(&path, uid, &signer);
        assert!(matches!(
            store.accept_signed_snapshot(&raw, 1_500_000, Instant::now()),
            Err(Error::BadStatus)
        ));
        assert_eq!(store.sequence(), None);
        assert!(!store.is_poisoned());
        assert!(matches!(
            store.current_fresh(1_500_000, Instant::now()),
            Err(Error::NotFresh)
        ));
        // The rejected object must not have advanced the verifier replay slot:
        // a valid empty-revocation snapshot at the same sequence is accepted.
        let valid = signer.sign_snapshot(1_000_000, 2_000_000, 1, b"");
        assert!(matches!(
            store.accept_signed_snapshot(&valid, 1_500_000, Instant::now()),
            Ok(SnapshotResult::Accepted)
        ));
        assert_eq!(store.sequence(), Some(1));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn persisted_snapshot_with_revocations_is_refused_by_default_open() {
        let signer = TestSigner::new(10, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let revocations = payload_bytes(vec![entry(IssuerClass::Identity, 0, 0x0207, 2, 0, 1)]);
        let raw = signer.sign_snapshot_with_revocations(1_000_000, 2_000_000, 1, &revocations);
        let signed = SignedObject::decode(&raw).unwrap();
        let mut state = State::empty(NET);
        state.utc_floor = 1_500_000;
        state.snapshot = Some(Snapshot {
            issuer: signer.key_id.clone(),
            generation: 1,
            seq: 1,
            object_id: sha256(&signed.raw_tbs).unwrap(),
            issued: 1_000_000,
            next: 2_000_000,
            raw,
        });
        write_state(&path, &state);
        // The image itself is a normal v1 image; the refusal comes from rebuilding
        // the non-empty payload under the production policy `none`.
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::RevocationPermission)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn same_sequence_conflict_freezes_with_both_envelopes() {
        let signer = TestSigner::new(2, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw_a = signer.sign_snapshot(1_000_000, 3_000_000, 1, b"a");
        // Same sequence, different signed issued_at => different object_id,
        // within the signed window, with empty revocations.
        let raw_b = signer.sign_snapshot(1_000_001, 3_000_000, 1, b"b");
        let start = Instant::now();
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(matches!(
                store.accept_signed_snapshot(&raw_a, 1_500_000, start),
                Ok(SnapshotResult::Accepted)
            ));
            assert!(matches!(
                store.accept_signed_snapshot(&raw_b, 1_500_000, start),
                Err(Error::Policy(PolicyError::SnapshotEquivocation))
            ));
            assert!(store.is_frozen());
            let (first, second) = store.equivocation_evidence().unwrap();
            assert_eq!(first, raw_a.as_slice());
            assert_eq!(second, raw_b.as_slice());
            assert!(matches!(
                store.current_fresh(1_500_000, start),
                Err(Error::Frozen)
            ));
            let raw_c = signer.sign_snapshot(1_500_000, 3_000_000, 2, b"c");
            assert!(matches!(
                store.accept_signed_snapshot(&raw_c, 1_500_000, start),
                Err(Error::Frozen)
            ));
        }
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(store.is_frozen());
            let (first, second) = store.equivocation_evidence().unwrap();
            assert_eq!(first, raw_a.as_slice());
            assert_eq!(second, raw_b.as_slice());
            assert!(matches!(
                store.current_fresh(1_500_000, Instant::now()),
                Err(Error::Frozen)
            ));
            let raw_d = signer.sign_snapshot(1_500_000, 3_000_000, 3, b"d");
            assert!(matches!(
                store.accept_signed_snapshot(&raw_d, 1_500_000, Instant::now()),
                Err(Error::Frozen)
            ));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn sequence_and_issued_regressions_rejected() {
        let signer = TestSigner::new(3, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw1 = signer.sign_snapshot(1_000_000, 3_000_000, 1, b"a");
        let raw2 = signer.sign_snapshot(1_100_000, 3_100_000, 2, b"b");
        let raw3 = signer.sign_snapshot(1_050_000, 3_050_000, 3, b"c");
        let mut store = open_store(&path, uid, &signer);
        assert!(matches!(
            store.accept_signed_snapshot(&raw2, 1_200_000, Instant::now()),
            Ok(SnapshotResult::Accepted)
        ));
        assert!(matches!(
            store.accept_signed_snapshot(&raw1, 1_200_000, Instant::now()),
            Err(Error::Policy(PolicyError::SequenceNotIncreasing))
        ));
        assert!(matches!(
            store.accept_signed_snapshot(&raw3, 1_200_000, Instant::now()),
            Err(Error::Policy(PolicyError::SnapshotIssuedAtRegression))
        ));
        assert_eq!(store.sequence(), Some(2));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn expired_and_future_snapshots_rejected() {
        let signer = TestSigner::new(4, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw = signer.sign_snapshot(1_000_000, 2_000_000, 1, b"a");
        let future = signer.sign_snapshot(3_000_000, 4_000_000, 2, b"b");
        let mut store = open_store(&path, uid, &signer);
        assert!(matches!(
            store.accept_signed_snapshot(&raw, 2_500_000, Instant::now()),
            Err(Error::Policy(PolicyError::SnapshotExpired))
        ));
        assert!(matches!(
            store.accept_signed_snapshot(&future, 2_500_000, Instant::now()),
            Err(Error::Policy(PolicyError::SnapshotFromFuture))
        ));
        assert_eq!(store.sequence(), None);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn clock_latch_survives_restart_and_recovery_cannot_lower_floor() {
        let signer = TestSigner::new(5, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        {
            let mut store = open_store(&path, uid, &signer);
            assert_eq!(store.observe_trusted_utc(100_000_000).unwrap(), 100_000_000);
            assert!(matches!(
                store.observe_trusted_utc(100_000_000 - CLOCK_ROLLBACK_TOLERANCE_US - 1),
                Err(Error::ClockRollback)
            ));
            assert!(store.is_clock_latched());
            assert!(matches!(
                store.observe_trusted_utc(100_000_000),
                Err(Error::ClockRollback)
            ));
        }
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(store.is_clock_latched());
            assert!(matches!(
                store.observe_trusted_utc(100_000_000),
                Err(Error::ClockRollback)
            ));
            assert!(matches!(
                store.recover_trusted_utc(99_999_999),
                Err(Error::ClockRollback)
            ));
            assert_eq!(store.recover_trusted_utc(100_000_000).unwrap(), 100_000_000);
            assert!(!store.is_clock_latched());
            assert_eq!(store.observe_trusted_utc(100_000_001).unwrap(), 100_000_001);
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn persist_failure_poisons_and_reopen_uses_last_durable_state() {
        let signer = TestSigner::new(6, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw = signer.sign_snapshot(1_000_000, 2_000_000, 1, b"a");
        {
            let mut store = open_store(&path, uid, &signer);
            store.observe_trusted_utc(1_500_000).unwrap();
            store.fail_next_commit = true;
            assert!(matches!(
                store.accept_signed_snapshot(&raw, 1_500_000, Instant::now()),
                Err(Error::Io(_))
            ));
            assert!(store.is_poisoned());
            assert!(matches!(
                store.current_fresh(1_500_000, Instant::now()),
                Err(Error::Poisoned)
            ));
            assert!(matches!(
                store.observe_trusted_utc(1_500_001),
                Err(Error::Poisoned)
            ));
            assert!(matches!(
                store.accept_signed_snapshot(&raw, 1_500_000, Instant::now()),
                Err(Error::Poisoned)
            ));
        }
        {
            let mut store = open_store(&path, uid, &signer);
            assert_eq!(store.last_trusted_utc(), 1_500_000);
            assert_eq!(store.sequence(), None);
            assert!(matches!(
                store.current_fresh(1_500_000, Instant::now()),
                Err(Error::NotFresh)
            ));
            assert!(matches!(
                store.accept_signed_snapshot(&raw, 1_500_000, Instant::now()),
                Ok(SnapshotResult::Accepted)
            ));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn fresh_capability_rechecks_clock_expiry_and_latch() {
        // All signed times are above the 60 s rollback tolerance so the tests
        // can subtract the tolerance without arithmetic underflow.
        const BASE: u64 = 100_000_000;
        const ACCEPTED: u64 = BASE + 500_000;
        let signer = TestSigner::new(7, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw1 = signer.sign_snapshot(BASE, BASE + 1_500_000, 1, b"a");
        let raw2 = signer.sign_snapshot(BASE + 100_000, BASE + 1_600_000, 2, b"b");
        let start = Instant::now();
        let mut store = open_store(&path, uid, &signer);
        assert!(matches!(
            store.accept_signed_snapshot(&raw1, ACCEPTED, start),
            Ok(SnapshotResult::Accepted)
        ));
        let fresh = store.current_fresh(ACCEPTED, start).unwrap();
        assert!(fresh.check(ACCEPTED, start).is_ok());
        assert!(matches!(
            fresh.check(ACCEPTED, start + Duration::from_micros(1_000_000)),
            Err(Error::NotFresh)
        ));
        assert!(matches!(
            fresh.check(BASE + 1_500_000, start),
            Err(Error::NotFresh)
        ));
        assert!(matches!(
            fresh.check(ACCEPTED - CLOCK_ROLLBACK_TOLERANCE_US - 1, start),
            Err(Error::ClockRollback)
        ));

        // A tolerated rollback is evaluated at the persisted floor, exactly as
        // `current_fresh` does: the same (UTC, mono) pair must both succeed.
        let tolerated = ACCEPTED - CLOCK_ROLLBACK_TOLERANCE_US;
        let fresh = store.current_fresh(tolerated, start).unwrap();
        assert!(fresh.check(tolerated, start).is_ok());

        assert!(matches!(
            store.accept_signed_snapshot(&raw2, BASE + 600_000, start),
            Ok(SnapshotResult::Accepted)
        ));
        let fresh = store.current_fresh(BASE + 600_000, start).unwrap();
        assert!(fresh.check(BASE + 600_000, start).is_ok());
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_unsafe_paths_modes_sizes_and_staging() {
        let signer = TestSigner::new(8, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let lock_path = suffix(&path, ".lock");
        let staging_path = suffix(&path, ".staging");

        assert!(matches!(
            StatusStore::open("relative-status", NET, uid, trust_for(&signer)),
            Err(Error::UnsafePath)
        ));
        assert!(matches!(
            StatusStore::open(&path, NET, uid.wrapping_add(1), trust_for(&signer)),
            Err(Error::UnsafePath)
        ));

        let public = directory.join("public");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            StatusStore::open(public.join("state"), NET, uid, trust_for(&signer)),
            Err(Error::UnsafePath)
        ));
        fs::remove_dir_all(&public).unwrap();

        let link = directory.join("link");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(matches!(
            StatusStore::open(link.join("state"), NET, uid, trust_for(&signer)),
            Err(Error::UnsafePath)
        ));
        fs::remove_file(&link).unwrap();

        let store = open_store(&path, uid, &signer);
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::Busy)
        ));
        drop(store);

        let mut store = open_store(&path, uid, &signer);
        store.observe_trusted_utc(1_000_000).unwrap();
        drop(store);
        let state_bytes = fs::read(&path).unwrap();

        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::UnsafePath)
        ));
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::UnsafePath)
        ));
        fs::remove_file(&path).unwrap();

        fs::write(&path, vec![0u8; MAX_STATUS_STATE_BYTES + 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::TooLarge)
        ));
        fs::remove_file(&path).unwrap();

        fs::write(&staging_path, b"x").unwrap();
        fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::UnsafePath)
        ));
        fs::remove_file(&staging_path).unwrap();

        fs::write(&path, &state_bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&lock_path).unwrap();
        std::os::unix::fs::symlink("missing", &lock_path).unwrap();
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::UnsafePath)
        ));
        fs::remove_file(&lock_path).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn restart_rejects_tampered_raw_metadata_and_network() {
        let signer = TestSigner::new(9, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw = signer.sign_snapshot(1_000_000, 2_000_000, 1, b"a");
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(matches!(
                store.accept_signed_snapshot(&raw, 1_500_000, Instant::now()),
                Ok(SnapshotResult::Accepted)
            ));
        }
        let valid = fs::read(&path).unwrap();

        let mut state = decode(&valid).unwrap();
        state.snapshot.as_mut().unwrap().raw[20] ^= 1;
        write_state(&path, &state);
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::Corrupt)
        ));

        let mut state = decode(&valid).unwrap();
        state.snapshot.as_mut().unwrap().object_id[0] ^= 1;
        write_state(&path, &state);
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::Corrupt)
        ));

        let mut state = decode(&valid).unwrap();
        state.utc_floor = 0;
        write_state(&path, &state);
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::Corrupt)
        ));

        let mut state = decode(&valid).unwrap();
        state.net = [0x44; 16];
        write_state(&path, &state);
        assert!(matches!(
            StatusStore::open(&path, NET, uid, trust_for(&signer)),
            Err(Error::WrongNetwork)
        ));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn wrong_network_authority_and_signatures_fail_closed() {
        let signer = TestSigner::new(10, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw = signer.sign_snapshot(1_000_000, 2_000_000, 1, b"a");

        let wrong_net_signer = TestSigner::new(11, Authority::StatusSigner).with_net([0x43; 16]);
        let raw_wrong_net = wrong_net_signer.sign_snapshot(1_000_000, 2_000_000, 1, b"a");
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(matches!(
                store.accept_signed_snapshot(&raw_wrong_net, 1_500_000, Instant::now()),
                Err(Error::WrongNetwork)
            ));
        }

        let mut signed = SignedObject::decode(&raw).unwrap();
        signed.signers[0].ed25519[0] ^= 1;
        let bad_ed25519 = signed.encode().unwrap();
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(matches!(
                store.accept_signed_snapshot(&bad_ed25519, 1_500_000, Instant::now()),
                Err(Error::BadStatus)
            ));
        }

        let mut signed = SignedObject::decode(&raw).unwrap();
        signed.signers[0].mldsa[0] ^= 1;
        let bad_mldsa = signed.encode().unwrap();
        {
            let mut store = open_store(&path, uid, &signer);
            assert!(matches!(
                store.accept_signed_snapshot(&bad_mldsa, 1_500_000, Instant::now()),
                Err(Error::BadStatus)
            ));
        }

        let wrong_authority = TestSigner::new(12, Authority::IdentityAuthority);
        let raw_wrong_authority = wrong_authority.sign_snapshot(1_000_000, 2_000_000, 1, b"a");
        let authority_path = directory.join("authority-state");
        let mut store =
            StatusStore::open(&authority_path, NET, uid, trust_for(&wrong_authority)).unwrap();
        assert!(matches!(
            store.accept_signed_snapshot(&raw_wrong_authority, 1_500_000, Instant::now()),
            Err(Error::BadStatus)
        ));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn different_signer_same_sequence_is_not_frozen_as_equivocation() {
        let first = TestSigner::new(20, Authority::StatusSigner);
        let second = TestSigner::new(21, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let raw_first = first.sign_snapshot(1_000_000, 3_000_000, 1, b"a");
        let raw_second_same = second.sign_snapshot(1_000_000, 3_000_000, 1, b"b");
        let raw_second_next = second.sign_snapshot(1_100_000, 3_100_000, 2, b"c");
        let mut store = StatusStore::open(&path, NET, uid, trust_with(&[&first, &second])).unwrap();
        assert!(matches!(
            store.accept_signed_snapshot(&raw_first, 1_500_000, Instant::now()),
            Ok(SnapshotResult::Accepted)
        ));
        assert!(matches!(
            store.accept_signed_snapshot(&raw_second_same, 1_500_000, Instant::now()),
            Err(Error::BadStatus)
        ));
        assert!(!store.is_frozen());
        assert_eq!(store.sequence(), Some(1));
        assert!(matches!(
            store.accept_signed_snapshot(&raw_second_next, 1_500_000, Instant::now()),
            Ok(SnapshotResult::Accepted)
        ));
        assert_eq!(store.sequence(), Some(2));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn codec_roundtrip_and_trailing_bytes() {
        let mut state = State::empty(NET);
        state.utc_floor = 123;
        state.rollback_latched = true;
        let bytes = encode(&state).unwrap();
        // A non-empty in-memory model must not change the v1 image or add a flag.
        let mut model_only = state.clone();
        model_only.revocation.scopes.push(RevokedScope {
            class: IssuerClass::Identity,
            origin_core: 0,
            node_id: 0x0207,
            generation: 1,
            target_id: 0,
            epoch: 1,
            digest: [0x55; 32],
        });
        assert_eq!(encode(&model_only).unwrap(), bytes);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.net, NET);
        assert_eq!(decoded.utc_floor, 123);
        assert!(decoded.rollback_latched);
        assert!(decoded.snapshot.is_none());
        assert!(decoded.equivocation.is_none());
        assert!(decoded.revocation.scopes.is_empty());
        assert!(decoded.revocation.conflict.is_none());
        let mut extra = bytes;
        extra.push(0);
        assert!(matches!(decode(&extra), Err(Error::Corrupt)));
    }

    #[test]
    fn revocations_require_relay_policy_and_dual_signatures() {
        let signer = TestSigner::new(30, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let node = 0x0207;
        let revocations = payload_bytes(vec![
            entry(IssuerClass::Identity, 0, node, 2, 0, 1),
            entry(IssuerClass::Core, 3, node, 2, 0, 1),
        ]);
        let raw = signer.sign_snapshot_with_revocations(1_000_000, 3_000_000, 1, &revocations);

        // `open` refuses every class, so nothing is consumed.
        let mut refused = open_store(&path, uid, &signer);
        let result = refused.accept_signed_snapshot(&raw, 1_500_000, Instant::now());
        assert!(matches!(result, Err(Error::RevocationPermission)));
        assert_eq!(refused.revoked_scope_count(), 0);
        assert_eq!(refused.sequence(), None);
        drop(refused);

        let mut store = open_relay_store(&path, uid, &signer, ALL);
        let result = store.accept_signed_snapshot(&raw, 1_500_000, Instant::now());
        assert!(matches!(result, Ok(SnapshotResult::Accepted)));
        assert_eq!(store.revoked_scope_count(), 2);

        let verdict = store.peer_revocation(&peer(node, 2));
        let PeerRevocation::Verified(state) = verdict else {
            panic!("verified revocation state expected");
        };
        assert!(state.identity);
        assert!(state.core);
        assert!(!state.route);
        assert!(!state.direct);
        assert!(state.sessions_revoked());
        assert_eq!(state.sequence, 1);

        // A newer identity generation of the same node is not covered.
        let newer = store.peer_revocation(&peer(node, 3));
        let PeerRevocation::Verified(newer) = newer else {
            panic!("verified revocation state expected");
        };
        assert!(!newer.any());

        // Bad ML-DSA or bad Ed25519 signature: refused, state unchanged.
        let mut signed = SignedObject::decode(&raw).unwrap();
        signed.signers[0].mldsa[0] ^= 1;
        let bad_mldsa = signed.encode().unwrap();
        let result = store.accept_signed_snapshot(&bad_mldsa, 1_500_000, Instant::now());
        assert!(matches!(result, Err(Error::BadStatus)));
        let mut signed = SignedObject::decode(&raw).unwrap();
        signed.signers[0].ed25519[0] ^= 1;
        let bad_ed25519 = signed.encode().unwrap();
        let result = store.accept_signed_snapshot(&bad_ed25519, 1_500_000, Instant::now());
        assert!(matches!(result, Err(Error::BadStatus)));
        assert_eq!(store.revoked_scope_count(), 2);
        assert_eq!(store.sequence(), Some(1));
        drop(store);

        // Restart rebuilds the decisions from the persisted signed snapshot and
        // re-verifies that envelope.
        let store = open_relay_store(&path, uid, &signer, ALL);
        assert_eq!(store.revoked_scope_count(), 2);
        let verdict = store.peer_revocation(&peer(node, 2));
        let PeerRevocation::Verified(state) = verdict else {
            panic!("verified revocation state expected");
        };
        assert!(state.sessions_revoked());
        drop(store);

        // A tightened policy refuses the rebuilt classes instead of keeping them.
        let tightened = try_open_relay(
            &path,
            uid,
            &signer,
            RevocationRelayPolicy {
                identity: true,
                ..RevocationRelayPolicy::none()
            },
        );
        assert!(matches!(tightened, Err(Error::RevocationPermission)));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn revocation_epochs_are_monotone_and_conflicts_latch() {
        let signer = TestSigner::new(31, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let node = 0x0207;
        let first = signer.sign_snapshot_with_revocations(
            1_000_000,
            9_000_000,
            1,
            &payload_bytes(vec![entry(IssuerClass::Identity, 0, node, 2, 0, 5)]),
        );
        let stale = signer.sign_snapshot_with_revocations(
            1_100_000,
            9_000_000,
            2,
            &payload_bytes(vec![entry(IssuerClass::Identity, 0, node, 2, 0, 4)]),
        );
        let replay = signer.sign_snapshot_with_revocations(
            1_200_000,
            9_000_000,
            3,
            &payload_bytes(vec![entry(IssuerClass::Identity, 0, node, 2, 0, 5)]),
        );
        let conflicting = RevocationEntry::new(IssuerClass::Identity, 0, node, 2, 0, 5, 2).unwrap();
        let conflict = signer.sign_snapshot_with_revocations(
            1_300_000,
            9_000_000,
            4,
            &payload_bytes(vec![conflicting]),
        );

        let mut store = open_relay_store(&path, uid, &signer, ALL);
        let result = store.accept_signed_snapshot(&first, 1_500_000, Instant::now());
        assert!(matches!(result, Ok(SnapshotResult::Accepted)));
        assert_eq!(store.sequence(), Some(1));

        // A lower epoch for the same scope is refused and changes nothing.
        let result = store.accept_signed_snapshot(&stale, 1_500_000, Instant::now());
        assert!(matches!(result, Err(Error::RevocationStale)));
        assert_eq!(store.sequence(), Some(1));
        assert_eq!(store.revoked_scope_count(), 1);
        assert_eq!(store.revocation_scopes()[0].epoch, 5);

        // Re-delivering the same decision at a higher sequence is idempotent.
        let result = store.accept_signed_snapshot(&replay, 1_500_000, Instant::now());
        assert!(matches!(result, Ok(SnapshotResult::Accepted)));
        assert_eq!(store.sequence(), Some(3));
        assert_eq!(store.revoked_scope_count(), 1);
        assert_eq!(store.revocation_scopes()[0].epoch, 5);

        // Same scope and epoch with different bytes latches in-memory evidence.
        let result = store.accept_signed_snapshot(&conflict, 1_500_000, Instant::now());
        assert!(matches!(result, Err(Error::RevocationConflict)));
        assert!(store.is_frozen());
        assert!(store.is_revocation_conflicted());
        let evidence = store.revocation_conflict().expect("latched conflict");
        assert_eq!(evidence.scope.epoch, 5);
        assert_ne!(evidence.first_digest, evidence.second_digest);
        assert_eq!(store.sequence(), Some(3));
        drop(store);

        // The conflict latch is not persisted. Reopening rebuilds only the latest
        // signed snapshot (`replay`), so no digest-only historical scope or latch
        // is presented as verified.
        let mut store = open_relay_store(&path, uid, &signer, ALL);
        assert!(!store.is_revocation_conflicted());
        assert!(!store.is_frozen());
        assert_eq!(store.revoked_scope_count(), 1);
        assert!(matches!(
            store.accept_signed_snapshot(&replay, 1_500_000, Instant::now()),
            Ok(SnapshotResult::DuplicateNotRenewed)
        ));
        let verdict = store.peer_revocation(&peer(node, 2));
        let PeerRevocation::Verified(state) = verdict else {
            panic!("latest signed snapshot should rebuild a verified scope");
        };
        assert!(state.identity);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn revocation_state_bound_is_enforced() {
        let signer = TestSigner::new(32, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let mut full = Vec::new();
        for index in 0..MAX_REVOCATION_SCOPES {
            let node = 0x0202 + index as u16;
            full.push(entry(IssuerClass::Identity, 0, node, 1, 0, 1));
        }
        let first =
            signer.sign_snapshot_with_revocations(1_000_000, 9_000_000, 1, &payload_bytes(full));
        let extra = signer.sign_snapshot_with_revocations(
            1_100_000,
            9_000_000,
            2,
            &payload_bytes(vec![entry(IssuerClass::Identity, 0, 0x0242, 1, 0, 1)]),
        );
        let mut store = open_relay_store(&path, uid, &signer, ALL);
        let result = store.accept_signed_snapshot(&first, 1_500_000, Instant::now());
        assert!(matches!(result, Ok(SnapshotResult::Accepted)));
        assert_eq!(store.revoked_scope_count(), MAX_REVOCATION_SCOPES);
        let result = store.accept_signed_snapshot(&extra, 1_500_000, Instant::now());
        assert!(matches!(result, Err(Error::RevocationTooLarge)));
        assert_eq!(store.revoked_scope_count(), MAX_REVOCATION_SCOPES);
        assert_eq!(store.sequence(), Some(1));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn revocation_queries_fail_closed_without_verified_state() {
        let signer = TestSigner::new(33, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        let mut store = open_relay_store(&path, uid, &signer, ALL);
        assert_eq!(
            store.peer_revocation(&peer(0x0207, 1)),
            PeerRevocation::Unknown(RevocationUnknown::NoSnapshot)
        );
        let raw = signer.sign_snapshot_with_revocations(
            1_000_000,
            9_000_000,
            1,
            &payload_bytes(vec![entry(IssuerClass::Identity, 0, 0x0207, 1, 0, 1)]),
        );
        let result = store.accept_signed_snapshot(&raw, 1_500_000, Instant::now());
        assert!(matches!(result, Ok(SnapshotResult::Accepted)));
        assert_eq!(
            store.peer_revocation(&peer(0x0208, 1)),
            PeerRevocation::Verified(PeerRevocationState {
                sequence: 1,
                identity: false,
                core: false,
                route: false,
                direct: false,
            })
        );
        let foreign = AuthenticatedPeer::new([0x43; 16], 0x0207, 1).unwrap();
        assert_eq!(
            store.peer_revocation(&foreign),
            PeerRevocation::Unknown(RevocationUnknown::WrongNetwork)
        );
        assert!(store.observe_trusted_utc(100_000_000_000).is_ok());
        let result = store.observe_trusted_utc(1_000_000);
        assert!(matches!(result, Err(Error::ClockRollback)));
        assert_eq!(
            store.peer_revocation(&peer(0x0207, 1)),
            PeerRevocation::Unknown(RevocationUnknown::ClockLatched)
        );
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn revocation_state_is_not_persisted_and_rebuilds_only_latest_snapshot() {
        let signer = TestSigner::new(34, Authority::StatusSigner);
        let (directory, path) = dir();
        let uid = owner(&directory);
        // First payload revokes node A. It is retained in memory after a later
        // payload omits it, but the image must not carry it.
        let first = signer.sign_snapshot_with_revocations(
            1_000_000,
            9_000_000,
            1,
            &payload_bytes(vec![entry(IssuerClass::Identity, 0, 0x0207, 2, 0, 1)]),
        );
        let second = signer.sign_snapshot_with_revocations(
            1_100_000,
            9_000_000,
            2,
            &payload_bytes(vec![entry(IssuerClass::Identity, 0, 0x0208, 2, 0, 1)]),
        );
        {
            let mut store = open_relay_store(&path, uid, &signer, ALL);
            assert!(matches!(
                store.accept_signed_snapshot(&first, 1_500_000, Instant::now()),
                Ok(SnapshotResult::Accepted)
            ));
            assert_eq!(store.revoked_scope_count(), 1);
            assert!(matches!(
                store.accept_signed_snapshot(&second, 1_500_000, Instant::now()),
                Ok(SnapshotResult::Accepted)
            ));
            // In-memory union: the omission did not withdraw node A.
            assert_eq!(store.revoked_scope_count(), 2);
        }

        // The durable image is exactly the pre-feature v1 image: no revocations,
        // no conflict block and no new flag. A digest-only historical scope is
        // therefore never reopened as verified.
        let image = fs::read(&path).unwrap();
        let decoded = decode(&image).unwrap();
        assert!(decoded.revocation.scopes.is_empty());
        assert!(decoded.revocation.conflict.is_none());
        assert_eq!(image, encode(&decoded).unwrap());

        // Reopening rebuilds only entries in the persisted `second` snapshot.
        let store = open_relay_store(&path, uid, &signer, ALL);
        assert_eq!(store.revoked_scope_count(), 1);
        let PeerRevocation::Verified(older) = store.peer_revocation(&peer(0x0207, 2)) else {
            panic!("a verified answer describes the rebuilt model state");
        };
        assert!(!older.any(), "node A is not in the latest signed snapshot");
        let PeerRevocation::Verified(newer) = store.peer_revocation(&peer(0x0208, 2)) else {
            panic!("node B is in the latest signed snapshot");
        };
        assert!(newer.identity);
        drop(store);

        // An image written before this feature (empty payload) still opens and
        // claims no revocation.
        let legacy_raw = signer.sign_snapshot(1_000_000, 9_000_000, 1, b"");
        let signed = SignedObject::decode(&legacy_raw).unwrap();
        let mut legacy = State::empty(NET);
        legacy.utc_floor = 1_500_000;
        legacy.snapshot = Some(Snapshot {
            issuer: signer.key_id.clone(),
            generation: 1,
            seq: 1,
            object_id: sha256(&signed.raw_tbs).unwrap(),
            issued: 1_000_000,
            next: 9_000_000,
            raw: legacy_raw,
        });
        write_state(&path, &legacy);
        let store = try_open_relay(&path, uid, &signer, ALL).unwrap();
        assert_eq!(store.revoked_scope_count(), 0);
        assert!(matches!(
            store.peer_revocation(&peer(0x0207, 2)),
            PeerRevocation::Verified(_)
        ));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_tests {
    use super::*;
    use crate::management::ManagementTrust;

    #[test]
    fn durable_operations_are_unsupported_without_linux() {
        assert!(matches!(
            StatusStore::open("unused", [7; 16], 0, ManagementTrust::new([7; 16])),
            Err(Error::Unsupported)
        ));
    }
}
