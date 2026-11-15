//! Durable enrollment transaction engine.
//!
//! This module does no CSR parsing or signature verification. The claim API accepts an
//! opaque verified-request token with private fields and no production constructor; it cannot
//! be made from an untrusted boolean. Until the reviewed CSR/signing integration is added,
//! production enrollment cannot be completed through this module.
//! The journal protects transaction consistency/torn writes, not against a malicious local
//! filesystem administrator or arbitrary journal rewriting.
//!
//! Durability is platform-scoped: Unix fsyncs the parent directory after creating/removing
//! journal and lock entries. Windows currently syncs file data only and does not flush
//! directory entries, so [`EnrollmentStore::directory_entry_durability_guaranteed`] reports
//! `false` there and the Windows crash-durability gate remains open.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;

#[cfg(feature = "openssl-backend")]
use openssl::hash::{MessageDigest, hash};
#[cfg(feature = "openssl-backend")]
use openssl::pkey::KeyType;
#[cfg(feature = "openssl-backend")]
use openssl::x509::X509Req;

const MAGIC: &[u8; 4] = b"BENR";
const VERSION: u8 = 2;
const MAX_FRAME: usize = 40 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 16_384;
const MAX_INVITES: usize = 100_000;
const MAX_SLOTS: usize = 4_016;
pub const MAX_CSR_BYTES: usize = 16 * 1024;
pub const RECOVERY_WINDOW_US: u64 = 24 * 60 * 60 * 1_000_000;

/// Candidate CSR policy for the phase-0/offline Ed25519 management-key proof.
///
/// The OID is deployment configuration, not a protocol constant. Tests and offline
/// provisioning may use an explicitly unregistered candidate OID; production must replace
/// it with a formally assigned enterprise OID (gate tracked in the ADR).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsrPolicy {
    ed25519_pop_oid: Option<String>,
}
impl CsrPolicy {
    pub const fn disabled() -> Self {
        Self {
            ed25519_pop_oid: None,
        }
    }
    pub fn with_ed25519_pop_oid(oid: impl Into<String>) -> Result<Self, EnrollmentError> {
        let oid = oid.into();
        if oid.is_empty()
            || oid.len() > 128
            || oid.starts_with('.')
            || oid.ends_with('.')
            || !oid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return Err(EnrollmentError::InvalidCsrPolicy);
        }
        Ok(Self {
            ed25519_pop_oid: Some(oid),
        })
    }
    pub fn ed25519_pop_oid(&self) -> Option<&str> {
        self.ed25519_pop_oid.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum NodeRole {
    Edge = 1,
    Core = 2,
    EnrollmentService = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Slot {
    pub home_core_id: u8,
    pub vip_octet: u8,
    pub role: NodeRole,
}
impl Slot {
    fn node_id(self) -> Result<u16, EnrollmentError> {
        if !(1..=16).contains(&self.home_core_id) {
            return Err(EnrollmentError::InvalidSlot);
        }
        match self.role {
            NodeRole::Core if self.vip_octet != 1 => return Err(EnrollmentError::InvalidSlot),
            NodeRole::Edge if !(2..=251).contains(&self.vip_octet) => {
                return Err(EnrollmentError::InvalidSlot);
            }
            NodeRole::EnrollmentService => return Err(EnrollmentError::InvalidSlot),
            _ => (),
        }
        Ok(((u16::from(self.home_core_id) - 1) << 8) | u16::from(self.vip_octet))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InviteSpec {
    pub invite_id: [u8; 16],
    pub expires_at_us: u64,
    /// Role permitted by this bearer invitation.
    pub role: NodeRole,
    /// Permanent home-core scope; never current attachment core.
    pub home_core_id: u8,
    /// 256-bit bearer secret provisioned out of band. This draft compares it directly;
    /// production integration should provision it from a protected secret store.
    pub bearer_secret: [u8; 32],
}

/// A caller-asserted monotonic writer epoch.
///
/// This is an assertion, not proof of exclusive ownership. The journal can reject an
/// epoch lower than the highest one it has durably observed, but it cannot authenticate
/// who issued the epoch or prevent two writers that were both given epoch N from running.
/// Deployments **must** obtain the epoch from a durable external fencing authority
/// (for example a control-plane lease service) after partitioning every older writer.
/// It must never be derived from wall time, a PID, a random nonce, or local configuration:
/// inventing a locally larger number defeats the only protection this type can offer.
///
/// The public constructor exists because an external integration must be able to pass the
/// authority-issued value in; it deliberately does not validate the source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriterFence {
    epoch: u64,
}
impl WriterFence {
    /// Wraps an epoch obtained from an independent, durable fencing authority.
    ///
    /// The caller is responsible for exclusive ownership; this constructor does not
    /// authenticate the authority or validate that older writers have been fenced.
    pub const fn from_external_authority(epoch: u64) -> Self {
        Self { epoch }
    }
    /// The externally issued epoch, for diagnostics and journal correlation.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
    #[cfg(test)]
    const fn from_authority(epoch: u64) -> Self {
        Self { epoch }
    }
}

/// Exists only after a future CSR parser/verifier has checked the exact DER CSR proof of
/// possession and established invite/role policy. No public unchecked constructor exists.
#[derive(Clone)]
pub struct VerifiedEnrollmentRequest {
    invite_id: [u8; 16],
    enrollment_id: [u8; 16],
    bearer_secret: [u8; 32],
    raw_csr_sha256: [u8; 32],
    raw_csr_der: Vec<u8>,
    role: NodeRole,
    home_core_id: u8,
    identity_pub_ed25519: [u8; 32],
}
impl fmt::Debug for VerifiedEnrollmentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedEnrollmentRequest")
            .field("invite_id", &self.invite_id)
            .field("enrollment_id", &self.enrollment_id)
            .field("bearer_secret", &"[REDACTED]")
            .field("raw_csr_sha256", &self.raw_csr_sha256)
            .field("raw_csr_len", &self.raw_csr_der.len())
            .field("role", &self.role)
            .field("home_core_id", &self.home_core_id)
            .field("identity_pub_ed25519", &self.identity_pub_ed25519)
            .finish()
    }
}
#[cfg(any(feature = "openssl-backend", test))]
struct VerifiedCsrFields {
    invite_id: [u8; 16],
    enrollment_id: [u8; 16],
    bearer_secret: [u8; 32],
    raw_csr_der: Vec<u8>,
    raw_csr_sha256: [u8; 32],
    role: NodeRole,
    home_core_id: u8,
    identity_pub_ed25519: [u8; 32],
}

impl VerifiedEnrollmentRequest {
    /// Internal verifier boundary: future CSR integration must hash exact DER and verify its
    /// proof-of-possession before constructing this type. Unit tests alone can bypass that.
    /// Only the in-crate CSR verifier may construct a request after cryptographic validation.
    #[cfg(any(feature = "openssl-backend", test))]
    fn from_verified_csr(fields: VerifiedCsrFields) -> Result<Self, EnrollmentError> {
        let VerifiedCsrFields {
            invite_id,
            enrollment_id,
            bearer_secret,
            raw_csr_der,
            raw_csr_sha256,
            role,
            home_core_id,
            identity_pub_ed25519,
        } = fields;
        if raw_csr_der.is_empty() || raw_csr_der.len() > MAX_CSR_BYTES {
            return Err(EnrollmentError::CsrTooLarge);
        }
        if identity_pub_ed25519 == [0; 32] {
            return Err(EnrollmentError::InvalidIdentityKey);
        }
        Ok(Self {
            invite_id,
            enrollment_id,
            bearer_secret,
            raw_csr_sha256,
            raw_csr_der,
            role,
            home_core_id,
            identity_pub_ed25519,
        })
    }
    #[cfg(test)]
    fn test_request(fields: VerifiedCsrFields) -> Result<Self, EnrollmentError> {
        Self::from_verified_csr(fields)
    }
}

/// Identity bytes must be the exact signed result produced by the later IdentityAuthority
/// signing layer. The type has no public constructor and is persisted verbatim once issued.
#[derive(Clone, Debug)]
pub struct SignedIdentityResult {
    raw_signed_bytes: Vec<u8>,
}
impl SignedIdentityResult {
    // The enrollment journal cannot call the feature-gated signer yet. Keep the
    // constructor so the signing slice can wire it without a dead_code failure
    // on the default (backend-free) workspace build.
    #[allow(dead_code)]
    fn from_identity_authority(raw_signed_bytes: Vec<u8>) -> Result<Self, EnrollmentError> {
        // The master plan caps one signed management object at 16 KiB total, including
        // signatures and container headers, not 16 KiB of TBS plus signatures.
        if raw_signed_bytes.is_empty() || raw_signed_bytes.len() > 16 * 1024 {
            return Err(EnrollmentError::InvalidSignedResult);
        }
        Ok(Self { raw_signed_bytes })
    }
    /// The exact signed object bytes persisted by the journal. Decode them with the
    /// management-object parser before treating any embedded field as authoritative.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw_signed_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentPhase {
    Prepared,
    Issued,
    Delivered,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentResult {
    pub phase: EnrollmentPhase,
    pub node_id: u16,
    pub slot: Slot,
    pub identity_generation: u64,
    pub signed_identity: Option<Vec<u8>>,
    pub recovery_until_us: u64,
}
/// Validity and role-scope material supplied by the enrolling deployment.
/// The IdentityAuthority signs these exact values into the NodeIdentity object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityValidity {
    pub not_before_us: u64,
    pub expires_us: u64,
    /// Role/prefix authorization scope bytes, at most 1024 bytes.
    pub scope: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Tx {
    result: EnrollmentResult,
    invite_id: [u8; 16],
    enrollment_id: [u8; 16],
    csr_hash: [u8; 32],
    csr_der: Vec<u8>,
    identity_pub_ed25519: [u8; 32],
}

#[derive(Debug)]
pub enum EnrollmentError {
    Io(io::Error),
    BusyLock,
    StaleFence,
    StorePoisoned,
    InvalidSlot,
    InvalidInvite,
    InviteExpired,
    InviteBoundToDifferentRequest,
    InviteRecoveryExpired,
    InvalidBearerSecret,
    InviteScopeMismatch,
    CapacityExhausted,
    TransactionNotFound,
    WrongPhase,
    InvalidSignedResult,
    CsrTooLarge,
    InvalidCsr,
    UnsupportedCsrKey,
    CsrProofOfPossession,
    InvalidCsrPolicy,
    CsrPolicyMissing,
    InvalidCsrExtension,
    Ed25519ProofOfPossession,
    InvalidIdentityKey,
    IdentityAuthorityRejected,
    InvalidIdentityValidity,
    StoreFull,
    CorruptJournal,
    UnsupportedVersion,
    UnsafeStoragePath,
}
impl From<io::Error> for EnrollmentError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Store is single-process mutable and guarded by an OS advisory exclusive lock on a
/// sidecar file. The kernel releases the lock when the holding process exits or is killed,
/// so a `SIGKILL` does not permanently wedge recovery. The lock file itself is intentionally
/// left in place: unlinking a still-locked inode can let a new writer create a different
/// inode while an old writer holds the old one. The lock does not replace the independent
/// fencing epoch, which still rejects a restored stale writer after an old process dies.
pub struct EnrollmentStore {
    path: PathBuf,
    journal: File,
    _lock: Option<File>,
    fence: u64,
    provided_fence: u64,
    poisoned: bool,
    record_count: usize,
    #[cfg(test)]
    fail_next_write: bool,
    invites: BTreeMap<[u8; 16], InviteSpec>,
    slots: Vec<Slot>,
    used_slots: BTreeSet<u16>,
    generations: BTreeMap<u16, u64>,
    transactions: BTreeMap<([u8; 16], [u8; 16]), Tx>,
    invite_bindings: BTreeMap<[u8; 16], ([u8; 16], [u8; 32])>,
    /// Durable per-home-core allocation watermark. It only moves forward and is
    /// recovered from the journal before any new allocation is attempted.
    allocation_watermarks: BTreeMap<u8, u64>,
    #[cfg(feature = "openssl-backend")]
    csr_policy: CsrPolicy,
}
impl fmt::Debug for EnrollmentStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentStore")
            .field("fence", &self.fence)
            .field("poisoned", &self.poisoned)
            .field("record_count", &self.record_count)
            .field("invite_count", &self.invites.len())
            .field("slot_count", &self.slots.len())
            .field("transaction_count", &self.transactions.len())
            .field("allocation_watermarks", &self.allocation_watermarks)
            .finish()
    }
}
impl EnrollmentStore {
    pub fn open(
        path: impl AsRef<Path>,
        fence: WriterFence,
        invites: Vec<InviteSpec>,
        slots: Vec<Slot>,
    ) -> Result<Self, EnrollmentError> {
        Self::open_with_csr_policy(path, fence, invites, slots, CsrPolicy::disabled())
    }

    /// Open with an explicit CSR Ed25519 management-key policy.
    ///
    /// `CsrPolicy::disabled()` deliberately rejects CSR-based Ed binding; production online
    /// enrollment must opt in with a formally assigned OID and a reviewed registration design.
    /// The candidate extension parser is for controlled/offline provisioning evidence first.
    pub fn open_with_csr_policy(
        path: impl AsRef<Path>,
        fence: WriterFence,
        invites: Vec<InviteSpec>,
        slots: Vec<Slot>,
        csr_policy: CsrPolicy,
    ) -> Result<Self, EnrollmentError> {
        if fence.epoch == 0 {
            return Err(EnrollmentError::StaleFence);
        }
        let path = canonical_storage_path(path.as_ref())?;
        let lock_path = suffix_path(&path, ".writer-lock");
        let mut lock_options = OpenOptions::new();
        // read+write is required by Windows LockFileEx. create(true) reuses an existing
        // lock file, which is intentionally persistent and not a crash sentinel.
        lock_options.read(true).write(true).create(true);
        #[cfg(unix)]
        lock_options.mode(0o600);
        let lock = lock_options.open(&lock_path)?;
        validate_open_file(&lock_path, &lock)?;
        match lock.try_lock() {
            Ok(()) => (),
            Err(std::fs::TryLockError::WouldBlock) => {
                drop(lock);
                return Err(EnrollmentError::BusyLock);
            }
            Err(std::fs::TryLockError::Error(error)) => {
                drop(lock);
                return Err(EnrollmentError::Io(error));
            }
        }
        sync_parent_dir(&lock_path)?;
        match Self::open_locked(path, lock, fence, invites, slots, csr_policy) {
            Ok(mut store) => {
                if store.provided_fence < store.fence {
                    drop(store);
                    return Err(EnrollmentError::StaleFence);
                }
                if store.provided_fence > store.fence {
                    store.fence = store.provided_fence;
                    let epoch = store.fence;
                    store.append_event(Event::Fence { epoch })?;
                    sync_parent_dir(&store.path)?;
                }
                Ok(store)
            }
            Err(error) => {
                // The OS lock is released when `lock`/store drops; the lock file stays so a
                // retry opens the same inode instead of racing an unlink.
                Err(error)
            }
        }
    }

    fn open_locked(
        path: PathBuf,
        lock: File,
        fence: WriterFence,
        invites: Vec<InviteSpec>,
        slots: Vec<Slot>,
        csr_policy: CsrPolicy,
    ) -> Result<Self, EnrollmentError> {
        #[cfg(not(feature = "openssl-backend"))]
        let _ = csr_policy;
        if invites.len() > MAX_INVITES || slots.len() > MAX_SLOTS {
            return Err(EnrollmentError::StoreFull);
        }
        let mut invite_map = BTreeMap::new();
        for invite in invites {
            if invite.expires_at_us == 0 || invite_map.insert(invite.invite_id, invite).is_some() {
                return Err(EnrollmentError::InvalidInvite);
            }
        }
        let mut slot_set = BTreeSet::new();
        for slot in &slots {
            let id = slot.node_id()?;
            if !slot_set.insert(id) {
                return Err(EnrollmentError::InvalidSlot);
            }
        }
        let mut journal_options = OpenOptions::new();
        journal_options.read(true).write(true).create(true);
        #[cfg(unix)]
        journal_options.mode(0o600);
        let journal = journal_options.open(&path)?;
        validate_open_file(&path, &journal)?;
        let mut store = Self {
            path,
            journal,
            _lock: Some(lock),
            fence: 0,
            provided_fence: fence.epoch,
            poisoned: false,
            record_count: 0,
            #[cfg(test)]
            fail_next_write: false,
            invites: invite_map,
            slots,
            used_slots: BTreeSet::new(),
            generations: BTreeMap::new(),
            transactions: BTreeMap::new(),
            invite_bindings: BTreeMap::new(),
            allocation_watermarks: BTreeMap::new(),
            #[cfg(feature = "openssl-backend")]
            csr_policy,
        };
        store.recover()?;
        Ok(store)
    }

    pub fn claim(
        &mut self,
        req: VerifiedEnrollmentRequest,
        now_us: u64,
    ) -> Result<EnrollmentResult, EnrollmentError> {
        self.ensure_healthy()?;
        if req.raw_csr_der.is_empty() || req.raw_csr_der.len() > MAX_CSR_BYTES {
            return Err(EnrollmentError::CsrTooLarge);
        }
        let pair = (req.invite_id, req.enrollment_id);
        let invite = *self
            .invites
            .get(&req.invite_id)
            .ok_or(EnrollmentError::InvalidInvite)?;
        if !secret_bytes_equal(&invite.bearer_secret, &req.bearer_secret) {
            return Err(EnrollmentError::InvalidBearerSecret);
        }
        if invite.role != req.role || invite.home_core_id != req.home_core_id {
            return Err(EnrollmentError::InviteScopeMismatch);
        }
        if let Some(tx) = self.transactions.get(&pair) {
            if tx.csr_hash != req.raw_csr_sha256
                || tx.csr_der != req.raw_csr_der
                || tx.identity_pub_ed25519 != req.identity_pub_ed25519
            {
                return Err(EnrollmentError::InviteBoundToDifferentRequest);
            }
            if now_us > tx.result.recovery_until_us {
                return Err(EnrollmentError::InviteRecoveryExpired);
            }
            return Ok(tx.result.clone());
        }
        if now_us >= invite.expires_at_us {
            return Err(EnrollmentError::InviteExpired);
        }
        if self.invite_bindings.contains_key(&req.invite_id) {
            return Err(EnrollmentError::InviteBoundToDifferentRequest);
        }
        let slot = self
            .slots
            .iter()
            .copied()
            .find(|s| {
                s.role == req.role
                    && s.home_core_id == req.home_core_id
                    && s.node_id().is_ok_and(|id| !self.used_slots.contains(&id))
            })
            .ok_or(EnrollmentError::CapacityExhausted)?;
        let node_id = slot.node_id()?;
        let generation = self
            .generations
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(EnrollmentError::InvalidSlot)?;
        let result = EnrollmentResult {
            phase: EnrollmentPhase::Prepared,
            node_id,
            slot,
            identity_generation: generation,
            signed_identity: None,
            recovery_until_us: invite.expires_at_us.saturating_add(RECOVERY_WINDOW_US),
        };
        if self.record_count >= MAX_RECORDS.saturating_sub(1) {
            return Err(EnrollmentError::StoreFull);
        }
        let watermark = self
            .allocation_watermarks
            .get(&invite.home_core_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(EnrollmentError::StoreFull)?;
        let tx = Tx {
            result: result.clone(),
            invite_id: req.invite_id,
            enrollment_id: req.enrollment_id,
            csr_hash: req.raw_csr_sha256,
            csr_der: req.raw_csr_der.clone(),
            identity_pub_ed25519: req.identity_pub_ed25519,
        };
        // The watermark is a separate durable record written before the binding.
        // A crash after this write may skip a number, but can never move backwards.
        self.append_event(Event::AllocationWatermark {
            fence: self.fence,
            home_core_id: invite.home_core_id,
            watermark,
        })?;
        self.allocation_watermarks
            .insert(invite.home_core_id, watermark);
        self.append_event(Event::Prepared {
            fence: self.fence,
            tx: tx.clone(),
        })?;
        self.apply_prepared(tx);
        Ok(result)
    }

    /// Durable, monotonically increasing allocation watermark for one home-core block.
    /// It survives torn writes and restart; a restored stale disk that cannot present a
    /// watermark at least this high must be fenced off rather than allowed to allocate.
    pub fn allocation_watermark(&self, home_core_id: u8) -> Result<u64, EnrollmentError> {
        if !(1..=16).contains(&home_core_id) {
            return Err(EnrollmentError::InvalidSlot);
        }
        Ok(self
            .allocation_watermarks
            .get(&home_core_id)
            .copied()
            .unwrap_or(0))
    }

    /// Whether this platform implements the parent-directory fsync required for
    /// crash-durable rename/create of a new journal or lock entry.
    ///
    /// This is `true` only on Unix. On Windows the implementation currently syncs file
    /// data but returns without a directory-entry flush; that platform gate is **not**
    /// passed, and a production deployment must not claim crash durability for a newly
    /// created journal there. A future implementation may use a documented Windows
    /// directory-handle flush strategy, but it must not be inferred from file `sync_all`.
    pub const fn directory_entry_durability_guaranteed() -> bool {
        cfg!(unix)
    }

    /// Canonical journal path selected after resolving the storage directory.
    pub fn journal_path(&self) -> &Path {
        &self.path
    }

    pub fn mark_issued(
        &mut self,
        invite_id: [u8; 16],
        enrollment_id: [u8; 16],
        now_us: u64,
        signed: SignedIdentityResult,
    ) -> Result<EnrollmentResult, EnrollmentError> {
        self.ensure_healthy()?;
        let key = (invite_id, enrollment_id);
        let old = self
            .transactions
            .get(&key)
            .cloned()
            .ok_or(EnrollmentError::TransactionNotFound)?;
        if now_us > old.result.recovery_until_us {
            return Err(EnrollmentError::InviteRecoveryExpired);
        }
        if let Some(existing) = &old.result.signed_identity {
            if existing == &signed.raw_signed_bytes {
                return Ok(old.result);
            }
            return Err(EnrollmentError::WrongPhase);
        }
        if old.result.phase != EnrollmentPhase::Prepared {
            return Err(EnrollmentError::WrongPhase);
        }
        let mut next = old.clone();
        next.result.phase = EnrollmentPhase::Issued;
        next.result.signed_identity = Some(signed.raw_signed_bytes);
        self.append_event(Event::Issued {
            fence: self.fence,
            tx: next.clone(),
        })?;
        self.transactions.insert(key, next.clone());
        Ok(next.result)
    }

    /// Recover the exact prepared DER CSR for the IdentityAuthority signing stage.
    /// Requires the invitation bearer secret; this does not validate CSR signatures.
    pub fn raw_csr_for_signing(
        &self,
        invite_id: [u8; 16],
        enrollment_id: [u8; 16],
        bearer_secret: &[u8; 32],
        now_us: u64,
    ) -> Result<Vec<u8>, EnrollmentError> {
        self.ensure_healthy()?;
        let invite = self
            .invites
            .get(&invite_id)
            .ok_or(EnrollmentError::InvalidInvite)?;
        if !secret_bytes_equal(&invite.bearer_secret, bearer_secret) {
            return Err(EnrollmentError::InvalidBearerSecret);
        }
        let tx = self
            .transactions
            .get(&(invite_id, enrollment_id))
            .ok_or(EnrollmentError::TransactionNotFound)?;
        if now_us > tx.result.recovery_until_us {
            return Err(EnrollmentError::InviteRecoveryExpired);
        }
        Ok(tx.csr_der.clone())
    }

    /// Production CSR admission boundary.
    ///
    /// The ML-DSA PKCS#10 signature is verified against the public key carried in the
    /// exact DER request, and the exact DER bytes are hashed and retained. The returned
    /// token is the only way to enter [`Self::claim`] from outside this crate's tests.
    /// The invitation determines the role and home core; the caller cannot supply them.
    #[cfg(feature = "openssl-backend")]
    pub fn verify_csr_request(
        &self,
        invite_id: [u8; 16],
        enrollment_id: [u8; 16],
        bearer_secret: &[u8; 32],
        csr_der: &[u8],
        now_us: u64,
    ) -> Result<VerifiedEnrollmentRequest, EnrollmentError> {
        self.ensure_healthy()?;
        let invite = *self
            .invites
            .get(&invite_id)
            .ok_or(EnrollmentError::InvalidInvite)?;
        if !secret_bytes_equal(&invite.bearer_secret, bearer_secret) {
            return Err(EnrollmentError::InvalidBearerSecret);
        }
        if csr_der.is_empty() || csr_der.len() > MAX_CSR_BYTES {
            return Err(EnrollmentError::CsrTooLarge);
        }
        // Cheap rejection before the expensive ML-DSA proof-of-possession check:
        // an invitation already bound to another enrollment cannot be rescued by a new CSR.
        if let Some((bound_enrollment_id, _)) = self.invite_bindings.get(&invite_id) {
            if *bound_enrollment_id != enrollment_id {
                return Err(EnrollmentError::InviteBoundToDifferentRequest);
            }
        }
        let pair = (invite_id, enrollment_id);
        if let Some(tx) = self.transactions.get(&pair) {
            if now_us > tx.result.recovery_until_us {
                return Err(EnrollmentError::InviteRecoveryExpired);
            }
            if tx.csr_der.as_slice() == csr_der {
                // The exact DER was already verified when first admitted. Recovery retries
                // reuse that decision instead of paying for a second ML-DSA verification;
                // the Ed key is the one durably bound to that exact DER.
                return VerifiedEnrollmentRequest::from_verified_csr(VerifiedCsrFields {
                    invite_id,
                    enrollment_id,
                    bearer_secret: *bearer_secret,
                    raw_csr_der: tx.csr_der.clone(),
                    raw_csr_sha256: tx.csr_hash,
                    role: invite.role,
                    home_core_id: invite.home_core_id,
                    identity_pub_ed25519: tx.identity_pub_ed25519,
                });
            }
            // A bound transaction cannot be rebound to different bytes; reject cheaply.
            return Err(EnrollmentError::InviteBoundToDifferentRequest);
        }
        if self.invite_bindings.contains_key(&invite_id) {
            return Err(EnrollmentError::InviteBoundToDifferentRequest);
        }
        if now_us >= invite.expires_at_us {
            return Err(EnrollmentError::InviteExpired);
        }
        let oid = self
            .csr_policy
            .ed25519_pop_oid()
            .ok_or(EnrollmentError::CsrPolicyMissing)?;
        let (csr_hash, identity_pub_ed25519) = verify_ml_dsa_csr(csr_der, oid)?;
        VerifiedEnrollmentRequest::from_verified_csr(VerifiedCsrFields {
            invite_id,
            enrollment_id,
            bearer_secret: *bearer_secret,
            raw_csr_der: csr_der.to_vec(),
            raw_csr_sha256: csr_hash,
            role: invite.role,
            home_core_id: invite.home_core_id,
            identity_pub_ed25519,
        })
    }

    /// Complete the recoverable enrollment and signing path in one call.
    ///
    /// A fresh transaction moves `PREPARED -> ISSUED`; a retry after a crash or lost
    /// response returns the already-persisted signed identity and never reallocates the
    /// slot. The CSR is read back from the journal, not reconstructed from the bare
    /// enrollment id.
    #[cfg(feature = "openssl-backend")]
    pub fn claim_and_issue(
        &mut self,
        req: VerifiedEnrollmentRequest,
        now_us: u64,
        authority: &crate::management::IdentityAuthority,
        validity: IdentityValidity,
    ) -> Result<EnrollmentResult, EnrollmentError> {
        if validity.not_before_us >= validity.expires_us
            || validity.not_before_us > now_us
            || validity.expires_us <= now_us
            || validity.scope.len() > 1024
        {
            return Err(EnrollmentError::InvalidIdentityValidity);
        }
        let invite_id = req.invite_id;
        let enrollment_id = req.enrollment_id;
        let bearer_secret = req.bearer_secret;
        let identity_pub_ed25519 = req.identity_pub_ed25519;
        let claimed = self.claim(req, now_us)?;
        if claimed.phase != EnrollmentPhase::Prepared {
            return Ok(claimed);
        }
        let csr_der = self.raw_csr_for_signing(invite_id, enrollment_id, &bearer_secret, now_us)?;
        let role = match claimed.slot.role {
            NodeRole::Edge => crate::NodeRole::Edge,
            NodeRole::Core => crate::NodeRole::Core,
            NodeRole::EnrollmentService => crate::NodeRole::EnrollmentService,
        };
        let template = crate::management::IdentityTemplate {
            node_id: claimed.node_id,
            home_core_id: claimed.slot.home_core_id,
            vip_octet: claimed.slot.vip_octet,
            role,
            identity_generation: claimed.identity_generation,
            identity_pub_ed25519,
            not_before_us: validity.not_before_us,
            expires_us: validity.expires_us,
            scope: validity.scope,
        };
        let body = authority
            .node_identity_from_csr(template, &csr_der)
            .map_err(|_| EnrollmentError::IdentityAuthorityRejected)?;
        let signed = authority
            .sign_node_identity(body)
            .map_err(|_| EnrollmentError::IdentityAuthorityRejected)?;
        let signed_bytes = signed
            .encode()
            .map_err(|_| EnrollmentError::IdentityAuthorityRejected)?;
        self.mark_issued(
            invite_id,
            enrollment_id,
            now_us,
            SignedIdentityResult::from_identity_authority(signed_bytes)?,
        )
    }

    pub fn mark_delivered(
        &mut self,
        invite_id: [u8; 16],
        enrollment_id: [u8; 16],
    ) -> Result<EnrollmentResult, EnrollmentError> {
        self.ensure_healthy()?;
        let key = (invite_id, enrollment_id);
        let mut next = self
            .transactions
            .get(&key)
            .cloned()
            .ok_or(EnrollmentError::TransactionNotFound)?;
        if next.result.phase == EnrollmentPhase::Delivered {
            return Ok(next.result);
        }
        if next.result.phase != EnrollmentPhase::Issued {
            return Err(EnrollmentError::WrongPhase);
        }
        next.result.phase = EnrollmentPhase::Delivered;
        self.append_event(Event::Delivered {
            fence: self.fence,
            tx: next.clone(),
        })?;
        self.transactions.insert(key, next.clone());
        Ok(next.result)
    }

    /// Durable retirement tombstone; slots are never silently reused. A future allocator may
    /// reuse only after separately proving all lease/snapshot TTLs drained and incrementing gen.
    pub fn tombstone_slot(
        &mut self,
        node_id: u16,
        next_generation: u64,
    ) -> Result<(), EnrollmentError> {
        self.ensure_healthy()?;
        let current = self.generations.get(&node_id).copied().unwrap_or(0);
        if !self.used_slots.contains(&node_id) || next_generation <= current {
            return Err(EnrollmentError::InvalidSlot);
        }
        self.append_event(Event::Tombstone {
            fence: self.fence,
            node_id,
            generation: next_generation,
        })?;
        self.generations.insert(node_id, next_generation);
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), EnrollmentError> {
        if self.poisoned {
            Err(EnrollmentError::StorePoisoned)
        } else {
            Ok(())
        }
    }
    fn apply_prepared(&mut self, tx: Tx) {
        let node_id = tx.result.node_id;
        self.used_slots.insert(node_id);
        self.generations
            .insert(node_id, tx.result.identity_generation);
        self.invite_bindings
            .insert(tx.invite_id, (tx.enrollment_id, tx.csr_hash));
        self.transactions
            .insert((tx.invite_id, tx.enrollment_id), tx);
    }
    fn append_event(&mut self, event: Event) -> Result<(), EnrollmentError> {
        self.ensure_healthy()?;
        let payload = event.encode();
        if self
            .journal
            .metadata()?
            .len()
            .saturating_add(payload.len() as u64 + 13)
            > MAX_JOURNAL_BYTES
            || self.record_count >= MAX_RECORDS
        {
            return Err(EnrollmentError::StoreFull);
        }
        let mut frame = Vec::with_capacity(payload.len() + 13);
        frame.extend_from_slice(MAGIC);
        frame.push(VERSION);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&crc32(&payload).to_be_bytes());
        frame.extend_from_slice(&payload);
        if frame.len() > MAX_FRAME {
            return Err(EnrollmentError::InvalidSignedResult);
        }
        let write = (|| -> io::Result<()> {
            self.journal.seek(SeekFrom::End(0))?;
            #[cfg(test)]
            if self.fail_next_write {
                self.fail_next_write = false;
                self.journal.write_all(&frame[..frame.len() / 2])?;
                return Err(io::Error::other("injected partial write failure"));
            }
            self.journal.write_all(&frame)?;
            self.journal.sync_all()
        })();
        if let Err(e) = write {
            self.poisoned = true;
            return Err(EnrollmentError::Io(e));
        }
        self.record_count += 1;
        Ok(())
    }

    fn recover(&mut self) -> Result<(), EnrollmentError> {
        self.journal.seek(SeekFrom::Start(0))?;
        if self.journal.metadata()?.len() > MAX_JOURNAL_BYTES {
            return Err(EnrollmentError::StoreFull);
        }
        let mut bytes = Vec::new();
        self.journal.read_to_end(&mut bytes)?;
        let mut offset = 0usize;
        let mut records = Vec::new();
        while offset < bytes.len() {
            let remain = bytes.len() - offset;
            if remain < 13 {
                break;
            } // torn header tail
            if &bytes[offset..offset + 4] != MAGIC {
                return Err(EnrollmentError::CorruptJournal);
            }
            if bytes[offset + 4] != VERSION {
                return Err(EnrollmentError::UnsupportedVersion);
            }
            let len = u32::from_be_bytes(
                bytes[offset + 5..offset + 9]
                    .try_into()
                    .map_err(|_| EnrollmentError::CorruptJournal)?,
            ) as usize;
            if len > MAX_FRAME - 13 {
                return Err(EnrollmentError::CorruptJournal);
            }
            let end = offset
                .checked_add(13)
                .and_then(|x| x.checked_add(len))
                .ok_or(EnrollmentError::CorruptJournal)?;
            if end > bytes.len() {
                break;
            } // torn payload tail
            let expected = u32::from_be_bytes(
                bytes[offset + 9..offset + 13]
                    .try_into()
                    .map_err(|_| EnrollmentError::CorruptJournal)?,
            );
            let payload = &bytes[offset + 13..end];
            if crc32(payload) != expected {
                return Err(EnrollmentError::CorruptJournal);
            }
            if records.len() >= MAX_RECORDS {
                return Err(EnrollmentError::StoreFull);
            }
            records.push(Event::decode(payload)?);
            offset = end;
        }
        if offset != bytes.len() {
            self.journal.set_len(offset as u64)?;
            self.journal.sync_all()?;
        }
        for event in records {
            self.apply_event(event)?;
            self.record_count += 1;
        }
        Ok(())
    }
    fn apply_event(&mut self, event: Event) -> Result<(), EnrollmentError> {
        match event {
            Event::Fence { epoch } => {
                if epoch < self.fence {
                    return Err(EnrollmentError::StaleFence);
                }
                self.fence = epoch;
            }
            Event::Prepared { fence, tx } => {
                if fence < self.fence {
                    return Err(EnrollmentError::StaleFence);
                }
                self.fence = fence;
                let id = tx.result.node_id;
                if self.used_slots.contains(&id) || self.invite_bindings.contains_key(&tx.invite_id)
                {
                    return Err(EnrollmentError::CorruptJournal);
                }
                let invite = self
                    .invites
                    .get(&tx.invite_id)
                    .ok_or(EnrollmentError::CorruptJournal)?;
                if invite.role != tx.result.slot.role
                    || invite.home_core_id != tx.result.slot.home_core_id
                    || !self.slots.contains(&tx.result.slot)
                    || tx.csr_der.is_empty()
                    || tx.csr_der.len() > MAX_CSR_BYTES
                    || tx.result.phase != EnrollmentPhase::Prepared
                    || tx.result.signed_identity.is_some()
                {
                    return Err(EnrollmentError::CorruptJournal);
                }
                let old_generation = self.generations.get(&id).copied().unwrap_or(0);
                if tx.result.identity_generation != old_generation + 1 {
                    return Err(EnrollmentError::CorruptJournal);
                }
                self.apply_prepared(tx);
            }
            Event::Issued { fence, tx } => {
                self.check_fence(fence)?;
                let key = (tx.invite_id, tx.enrollment_id);
                let old = self
                    .transactions
                    .get(&key)
                    .ok_or(EnrollmentError::CorruptJournal)?;
                if old.csr_hash != tx.csr_hash
                    || old.csr_der != tx.csr_der
                    || tx.result.node_id != old.result.node_id
                    || tx.result.slot != old.result.slot
                    || tx.result.identity_generation != old.result.identity_generation
                    || tx.result.recovery_until_us != old.result.recovery_until_us
                    || tx.result.phase != EnrollmentPhase::Issued
                    || tx.result.signed_identity.is_none()
                    || old.result.phase != EnrollmentPhase::Prepared
                    || old.result.signed_identity.is_some()
                {
                    return Err(EnrollmentError::CorruptJournal);
                }
                self.transactions.insert(key, tx);
            }
            Event::Delivered { fence, tx } => {
                self.check_fence(fence)?;
                let key = (tx.invite_id, tx.enrollment_id);
                let old = self
                    .transactions
                    .get(&key)
                    .ok_or(EnrollmentError::CorruptJournal)?;
                if old.csr_hash != tx.csr_hash
                    || old.csr_der != tx.csr_der
                    || tx.result.node_id != old.result.node_id
                    || tx.result.slot != old.result.slot
                    || tx.result.identity_generation != old.result.identity_generation
                    || tx.result.recovery_until_us != old.result.recovery_until_us
                    || tx.result.signed_identity != old.result.signed_identity
                    || tx.result.phase != EnrollmentPhase::Delivered
                    || old.result.phase != EnrollmentPhase::Issued
                {
                    return Err(EnrollmentError::CorruptJournal);
                }
                self.transactions.insert(key, tx);
            }
            Event::AllocationWatermark {
                fence,
                home_core_id,
                watermark,
            } => {
                self.check_fence(fence)?;
                let previous = self
                    .allocation_watermarks
                    .get(&home_core_id)
                    .copied()
                    .unwrap_or(0);
                if !(1..=16).contains(&home_core_id) || watermark == 0 || watermark <= previous {
                    return Err(EnrollmentError::CorruptJournal);
                }
                self.allocation_watermarks.insert(home_core_id, watermark);
            }
            Event::Tombstone {
                fence,
                node_id,
                generation,
            } => {
                self.check_fence(fence)?;
                if !self.used_slots.contains(&node_id)
                    || generation <= self.generations.get(&node_id).copied().unwrap_or(0)
                {
                    return Err(EnrollmentError::CorruptJournal);
                }
                self.generations.insert(node_id, generation);
            }
        }
        Ok(())
    }
    fn check_fence(&mut self, fence: u64) -> Result<(), EnrollmentError> {
        if fence < self.fence {
            return Err(EnrollmentError::StaleFence);
        }
        self.fence = fence;
        Ok(())
    }
}
impl Drop for EnrollmentStore {
    fn drop(&mut self) {
        // The OS releases the advisory lock on close, and also on process death/SIGKILL.
        // The lock file is not unlinked: unlinking while another waiter holds the old inode
        // would allow a second writer on a newly created inode.
        if let Some(lock) = self._lock.take() {
            let _ = lock.unlock();
            drop(lock);
        }
    }
}

#[derive(Clone, Debug)]
enum Event {
    Fence {
        epoch: u64,
    },
    Prepared {
        fence: u64,
        tx: Tx,
    },
    Issued {
        fence: u64,
        tx: Tx,
    },
    Delivered {
        fence: u64,
        tx: Tx,
    },
    Tombstone {
        fence: u64,
        node_id: u16,
        generation: u64,
    },
    AllocationWatermark {
        fence: u64,
        home_core_id: u8,
        watermark: u64,
    },
}
impl Event {
    fn encode(&self) -> Vec<u8> {
        let mut w = Vec::new();
        match self {
            Event::Fence { epoch } => {
                w.push(5);
                w.extend_from_slice(&epoch.to_be_bytes());
            }
            Event::Prepared { fence, tx } => {
                w.push(1);
                w.extend_from_slice(&fence.to_be_bytes());
                encode_tx(&mut w, tx);
            }
            Event::Issued { fence, tx } => {
                w.push(2);
                w.extend_from_slice(&fence.to_be_bytes());
                encode_tx(&mut w, tx);
            }
            Event::Delivered { fence, tx } => {
                w.push(3);
                w.extend_from_slice(&fence.to_be_bytes());
                encode_tx(&mut w, tx);
            }
            Event::Tombstone {
                fence,
                node_id,
                generation,
            } => {
                w.push(4);
                w.extend_from_slice(&fence.to_be_bytes());
                w.extend_from_slice(&node_id.to_be_bytes());
                w.extend_from_slice(&generation.to_be_bytes());
            }
            Event::AllocationWatermark {
                fence,
                home_core_id,
                watermark,
            } => {
                w.push(6);
                w.extend_from_slice(&fence.to_be_bytes());
                w.push(*home_core_id);
                w.extend_from_slice(&watermark.to_be_bytes());
            }
        }
        w
    }
    fn decode(b: &[u8]) -> Result<Self, EnrollmentError> {
        let mut r = Reader { b, p: 0 };
        let kind = r.u8()?;
        let fence = r.u64()?;
        let e = match kind {
            1 => Self::Prepared {
                fence,
                tx: decode_tx(&mut r)?,
            },
            2 => Self::Issued {
                fence,
                tx: decode_tx(&mut r)?,
            },
            3 => Self::Delivered {
                fence,
                tx: decode_tx(&mut r)?,
            },
            4 => Self::Tombstone {
                fence,
                node_id: r.u16()?,
                generation: r.u64()?,
            },
            5 => Self::Fence { epoch: fence },
            6 => Self::AllocationWatermark {
                fence,
                home_core_id: r.u8()?,
                watermark: r.u64()?,
            },
            _ => return Err(EnrollmentError::CorruptJournal),
        };
        if r.p != b.len() {
            return Err(EnrollmentError::CorruptJournal);
        }
        Ok(e)
    }
}
fn encode_tx(w: &mut Vec<u8>, tx: &Tx) {
    w.extend_from_slice(&tx.invite_id);
    w.extend_from_slice(&tx.enrollment_id);
    w.extend_from_slice(&tx.csr_hash);
    w.extend_from_slice(&tx.identity_pub_ed25519);
    w.push(match tx.result.phase {
        EnrollmentPhase::Prepared => 1,
        EnrollmentPhase::Issued => 2,
        EnrollmentPhase::Delivered => 3,
    });
    w.extend_from_slice(&tx.result.node_id.to_be_bytes());
    w.push(tx.result.slot.home_core_id);
    w.push(tx.result.slot.vip_octet);
    w.push(tx.result.slot.role as u8);
    w.extend_from_slice(&tx.result.identity_generation.to_be_bytes());
    w.extend_from_slice(&tx.result.recovery_until_us.to_be_bytes());
    w.extend_from_slice(&(tx.csr_der.len() as u16).to_be_bytes());
    w.extend_from_slice(&tx.csr_der);
    let signed = tx.result.signed_identity.as_deref().unwrap_or(&[]);
    w.extend_from_slice(&(signed.len() as u16).to_be_bytes());
    w.extend_from_slice(signed);
}
fn decode_tx(r: &mut Reader<'_>) -> Result<Tx, EnrollmentError> {
    let invite_id = r.array16()?;
    let enrollment_id = r.array16()?;
    let csr_hash = r.array32()?;
    let identity_pub_ed25519 = r.array32()?;
    if identity_pub_ed25519 == [0; 32] {
        return Err(EnrollmentError::CorruptJournal);
    }
    let phase = match r.u8()? {
        1 => EnrollmentPhase::Prepared,
        2 => EnrollmentPhase::Issued,
        3 => EnrollmentPhase::Delivered,
        _ => return Err(EnrollmentError::CorruptJournal),
    };
    let node_id = r.u16()?;
    let slot = Slot {
        home_core_id: r.u8()?,
        vip_octet: r.u8()?,
        role: match r.u8()? {
            1 => NodeRole::Edge,
            2 => NodeRole::Core,
            3 => NodeRole::EnrollmentService,
            _ => return Err(EnrollmentError::CorruptJournal),
        },
    };
    if slot.node_id()? != node_id {
        return Err(EnrollmentError::CorruptJournal);
    }
    let identity_generation = r.u64()?;
    let recovery_until_us = r.u64()?;
    let csr_len = r.u16()? as usize;
    if csr_len == 0 || csr_len > MAX_CSR_BYTES {
        return Err(EnrollmentError::CorruptJournal);
    }
    let csr_der = r.take(csr_len)?.to_vec();
    let n = r.u16()? as usize;
    if n > 16 * 1024 {
        return Err(EnrollmentError::CorruptJournal);
    }
    let raw = r.take(n)?.to_vec();
    let signed_identity = if raw.is_empty() { None } else { Some(raw) };
    if (phase == EnrollmentPhase::Prepared) != signed_identity.is_none() {
        return Err(EnrollmentError::CorruptJournal);
    }
    Ok(Tx {
        invite_id,
        enrollment_id,
        csr_hash,
        csr_der,
        identity_pub_ed25519,
        result: EnrollmentResult {
            phase,
            node_id,
            slot,
            identity_generation,
            signed_identity,
            recovery_until_us,
        },
    })
}
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EnrollmentError> {
        let end = self
            .p
            .checked_add(n)
            .ok_or(EnrollmentError::CorruptJournal)?;
        if end > self.b.len() {
            return Err(EnrollmentError::CorruptJournal);
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, EnrollmentError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, EnrollmentError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| EnrollmentError::CorruptJournal)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, EnrollmentError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| EnrollmentError::CorruptJournal)?,
        ))
    }
    fn array16(&mut self) -> Result<[u8; 16], EnrollmentError> {
        self.take(16)?
            .try_into()
            .map_err(|_| EnrollmentError::CorruptJournal)
    }
    fn array32(&mut self) -> Result<[u8; 32], EnrollmentError> {
        self.take(32)?
            .try_into()
            .map_err(|_| EnrollmentError::CorruptJournal)
    }
}
/// Candidate, explicitly unregistered OID for offline/controlled Ed25519 PoP evidence.
/// Production must configure a formally assigned enterprise OID through [`CsrPolicy`].
pub const EXPERIMENTAL_ED25519_CSR_POP_OID: &str = "1.3.6.1.4.1.55555.1.1";
#[cfg(feature = "openssl-backend")]
const ED25519_POP_DOMAIN: &[u8] = b"BOREAS-NODE-ED25519-POP-v1\0";
#[cfg(feature = "openssl-backend")]
const ED25519_POP_PAYLOAD_LEN: usize = 1 + 32 + 64;

/// Verify a standard PKCS#10 DER request carrying an ML-DSA-65 key.
///
/// `X509Req::verify` performs the actual proof-of-possession check. Re-encoding and
/// comparing the whole DER rejects trailing bytes that some decoders would ignore.
/// The Ed25519 management key is carried only by the configured CSR extension and must
/// prove possession over a fixed domain bound to the CSR's ML-DSA public key. The returned
/// digest is over the exact bytes persisted by the journal.
#[cfg(feature = "openssl-backend")]
fn verify_ml_dsa_csr(
    csr_der: &[u8],
    ed25519_pop_oid: &str,
) -> Result<([u8; 32], [u8; 32]), EnrollmentError> {
    if csr_der.is_empty() || csr_der.len() > MAX_CSR_BYTES {
        return Err(EnrollmentError::CsrTooLarge);
    }
    let request = X509Req::from_der(csr_der).map_err(|_| EnrollmentError::InvalidCsr)?;
    if request.version() != 0 {
        return Err(EnrollmentError::InvalidCsr);
    }
    let canonical_der = request.to_der().map_err(|_| EnrollmentError::InvalidCsr)?;
    if canonical_der != csr_der {
        return Err(EnrollmentError::InvalidCsr);
    }
    let public_key = request
        .public_key()
        .map_err(|_| EnrollmentError::InvalidCsr)?;
    if !public_key.is_a(KeyType::ML_DSA_65) {
        return Err(EnrollmentError::UnsupportedCsrKey);
    }
    let proof_of_possession = request
        .verify(&public_key)
        .map_err(|_| EnrollmentError::InvalidCsr)?;
    if !proof_of_possession {
        return Err(EnrollmentError::CsrProofOfPossession);
    }
    let ml_dsa_public = public_key
        .raw_public_key()
        .map_err(|_| EnrollmentError::InvalidCsr)?;
    let ed25519_public = verify_csr_ed25519_extension(&request, ed25519_pop_oid, &ml_dsa_public)?;
    let digest = hash(MessageDigest::sha256(), csr_der).map_err(|_| EnrollmentError::InvalidCsr)?;
    let digest_bytes: &[u8] = digest.as_ref();
    let mut csr_hash = [0u8; 32];
    csr_hash.copy_from_slice(digest_bytes);
    Ok((csr_hash, ed25519_public))
}

#[cfg(feature = "openssl-backend")]
fn verify_csr_ed25519_extension(
    request: &X509Req,
    oid: &str,
    ml_dsa_public: &[u8],
) -> Result<[u8; 32], EnrollmentError> {
    let expected_oid = openssl::asn1::Asn1Object::from_str(oid)
        .map_err(|_| EnrollmentError::InvalidCsrPolicy)?
        .to_der()
        .map_err(|_| EnrollmentError::InvalidCsrPolicy)?;
    let extensions = request
        .extensions()
        .map_err(|_| EnrollmentError::InvalidCsrExtension)?;
    let mut matched: Option<(bool, Vec<u8>)> = None;
    for extension in &extensions {
        let der = extension
            .to_der()
            .map_err(|_| EnrollmentError::InvalidCsrExtension)?;
        let (extension_oid, critical, value) = parse_extension_der(&der)?;
        if extension_oid == expected_oid {
            if matched.is_some() {
                return Err(EnrollmentError::InvalidCsrExtension);
            }
            matched = Some((critical, value));
        }
    }
    let (critical, value) = matched.ok_or(EnrollmentError::InvalidCsrExtension)?;
    if !critical || value.len() != ED25519_POP_PAYLOAD_LEN || value[0] != 1 {
        return Err(EnrollmentError::InvalidCsrExtension);
    }
    let mut ed25519_public = [0u8; 32];
    ed25519_public.copy_from_slice(&value[1..33]);
    if ed25519_public == [0; 32] {
        return Err(EnrollmentError::InvalidCsrExtension);
    }
    let mut message = Vec::with_capacity(ED25519_POP_DOMAIN.len() + 32 + ml_dsa_public.len());
    message.extend_from_slice(ED25519_POP_DOMAIN);
    message.extend_from_slice(&ed25519_public);
    message.extend_from_slice(ml_dsa_public);
    let ed_key =
        openssl::pkey::PKey::public_key_from_raw_bytes(&ed25519_public, openssl::pkey::Id::ED25519)
            .map_err(|_| EnrollmentError::InvalidCsrExtension)?;
    let mut verifier = openssl::sign::Verifier::new_without_digest(&ed_key)
        .map_err(|_| EnrollmentError::InvalidCsrExtension)?;
    if !verifier
        .verify_oneshot(&value[33..97], &message)
        .map_err(|_| EnrollmentError::InvalidCsrExtension)?
    {
        return Err(EnrollmentError::Ed25519ProofOfPossession);
    }
    Ok(ed25519_public)
}

#[cfg(feature = "openssl-backend")]
fn parse_extension_der(der: &[u8]) -> Result<(Vec<u8>, bool, Vec<u8>), EnrollmentError> {
    let mut position = 0usize;
    let (tag, content_start, content_end) = der_take(der, &mut position)?;
    if tag != 0x30 || content_end != der.len() {
        return Err(EnrollmentError::InvalidCsrExtension);
    }
    let mut inner = content_start;
    let oid_tlv_start = inner;
    let (oid_tag, _oid_start, oid_end) = der_take(der, &mut inner)?;
    if oid_tag != 0x06 {
        return Err(EnrollmentError::InvalidCsrExtension);
    }
    let oid = der[oid_tlv_start..oid_end].to_vec();
    let before_boolean = inner;
    let (boolean_tag, boolean_start, boolean_end) = der_take(der, &mut inner)?;
    let critical = if boolean_tag == 0x01 {
        if boolean_end != boolean_start + 1 {
            return Err(EnrollmentError::InvalidCsrExtension);
        }
        match der[boolean_start] {
            0xff => true,
            0x00 => false,
            _ => return Err(EnrollmentError::InvalidCsrExtension),
        }
    } else {
        inner = before_boolean;
        false
    };
    let (value_tag, value_start, value_end) = der_take(der, &mut inner)?;
    if value_tag != 0x04 || value_end != content_end || inner != content_end {
        return Err(EnrollmentError::InvalidCsrExtension);
    }
    Ok((oid, critical, der[value_start..value_end].to_vec()))
}

#[cfg(feature = "openssl-backend")]
fn der_take(der: &[u8], position: &mut usize) -> Result<(u8, usize, usize), EnrollmentError> {
    let tag = *der
        .get(*position)
        .ok_or(EnrollmentError::InvalidCsrExtension)?;
    if tag & 0x1f == 0x1f {
        return Err(EnrollmentError::InvalidCsrExtension);
    }
    let length_byte = *der
        .get(*position + 1)
        .ok_or(EnrollmentError::InvalidCsrExtension)?;
    let (length, header_len) = if length_byte & 0x80 == 0 {
        (usize::from(length_byte), 2usize)
    } else {
        let count = usize::from(length_byte & 0x7f);
        if count == 0 || count > 3 || der.len() < *position + 2 + count {
            return Err(EnrollmentError::InvalidCsrExtension);
        }
        let mut length = 0usize;
        for offset in 0..count {
            length = (length << 8) | usize::from(der[*position + 2 + offset]);
        }
        (length, 2 + count)
    };
    let content_start = (*position)
        .checked_add(header_len)
        .ok_or(EnrollmentError::InvalidCsrExtension)?;
    let content_end = content_start
        .checked_add(length)
        .ok_or(EnrollmentError::InvalidCsrExtension)?;
    if content_end > der.len() {
        return Err(EnrollmentError::InvalidCsrExtension);
    }
    *position = content_end;
    Ok((tag, content_start, content_end))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb88320
            } else {
                c >> 1
            };
        }
    }
    !c
}
fn suffix_path(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Resolve the storage directory before creating any file.
///
/// macOS exposes `/tmp` and `/var/folders/...` through the system `/var` symlink, so a
/// blanket "no symlink in any textual ancestor" check rejects a safe, standard temporary
/// directory. Canonicalizing the parent resolves every component first; the final directory
/// is then re-checked as a real directory with private permissions. The final file name is
/// checked before and after open, including hard-link count, so a symlinked journal or lock
/// file is still rejected. This is not a proof against a malicious local administrator racing
/// the path, which is outside this journal's threat model.
fn canonical_storage_path(path: &Path) -> Result<PathBuf, EnrollmentError> {
    let file_name = path.file_name().ok_or(EnrollmentError::UnsafeStoragePath)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(EnrollmentError::UnsafeStoragePath);
            }
            #[cfg(unix)]
            if meta.nlink() != 1 {
                return Err(EnrollmentError::UnsafeStoragePath);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(EnrollmentError::Io(e)),
    }
    let canonical_parent = fs::canonicalize(parent)?;
    let parent_meta = fs::symlink_metadata(&canonical_parent)?;
    if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
        return Err(EnrollmentError::UnsafeStoragePath);
    }
    #[cfg(unix)]
    if parent_meta.permissions().mode() & 0o077 != 0 {
        return Err(EnrollmentError::UnsafeStoragePath);
    }
    Ok(canonical_parent.join(file_name))
}
fn validate_open_file(path: &Path, file: &File) -> Result<(), EnrollmentError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(EnrollmentError::UnsafeStoragePath);
    }
    #[cfg(unix)]
    {
        if meta.nlink() != 1 || file.metadata()?.mode() & 0o777 != 0o600 {
            return Err(EnrollmentError::UnsafeStoragePath);
        }
        let opened = file.metadata()?;
        if meta.dev() != opened.dev() || meta.ino() != opened.ino() {
            return Err(EnrollmentError::UnsafeStoragePath);
        }
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<(), EnrollmentError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<(), EnrollmentError> {
    // std has no portable directory-handle fsync API and this crate forbids unsafe FFI.
    // File data is still synced by append_event, but a newly created directory entry is
    // not crash-durable here. EnrollmentStore::directory_entry_durability_guaranteed()
    // returns false so the deployment gate cannot mistake this for Unix behavior.
    Ok(())
}
/// Constant-time equality for the fixed-size bearer secret.
///
/// The length check is not secret-dependent because every valid secret is exactly 32 bytes.
fn secret_bytes_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    static TEMP_ID: AtomicU64 = AtomicU64::new(1);
    fn temp_path() -> PathBuf {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("boreas-enroll-{}-{id}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir.join("journal")
    }
    fn invite() -> InviteSpec {
        InviteSpec {
            invite_id: [1; 16],
            expires_at_us: 10_000_000,
            role: NodeRole::Edge,
            home_core_id: 1,
            bearer_secret: [7; 32],
        }
    }
    fn slots() -> Vec<Slot> {
        vec![Slot {
            home_core_id: 1,
            vip_octet: 2,
            role: NodeRole::Edge,
        }]
    }
    fn two_slots() -> Vec<Slot> {
        vec![
            Slot {
                home_core_id: 1,
                vip_octet: 2,
                role: NodeRole::Edge,
            },
            Slot {
                home_core_id: 1,
                vip_octet: 3,
                role: NodeRole::Edge,
            },
        ]
    }
    fn second_invite() -> InviteSpec {
        InviteSpec {
            invite_id: [2; 16],
            expires_at_us: 10_000_000,
            role: NodeRole::Edge,
            home_core_id: 1,
            bearer_secret: [7; 32],
        }
    }
    fn setup(path: &Path) -> EnrollmentStore {
        EnrollmentStore::open(
            path,
            WriterFence::from_authority(1),
            vec![invite()],
            slots(),
        )
        .unwrap()
    }
    fn open(path: &Path, fence: u64) -> Result<EnrollmentStore, EnrollmentError> {
        EnrollmentStore::open(
            path,
            WriterFence::from_authority(fence),
            vec![invite()],
            slots(),
        )
    }
    #[cfg(feature = "openssl-backend")]
    fn setup_with_policy(path: &Path, policy: CsrPolicy) -> EnrollmentStore {
        EnrollmentStore::open_with_csr_policy(
            path,
            WriterFence::from_authority(1),
            vec![invite()],
            slots(),
            policy,
        )
        .unwrap()
    }
    fn open_two(path: &Path, fence: u64) -> Result<EnrollmentStore, EnrollmentError> {
        EnrollmentStore::open(
            path,
            WriterFence::from_authority(fence),
            vec![invite(), second_invite()],
            two_slots(),
        )
    }
    fn request(enroll: u8, fill: u8) -> VerifiedEnrollmentRequest {
        request_with([1; 16], enroll, fill)
    }
    fn request_with(invite_id: [u8; 16], enroll: u8, fill: u8) -> VerifiedEnrollmentRequest {
        let csr = vec![fill; 256];
        let digest = [fill; 32];
        VerifiedEnrollmentRequest::test_request(VerifiedCsrFields {
            invite_id,
            enrollment_id: [enroll; 16],
            bearer_secret: [7; 32],
            raw_csr_der: csr,
            raw_csr_sha256: digest,
            role: NodeRole::Edge,
            home_core_id: 1,
            identity_pub_ed25519: [8; 32],
        })
        .unwrap()
    }
    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(suffix_path(path, ".writer-lock"));
    }
    #[test]
    fn prepared_issued_delivered_recover_same_result() {
        let path = temp_path();
        let mut s = setup(&path);
        let p = s.claim(request(2, 3), 1).unwrap();
        assert_eq!(p.phase, EnrollmentPhase::Prepared);
        let issued = s
            .mark_issued(
                [1; 16],
                [2; 16],
                2,
                SignedIdentityResult::from_identity_authority(vec![9, 8]).unwrap(),
            )
            .unwrap();
        assert_eq!(issued.phase, EnrollmentPhase::Issued);
        drop(s);
        let mut s = setup(&path);
        let got = s.claim(request(2, 3), 2).unwrap();
        assert_eq!(got.signed_identity, Some(vec![9, 8]));
        assert_eq!(
            s.raw_csr_for_signing([1; 16], [2; 16], &[7; 32], 2)
                .unwrap(),
            vec![3; 256]
        );
        let delivered = s.mark_delivered([1; 16], [2; 16]).unwrap();
        assert_eq!(delivered.phase, EnrollmentPhase::Delivered);
        drop(s);
        cleanup(&path);
    }
    #[test]
    fn wrong_csr_never_rebinds_invite_and_recovery_window_is_bounded() {
        let path = temp_path();
        let mut s = setup(&path);
        s.claim(request(2, 3), 1).unwrap();
        assert!(matches!(
            s.claim(request(2, 4), 2),
            Err(EnrollmentError::InviteBoundToDifferentRequest)
        ));
        let mut bad_scope = request(2, 3);
        bad_scope.home_core_id = 2;
        assert!(matches!(
            s.claim(bad_scope, 2),
            Err(EnrollmentError::InviteScopeMismatch)
        ));
        let mut bad_secret = request(2, 3);
        bad_secret.bearer_secret = [8; 32];
        assert!(matches!(
            s.claim(bad_secret, 2),
            Err(EnrollmentError::InvalidBearerSecret)
        ));
        let same = request(2, 3);
        assert!(matches!(
            s.claim(same.clone(), 10_000_000 + RECOVERY_WINDOW_US + 1),
            Err(EnrollmentError::InviteRecoveryExpired)
        ));
        drop(s);
        cleanup(&path);
    }
    #[test]
    fn sixteen_concurrent_identical_requests_bind_once() {
        let path = temp_path();
        let store = Arc::new(Mutex::new(setup(&path)));
        let mut joins = Vec::new();
        for _ in 0..16 {
            let s = store.clone();
            joins.push(thread::spawn(move || {
                s.lock().unwrap().claim(request(2, 3), 1).unwrap()
            }));
        }
        let results: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        assert!(results.iter().all(|r| r == &results[0]));
        drop(store);
        cleanup(&path);
    }
    #[test]
    fn sixteen_competing_csrs_have_one_winner() {
        let path = temp_path();
        let store = Arc::new(Mutex::new(setup(&path)));
        let mut joins = Vec::new();
        for i in 0..16u8 {
            let s = store.clone();
            joins.push(thread::spawn(move || {
                s.lock().unwrap().claim(request(i + 1, i + 1), 1)
            }));
        }
        let results: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        for result in &results {
            if let Err(error) = result {
                assert!(matches!(
                    error,
                    EnrollmentError::InviteBoundToDifferentRequest
                ));
            }
        }
        let winner = results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .cloned()
            .unwrap();
        // The exact winning enrollment is idempotent; every other enrollment id is still
        // rejected without a second slot allocation or invite rebinding.
        let mut store = store.lock().unwrap();
        let mut retried_winner = false;
        for i in 0..16u8 {
            match store.claim(request(i + 1, i + 1), 1) {
                Ok(result) => {
                    assert_eq!(result, winner);
                    retried_winner = true;
                }
                Err(EnrollmentError::InviteBoundToDifferentRequest) => {}
                Err(error) => panic!("unexpected retry error: {error:?}"),
            }
        }
        assert!(retried_winner);
        drop(store);
        cleanup(&path);
    }
    #[test]
    fn partial_trailing_record_is_truncated_but_complete_corruption_rejected() {
        let path = temp_path();
        {
            let mut s = setup(&path);
            s.claim(request(2, 3), 1).unwrap();
        } // simulate crashed process by retaining stale lock
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"BEN")
            .unwrap();
        let s = setup(&path);
        drop(s);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"BENR\x02\0\0\0\x01\0\0\0\0\x99").unwrap();
        f.sync_all().unwrap();
        assert!(matches!(
            open(&path, 1),
            Err(EnrollmentError::CorruptJournal)
        ));
        cleanup(&path);
    }
    #[test]
    fn lock_and_fence_reject_second_or_stale_writer() {
        let path = temp_path();
        let s = setup(&path);
        assert!(matches!(open(&path, 1), Err(EnrollmentError::BusyLock)));
        drop(s);
        // Opening persists fence before returning; a fenced-off old process cannot reopen.
        assert!(matches!(open(&path, 0), Err(EnrollmentError::StaleFence)));
        cleanup(&path);
    }
    #[test]
    fn partial_write_failure_poison_store_and_is_not_reported_committed() {
        let path = temp_path();
        let mut s = setup(&path);
        s.fail_next_write = true;
        assert!(matches!(
            s.claim(request(2, 3), 1),
            Err(EnrollmentError::Io(_))
        ));
        assert!(matches!(
            s.claim(request(2, 3), 1),
            Err(EnrollmentError::StorePoisoned)
        ));
        drop(s);
        let mut recovered = setup(&path);
        assert!(recovered.claim(request(2, 3), 1).is_ok());
        drop(recovered);
        cleanup(&path);
    }
    #[test]
    fn tombstone_generation_survives_recovery_and_increments() {
        let path = temp_path();
        let mut s = setup(&path);
        let r = s.claim(request(2, 3), 1).unwrap();
        s.tombstone_slot(r.node_id, r.identity_generation + 1)
            .unwrap();
        drop(s);
        // Slots intentionally remain quarantined: no silent address reuse in this phase.
        let s = setup(&path);
        assert!(s.used_slots.contains(&r.node_id));
        assert_eq!(
            s.generations.get(&r.node_id),
            Some(&(r.identity_generation + 1))
        );
        drop(s);
        cleanup(&path);
    }
    #[test]
    fn failed_authentication_does_not_burn_invite_or_watermark() {
        let path = temp_path();
        let mut store = setup(&path);
        let mut bad_secret = request(2, 3);
        bad_secret.bearer_secret = [9; 32];
        assert!(matches!(
            store.claim(bad_secret, 1),
            Err(EnrollmentError::InvalidBearerSecret)
        ));
        assert_eq!(store.allocation_watermark(1).unwrap(), 0);
        let mut bad_scope = request(2, 3);
        bad_scope.home_core_id = 2;
        assert!(matches!(
            store.claim(bad_scope, 1),
            Err(EnrollmentError::InviteScopeMismatch)
        ));
        assert_eq!(store.allocation_watermark(1).unwrap(), 0);
        let result = store.claim(request(2, 3), 1).unwrap();
        assert_eq!(result.node_id, 2);
        assert_eq!(store.allocation_watermark(1).unwrap(), 1);
        drop(store);
        cleanup(&path);
    }
    #[test]
    fn torn_prepared_record_preserves_watermark_and_does_not_burn_invite() {
        let path = temp_path();
        {
            let mut store = setup(&path);
            let first = store.claim(request(2, 3), 1).unwrap();
            assert_eq!(first.node_id, 2);
        }
        let journal_len = fs::metadata(&path).unwrap().len();
        // Remove the tail of the Prepared record, leaving the durable allocation
        // watermark intact. Recovery must truncate the torn tail and allow a retry.
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(journal_len - 7)
            .unwrap();
        let mut store = setup(&path);
        assert_eq!(store.allocation_watermark(1).unwrap(), 1);
        let retried = store.claim(request(2, 3), 1).unwrap();
        assert_eq!(retried.node_id, 2);
        assert_eq!(store.allocation_watermark(1).unwrap(), 2);
        drop(store);
        cleanup(&path);
    }
    #[test]
    fn allocation_watermark_persists_and_never_moves_backwards() {
        let path = temp_path();
        {
            let mut store = open_two(&path, 1).unwrap();
            assert_eq!(store.allocation_watermark(1).unwrap(), 0);
            let first = store.claim(request(2, 3), 1).unwrap();
            assert_eq!(first.node_id, 2);
            assert_eq!(store.allocation_watermark(1).unwrap(), 1);
            assert_eq!(store.allocation_watermark(2).unwrap(), 0);
        }
        {
            // A higher external fence is persisted; the old watermark remains and the
            // next allocation advances it rather than reusing a rolled-back value.
            let mut store = open_two(&path, 2).unwrap();
            assert_eq!(store.allocation_watermark(1).unwrap(), 1);
            let second = store.claim(request_with([2; 16], 4, 4), 2).unwrap();
            assert_eq!(second.node_id, 3);
            assert_eq!(store.allocation_watermark(1).unwrap(), 2);
            assert!(matches!(
                store.allocation_watermark(0),
                Err(EnrollmentError::InvalidSlot)
            ));
        }
        cleanup(&path);
    }

    #[test]
    fn persistent_lock_file_does_not_wedge_recovery() {
        let path = temp_path();
        {
            let mut store = setup(&path);
            store.claim(request(2, 3), 1).unwrap();
            // Dropping normally releases the OS advisory lock. The lock file deliberately
            // remains on disk and must be reusable, not treated as a crash sentinel.
        }
        assert!(fs::metadata(suffix_path(&path, ".writer-lock")).is_ok());
        let store = setup(&path);
        assert_eq!(store.allocation_watermark(1).unwrap(), 1);
        drop(store);
        cleanup(&path);
    }

    #[cfg(feature = "openssl-backend")]
    fn csr_from_key(key: &openssl::pkey::PKey<openssl::pkey::Private>) -> Vec<u8> {
        use openssl::hash::MessageDigest;
        use openssl::x509::{X509NameBuilder, X509ReqBuilder};
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "boreas-enrollment-test")
            .unwrap();
        let name = name.build();
        let mut builder = X509ReqBuilder::new().unwrap();
        builder.set_version(0).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_pubkey(key).unwrap();
        builder.sign(key, MessageDigest::null()).unwrap();
        builder.build().to_der().unwrap()
    }
    #[cfg(feature = "openssl-backend")]
    fn csr_with_ed25519_pop(
        ml_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        ed_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        oid: &str,
    ) -> Vec<u8> {
        use openssl::asn1::{Asn1Object, Asn1OctetString};
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;
        use openssl::stack::Stack;
        use openssl::x509::{X509Extension, X509NameBuilder, X509ReqBuilder};
        let ml_public = ml_key.raw_public_key().unwrap();
        let ed_public = ed_key.raw_public_key().unwrap();
        let mut pop_message = Vec::new();
        pop_message.extend_from_slice(ED25519_POP_DOMAIN);
        pop_message.extend_from_slice(&ed_public);
        pop_message.extend_from_slice(&ml_public);
        let mut signer = Signer::new_without_digest(ed_key).unwrap();
        let ed_signature = signer.sign_oneshot_to_vec(&pop_message).unwrap();
        let mut payload = vec![1u8];
        payload.extend_from_slice(&ed_public);
        payload.extend_from_slice(&ed_signature);
        let oid_object = Asn1Object::from_str(oid).unwrap();
        let octets = Asn1OctetString::new_from_bytes(&payload).unwrap();
        let extension =
            X509Extension::new_from_der(oid_object.as_ref(), true, octets.as_ref()).unwrap();
        let mut extensions = Stack::new().unwrap();
        extensions.push(extension).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "boreas-enrollment-test")
            .unwrap();
        let name = name.build();
        let mut builder = X509ReqBuilder::new().unwrap();
        builder.set_version(0).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_pubkey(ml_key).unwrap();
        builder.add_extensions(&extensions).unwrap();
        builder.sign(ml_key, MessageDigest::null()).unwrap();
        builder.build().to_der().unwrap()
    }
    #[cfg(feature = "openssl-backend")]
    fn ml_dsa_key(seed: u8) -> openssl::pkey::PKey<openssl::pkey::Private> {
        openssl::pkey::PKey::private_key_from_seed(
            None,
            openssl::pkey::KeyType::ML_DSA_65,
            None,
            &[seed; 32],
        )
        .unwrap()
    }
    #[cfg(feature = "openssl-backend")]
    #[test]
    fn real_csr_admission_and_identity_signing_vertical_path() {
        use crate::management::{IdentityAuthority, ManagementTrust, verify_signed_identity};
        let path = temp_path();
        let policy = CsrPolicy::with_ed25519_pop_oid(EXPERIMENTAL_ED25519_CSR_POP_OID).unwrap();
        let csr_key = ml_dsa_key(11);
        let node_ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let node_ed_public: [u8; 32] = node_ed_key.raw_public_key().unwrap().try_into().unwrap();
        let csr = csr_with_ed25519_pop(&csr_key, &node_ed_key, EXPERIMENTAL_ED25519_CSR_POP_OID);
        let expected_identity_public = csr_key.raw_public_key().unwrap();
        let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let authority_key = ml_dsa_key(12);
        let authority = IdentityAuthority::from_pkcs8_der(
            [0x42; 16],
            vec![1],
            1,
            &ed_key.private_key_to_pkcs8().unwrap(),
            &authority_key.private_key_to_pkcs8().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            IdentityAuthority::from_pkcs8_der(
                [0x42; 16],
                vec![2],
                1,
                &ed_key.private_key_to_pkcs8().unwrap(),
                &ed_key.private_key_to_pkcs8().unwrap(),
            ),
            Err(crate::management::Error::InvalidIssuerKey)
        ));
        let mut store = setup_with_policy(&path, policy.clone());
        let request = store
            .verify_csr_request([1; 16], [9; 16], &[7; 32], &csr, 1)
            .unwrap();
        let issued = store
            .claim_and_issue(
                request,
                1,
                &authority,
                IdentityValidity {
                    not_before_us: 0,
                    expires_us: 10_000_000,
                    scope: vec![1, 2, 3],
                },
            )
            .unwrap();
        assert_eq!(issued.phase, EnrollmentPhase::Issued);
        assert_eq!(issued.node_id, 2);
        let signed = issued.signed_identity.clone().unwrap();
        let mut trust = ManagementTrust::new([0x42; 16]);
        trust
            .add_issuer(
                authority
                    .issuer_record(
                        crate::management::IssuerScope::for_identity(
                            vec![crate::NodeRole::Edge],
                            vec![1],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
            )
            .unwrap();
        let verified = verify_signed_identity(&mut trust, &signed, 1).unwrap();
        assert!(!verified.is_duplicate());
        assert_eq!(verified.object().seq, 1);
        match &verified.object().body {
            boreas_proto::objects::ObjectBody::NodeIdentity(body) => {
                assert_eq!(body.node_id, 2);
                assert_eq!(body.vip, [10, 20, 1, 2]);
                assert_eq!(body.identity_generation, 1);
                assert_eq!(
                    body.identity_pub_mldsa.as_slice(),
                    expected_identity_public.as_slice()
                );
                assert_eq!(body.identity_pub_ed25519, node_ed_public);
                assert_eq!(body.scope.as_slice(), &[1, 2, 3]);
            }
            _ => panic!("expected a NodeIdentity object"),
        }
        // Retry after restart must return the exact persisted signed result and the same slot.
        drop(store);
        let mut store = setup_with_policy(&path, policy.clone());
        let retry = store
            .verify_csr_request([1; 16], [9; 16], &[7; 32], &csr, 2)
            .unwrap();
        let retried = store
            .claim_and_issue(
                retry,
                2,
                &authority,
                IdentityValidity {
                    not_before_us: 0,
                    expires_us: 10_000_000,
                    scope: vec![1, 2, 3],
                },
            )
            .unwrap();
        assert_eq!(retried.phase, EnrollmentPhase::Issued);
        assert_eq!(retried.signed_identity.as_deref(), Some(signed.as_slice()));
        // A tampered CSR must fail the actual PKCS#10 proof/parsing on a fresh store,
        // not merely hit the already-bound cheap rejection path.
        let tamper_path = temp_path();
        let tamper_store = setup_with_policy(&tamper_path, policy.clone());
        let mut tampered = csr.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            tamper_store
                .verify_csr_request([1; 16], [9; 16], &[7; 32], &tampered, 1)
                .is_err()
        );
        cleanup(&tamper_path);
        // A valid CSR for the wrong algorithm is rejected, not silently downgraded.
        let ed_path = temp_path();
        let ed_store = setup_with_policy(&ed_path, policy.clone());
        let ed_csr_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let ed_csr = csr_from_key(&ed_csr_key);
        assert!(matches!(
            ed_store.verify_csr_request([1; 16], [9; 16], &[7; 32], &ed_csr, 1),
            Err(EnrollmentError::UnsupportedCsrKey)
        ));
        cleanup(&ed_path);
        drop(store);
        cleanup(&path);
    }
}
