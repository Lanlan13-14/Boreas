//! Durable enrollment transaction engine.
//!
//! This module does no CSR parsing or signature verification. The claim API accepts an
//! opaque verified-request token with private fields and no production constructor; it cannot
//! be made from an untrusted boolean. Until the reviewed CSR/signing integration is added,
//! production enrollment cannot be completed through this module.
//! The journal protects transaction consistency/torn writes, not against a malicious local
//! filesystem administrator or arbitrary journal rewriting.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"BENR";
const VERSION: u8 = 1;
const MAX_FRAME: usize = 40 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 16_384;
const MAX_INVITES: usize = 100_000;
const MAX_SLOTS: usize = 4_016;
pub const MAX_CSR_BYTES: usize = 16 * 1024;
pub const RECOVERY_WINDOW_US: u64 = 24 * 60 * 60 * 1_000_000;

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

/// Monotonically increasing writer epoch delivered by a durable external fencing authority.
/// Do not manufacture one from wall time, PID, or local state. Public integration should
/// provide it only after establishing single-writer ownership in the deployment control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriterFence {
    epoch: u64,
}
impl WriterFence {
    /// Internal constructor for trusted integration and unit tests. Not exposed to callers
    /// outside this crate; current module is intentionally not yet exported from lib.rs.
    /// Wraps an epoch issued by an independent durable fencing authority.
    /// This constructor does not authenticate or validate its source: choosing a number
    /// locally does not establish exclusive ownership. Deployments must obtain this value
    /// from a monotonic authority that fences every older writer.
    pub const fn from_external_authority(epoch: u64) -> Self {
        Self { epoch }
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
            .finish()
    }
}
impl VerifiedEnrollmentRequest {
    /// Internal verifier boundary: future CSR integration must hash exact DER and verify its
    /// proof-of-possession before constructing this type. Unit tests alone can bypass that.
    /// Only the in-crate CSR verifier may construct a request after cryptographic validation.
    #[allow(dead_code)] // Intentionally unavailable until a real verifier is integrated.
    fn from_verified_csr(
        invite_id: [u8; 16],
        enrollment_id: [u8; 16],
        bearer_secret: [u8; 32],
        raw_csr_der: Vec<u8>,
        raw_csr_sha256: [u8; 32],
        role: NodeRole,
        home_core_id: u8,
    ) -> Result<Self, EnrollmentError> {
        if raw_csr_der.is_empty() || raw_csr_der.len() > MAX_CSR_BYTES {
            return Err(EnrollmentError::CsrTooLarge);
        }
        Ok(Self {
            invite_id,
            enrollment_id,
            bearer_secret,
            raw_csr_sha256,
            raw_csr_der,
            role,
            home_core_id,
        })
    }
    #[cfg(test)]
    fn test_request(
        invite_id: [u8; 16],
        enrollment_id: [u8; 16],
        bearer_secret: [u8; 32],
        raw_csr_der: Vec<u8>,
        raw_csr_sha256: [u8; 32],
        role: NodeRole,
        home_core_id: u8,
    ) -> Result<Self, EnrollmentError> {
        Self::from_verified_csr(
            invite_id,
            enrollment_id,
            bearer_secret,
            raw_csr_der,
            raw_csr_sha256,
            role,
            home_core_id,
        )
    }
}

/// Identity bytes must be the exact signed result produced by the later IdentityAuthority
/// signing layer. The type has no public constructor and is persisted verbatim once issued.
#[derive(Clone, Debug)]
pub struct SignedIdentityResult {
    raw_signed_bytes: Vec<u8>,
}
impl SignedIdentityResult {
    #[allow(dead_code)] // Called when the IdentityAuthority signer integration is added.
    fn from_identity_authority(raw_signed_bytes: Vec<u8>) -> Result<Self, EnrollmentError> {
        if raw_signed_bytes.is_empty() || raw_signed_bytes.len() > 16 * 1024 {
            return Err(EnrollmentError::InvalidSignedResult);
        }
        Ok(Self { raw_signed_bytes })
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
#[derive(Clone, Debug)]
struct Tx {
    result: EnrollmentResult,
    invite_id: [u8; 16],
    enrollment_id: [u8; 16],
    csr_hash: [u8; 32],
    csr_der: Vec<u8>,
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

/// Store is single-process mutable and guarded by an exclusive create_new sidecar lock.
/// A crash leaves the lock behind; operators must inspect and explicitly remove it after
/// fencing the old writer. No automatic stale-lock stealing is attempted.
pub struct EnrollmentStore {
    path: PathBuf,
    lock_path: PathBuf,
    journal: File,
    _lock: Option<File>,
    fence: u64,
    provided_fence: u64,
    poisoned: bool,
    record_count: usize,
    remove_lock_on_drop: bool,
    #[cfg(test)]
    fail_next_write: bool,
    invites: BTreeMap<[u8; 16], InviteSpec>,
    slots: Vec<Slot>,
    used_slots: BTreeSet<u16>,
    generations: BTreeMap<u16, u64>,
    transactions: BTreeMap<([u8; 16], [u8; 16]), Tx>,
    invite_bindings: BTreeMap<[u8; 16], ([u8; 16], [u8; 32])>,
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
        if fence.epoch == 0 {
            return Err(EnrollmentError::StaleFence);
        }
        let path = path.as_ref().to_path_buf();
        validate_storage_path(&path)?;
        let lock_path = suffix_path(&path, ".writer-lock");
        let mut lock_options = OpenOptions::new();
        lock_options.write(true).create_new(true);
        #[cfg(unix)]
        lock_options.mode(0o600);
        let lock = lock_options.open(&lock_path).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                EnrollmentError::BusyLock
            } else {
                EnrollmentError::Io(e)
            }
        })?;
        if let Err(error) = validate_open_file(&lock_path, &lock) {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(error);
        }
        if let Err(error) = sync_parent_dir(&lock_path) {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(error);
        }
        match Self::open_locked(path, lock_path.clone(), lock, fence, invites, slots) {
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
                store.remove_lock_on_drop = true;
                Ok(store)
            }
            Err(error) => {
                // A recovery/open failure leaves the sentinel for explicit operator review;
                // it is not automatically stolen or removed.
                let _ = lock_path;
                Err(error)
            }
        }
    }

    fn open_locked(
        path: PathBuf,
        lock_path: PathBuf,
        lock: File,
        fence: WriterFence,
        invites: Vec<InviteSpec>,
        slots: Vec<Slot>,
    ) -> Result<Self, EnrollmentError> {
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
            lock_path,
            journal,
            _lock: Some(lock),
            fence: 0,
            provided_fence: fence.epoch,
            poisoned: false,
            record_count: 0,
            remove_lock_on_drop: false,
            #[cfg(test)]
            fail_next_write: false,
            invites: invite_map,
            slots,
            used_slots: BTreeSet::new(),
            generations: BTreeMap::new(),
            transactions: BTreeMap::new(),
            invite_bindings: BTreeMap::new(),
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
            if tx.csr_hash != req.raw_csr_sha256 || tx.csr_der != req.raw_csr_der {
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
        let tx = Tx {
            result: result.clone(),
            invite_id: req.invite_id,
            enrollment_id: req.enrollment_id,
            csr_hash: req.raw_csr_sha256,
            csr_der: req.raw_csr_der.clone(),
        };
        self.append_event(Event::Prepared {
            fence: self.fence,
            tx,
        })?;
        self.apply_prepared(
            result.node_id,
            generation,
            req.invite_id,
            req.enrollment_id,
            req.raw_csr_sha256,
            req.raw_csr_der.clone(),
            result.clone(),
        );
        Ok(result)
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
    fn apply_prepared(
        &mut self,
        node_id: u16,
        generation: u64,
        invite: [u8; 16],
        enrollment: [u8; 16],
        hash: [u8; 32],
        csr_der: Vec<u8>,
        tx: EnrollmentResult,
    ) {
        self.used_slots.insert(node_id);
        self.generations.insert(node_id, generation);
        self.invite_bindings.insert(invite, (enrollment, hash));
        self.transactions.insert(
            (invite, enrollment),
            Tx {
                result: tx,
                invite_id: invite,
                enrollment_id: enrollment,
                csr_hash: hash,
                csr_der,
            },
        );
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
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "injected partial write failure",
                ));
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
                    || !self.slots.iter().any(|s| *s == tx.result.slot)
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
                self.apply_prepared(
                    id,
                    tx.result.identity_generation,
                    tx.invite_id,
                    tx.enrollment_id,
                    tx.csr_hash,
                    tx.csr_der.clone(),
                    tx.result,
                );
            }
            Event::Issued { fence, tx } => {
                self.check_fence(fence)?;
                let key = (tx.invite_id, tx.enrollment_id);
                let old = self
                    .transactions
                    .get(&key)
                    .ok_or(EnrollmentError::CorruptJournal)?;
                if old.csr_hash != tx.csr_hash
                    || tx.result.phase != EnrollmentPhase::Issued
                    || tx.result.signed_identity.is_none()
                    || old.result.phase != EnrollmentPhase::Prepared
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
                    || tx.result.phase != EnrollmentPhase::Delivered
                    || old.result.phase != EnrollmentPhase::Issued
                {
                    return Err(EnrollmentError::CorruptJournal);
                }
                self.transactions.insert(key, tx);
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
        // Open stores release their owned lock on orderly shutdown. A process crash skips
        // Drop and leaves the sentinel for operator-reviewed recovery.
        if let Some(lock) = self._lock.take() {
            let _ = lock.sync_all();
            drop(lock);
            if self.remove_lock_on_drop {
                let _ = fs::remove_file(&self.lock_path);
            }
        }
        let _ = &self.path;
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

fn validate_storage_path(path: &Path) -> Result<(), EnrollmentError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Refuse symlinks at every component, not just the final directory.
    for ancestor in parent.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        if meta.file_type().is_symlink() {
            return Err(EnrollmentError::UnsafeStoragePath);
        }
    }
    let parent_meta = fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() {
        return Err(EnrollmentError::UnsafeStoragePath);
    }
    #[cfg(unix)]
    if parent_meta.permissions().mode() & 0o077 != 0 {
        return Err(EnrollmentError::UnsafeStoragePath);
    }
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
    Ok(())
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
    Ok(())
}
fn sync_parent_dir(path: &Path) -> Result<(), EnrollmentError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn secret_bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}
#[cfg(test)]
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, x) in chunk.chunks_exact(4).take(16).enumerate() {
            w[i] = u32::from_be_bytes([x[0], x[1], x[2], x[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut z) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = z
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            z = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, z].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
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
    fn request(enroll: u8, fill: u8) -> VerifiedEnrollmentRequest {
        let csr = vec![fill; 256];
        let digest = sha256(&csr);
        VerifiedEnrollmentRequest::test_request(
            [1; 16],
            [enroll; 16],
            [7; 32],
            csr,
            digest,
            NodeRole::Edge,
            1,
        )
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
                s.lock().unwrap().claim(request(i + 1, i + 1), 1).is_ok()
            }));
        }
        let wins = joins
            .into_iter()
            .map(|j| j.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
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
        f.write_all(b"BENR\x01\0\0\0\x01\0\0\0\0\x99").unwrap();
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
        assert!(matches!(recovered.claim(request(2, 3), 1), Ok(_)));
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
}
