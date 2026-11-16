//! Linux durable anti-replay watermarks for verified NetworkPolicy candidates.
//!
//! Stored candidate bytes are evidence/watermark data only. Reopening does not
//! reconstruct a VerifiedNetworkPolicy or authorize the stored candidate; every
//! advancement requires a fresh verified token bound to its exact raw TBS bytes.
//! A missing state file is indistinguishable from first use unless the caller
//! supplies an external expected watermark to `open_with_expected`. Restoring an
//! older whole-disk image likewise cannot be detected without an external
//! monotonic anchor.
#![cfg(feature = "openssl-backend")]

use crate::VerifiedNetworkPolicy;
use std::{fmt, io, path::Path};

#[cfg(target_os = "linux")]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, PathBuf},
};

#[cfg(target_os = "linux")]
const MAGIC: &[u8; 8] = b"BRNP\0\0\0\x01";
// Linux UAPI flags; this entire filesystem implementation is Linux-only.
#[cfg(target_os = "linux")]
const LINUX_O_NOFOLLOW: i32 = 0x20000;
#[cfg(target_os = "linux")]
const LINUX_O_NONBLOCK: i32 = 0x800;
#[cfg(target_os = "linux")]
const LINUX_O_CLOEXEC: i32 = 0x80000;
pub const MAX_NETWORK_POLICY_STATE_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Unsupported,
    UnsafePath,
    Busy,
    TooLarge,
    Corrupt,
    WrongNetwork,
    WrongRootFingerprint,
    RawTokenMismatch,
    PrefixConflict,
    SequenceRollback,
    Equivocation,
    IssuedAtRegression,
    Frozen,
    Poisoned,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitResult {
    Committed,
    Duplicate,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct Record {
    net: [u8; 16],
    root: [u8; 32],
    prefix: [u8; 4],
    seq: u64,
    issued: u64,
    object_hash: [u8; 32],
    raw_tbs: Vec<u8>,
}
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct State {
    record: Option<Record>,
    frozen: bool,
    conflict_hash: Option<[u8; 32]>,
}

/// Exclusive Linux durable watermark. It never reconstructs authorization from disk.
pub struct NetworkPolicyStore {
    #[cfg(target_os = "linux")]
    path: PathBuf,
    #[cfg(target_os = "linux")]
    _lock: File,
    #[cfg(target_os = "linux")]
    owner: u32,
    #[cfg(target_os = "linux")]
    net_id: [u8; 16],
    #[cfg(target_os = "linux")]
    root_fingerprint: [u8; 32],
    #[cfg(target_os = "linux")]
    state: State,
    #[cfg(target_os = "linux")]
    poisoned: bool,
}

impl NetworkPolicyStore {
    /// Open a store bound to one network and root fingerprint.
    /// `trusted_owner_uid` is an independent deployment input.
    /// On non-Linux this returns Unsupported without touching the filesystem.
    pub fn open(
        path: impl AsRef<Path>,
        net_id: [u8; 16],
        root_fingerprint: [u8; 32],
        trusted_owner_uid: u32,
    ) -> Result<Self, Error> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, net_id, root_fingerprint, trusted_owner_uid);
            return Err(Error::Unsupported);
        }
        #[cfg(target_os = "linux")]
        {
            let path = checked_path(path.as_ref(), trusted_owner_uid)?;
            let lock_path = suffix(&path, ".lock");
            let staging_path = suffix(&path, ".staging");
            reject_any_existing(&staging_path)?;
            check_lock_path(&lock_path)?;
            let lock = open_private(&lock_path, true)?;
            validate_file(&lock_path, &lock, trusted_owner_uid)?;
            match lock.try_lock() {
                Ok(()) => (),
                Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Busy),
                Err(std::fs::TryLockError::Error(error)) => return Err(Error::Io(error)),
            }
            File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
            let base = Self {
                path,
                _lock: lock,
                owner: trusted_owner_uid,
                net_id,
                root_fingerprint,
                state: State {
                    record: None,
                    frozen: false,
                    conflict_hash: None,
                },
                poisoned: false,
            };
            let state = base.load()?;
            if let Some(record) = &state.record {
                if record.net != net_id {
                    return Err(Error::WrongNetwork);
                }
                if record.root != root_fingerprint {
                    return Err(Error::WrongRootFingerprint);
                }
            }
            Ok(Self { state, ..base })
        }
    }

    /// Require the caller's external view of prior durable state.
    /// `None` explicitly means expected first use; `Some((seq, hash))` requires
    /// an existing state record with exactly that sequence and object hash.
    pub fn open_with_expected(
        path: impl AsRef<Path>,
        net_id: [u8; 16],
        root_fingerprint: [u8; 32],
        trusted_owner_uid: u32,
        expected: Option<(u64, [u8; 32])>,
    ) -> Result<Self, Error> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, net_id, root_fingerprint, trusted_owner_uid, expected);
            return Err(Error::Unsupported);
        }
        #[cfg(target_os = "linux")]
        {
            let store = Self::open(path, net_id, root_fingerprint, trusted_owner_uid)?;
            let actual = store.state.record.as_ref().map(|r| (r.seq, r.object_hash));
            if actual != expected {
                return Err(Error::Corrupt);
            }
            Ok(store)
        }
    }

    /// Durably advance using a freshly verified token and its exact raw TBS bytes.
    pub fn commit(
        &mut self,
        token: &VerifiedNetworkPolicy,
        raw_tbs: &[u8],
    ) -> Result<CommitResult, Error> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, token, raw_tbs);
            return Err(Error::Unsupported);
        }
        #[cfg(target_os = "linux")]
        {
            if self.poisoned {
                return Err(Error::Poisoned);
            }
            if self.state.frozen {
                return Err(Error::Frozen);
            }
            if token.net_id() != self.net_id {
                return Err(Error::WrongNetwork);
            }
            if token.root_key_fingerprint() != self.root_fingerprint {
                return Err(Error::WrongRootFingerprint);
            }
            if raw_tbs.is_empty() || raw_tbs.len() > boreas_proto::network_policy::MAX_TBS_LEN {
                return Err(Error::TooLarge);
            }
            if !token.matches_raw(raw_tbs) {
                return Err(Error::RawTokenMismatch);
            }
            let object_hash = sha256(raw_tbs)?;
            if let Some(old) = self.state.record.clone() {
                if old.prefix != token.overlay_base() {
                    return Err(Error::PrefixConflict);
                }
                if token.seq() < old.seq {
                    return Err(Error::SequenceRollback);
                }
                if token.seq() == old.seq {
                    if object_hash == old.object_hash {
                        return Ok(CommitResult::Duplicate);
                    }
                    self.state.frozen = true;
                    self.state.conflict_hash = Some(object_hash);
                    self.commit_or_poison()?;
                    return Err(Error::Equivocation);
                }
                if token.validity().0 < old.issued {
                    return Err(Error::IssuedAtRegression);
                }
            }
            self.state.record = Some(Record {
                net: self.net_id,
                root: self.root_fingerprint,
                prefix: token.overlay_base(),
                seq: token.seq(),
                issued: token.validity().0,
                object_hash,
                raw_tbs: raw_tbs.to_vec(),
            });
            self.commit_or_poison()?;
            Ok(CommitResult::Committed)
        }
    }

    #[cfg(target_os = "linux")]
    pub fn sequence(&self) -> Option<u64> {
        self.state.record.as_ref().map(|record| record.seq)
    }
    #[cfg(target_os = "linux")]
    pub fn is_frozen(&self) -> bool {
        self.state.frozen
    }

    #[cfg(target_os = "linux")]
    fn commit_or_poison(&mut self) -> Result<(), Error> {
        if let Err(error) = self.persist() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn load(&self) -> Result<State, Error> {
        let file = match open_existing(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(State {
                    record: None,
                    frozen: false,
                    conflict_hash: None,
                });
            }
            Err(error) => return Err(error.into()),
        };
        validate_file(&self.path, &file, self.owner)?;
        let len = usize::try_from(file.metadata()?.len()).map_err(|_| Error::TooLarge)?;
        if len > MAX_NETWORK_POLICY_STATE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut bytes = Vec::with_capacity(len);
        file.take(MAX_NETWORK_POLICY_STATE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_NETWORK_POLICY_STATE_BYTES {
            return Err(Error::TooLarge);
        }
        decode(&bytes)
    }

    #[cfg(target_os = "linux")]
    fn persist(&self) -> Result<(), Error> {
        let bytes = encode(&self.state)?;
        let staging = suffix(&self.path, ".staging");
        reject_any_existing(&staging)?;
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
}

#[cfg(target_os = "linux")]
fn sha256(bytes: &[u8]) -> Result<[u8; 32], Error> {
    use openssl::hash::{MessageDigest, hash};
    hash(MessageDigest::sha256(), bytes)
        .map_err(|_| Error::Corrupt)?
        .as_ref()
        .try_into()
        .map_err(|_| Error::Corrupt)
}
#[cfg(target_os = "linux")]
fn encode(state: &State) -> Result<Vec<u8>, Error> {
    let mut bytes = MAGIC.to_vec();
    bytes.push(u8::from(state.frozen));
    match &state.record {
        None => bytes.push(0),
        Some(record) => {
            if record.raw_tbs.len() > boreas_proto::network_policy::MAX_TBS_LEN {
                return Err(Error::TooLarge);
            }
            bytes.push(1);
            bytes.extend_from_slice(&record.net);
            bytes.extend_from_slice(&record.root);
            bytes.extend_from_slice(&record.prefix);
            bytes.extend_from_slice(&record.seq.to_be_bytes());
            bytes.extend_from_slice(&record.issued.to_be_bytes());
            bytes.extend_from_slice(&record.object_hash);
            bytes.extend_from_slice(&(record.raw_tbs.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&record.raw_tbs);
        }
    }
    if let Some(hash) = state.conflict_hash {
        bytes.extend_from_slice(&hash);
    }
    if bytes.len() > MAX_NETWORK_POLICY_STATE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
#[cfg(target_os = "linux")]
fn decode(bytes: &[u8]) -> Result<State, Error> {
    if bytes.len() < 10 || &bytes[..8] != MAGIC {
        return Err(Error::Corrupt);
    }
    let frozen = match bytes[8] {
        0 => false,
        1 => true,
        _ => return Err(Error::Corrupt),
    };
    let mut position = 10;
    let record = match bytes[9] {
        0 => None,
        1 => {
            if bytes.len() < 114 {
                return Err(Error::Corrupt);
            }
            let net = take::<16>(bytes, &mut position)?;
            let root = take::<32>(bytes, &mut position)?;
            let prefix = take::<4>(bytes, &mut position)?;
            let seq = u64::from_be_bytes(take::<8>(bytes, &mut position)?);
            let issued = u64::from_be_bytes(take::<8>(bytes, &mut position)?);
            let object_hash = take::<32>(bytes, &mut position)?;
            let raw_len = u32::from_be_bytes(take::<4>(bytes, &mut position)?) as usize;
            if raw_len > boreas_proto::network_policy::MAX_TBS_LEN
                || position
                    .checked_add(raw_len)
                    .is_none_or(|end| end > bytes.len())
            {
                return Err(Error::Corrupt);
            }
            let raw_tbs = bytes[position..position + raw_len].to_vec();
            position += raw_len;
            if sha256(&raw_tbs)? != object_hash {
                return Err(Error::Corrupt);
            }
            let candidate =
                boreas_proto::network_policy::NetworkPolicyCandidate::decode_tbs(&raw_tbs)
                    .map_err(|_| Error::Corrupt)?;
            if candidate.net_id != net
                || candidate.root_key_fingerprint != root
                || candidate.overlay_base != prefix
                || candidate.seq != seq
                || candidate.issued_at != issued
            {
                return Err(Error::Corrupt);
            }
            Some(Record {
                net,
                root,
                prefix,
                seq,
                issued,
                object_hash,
                raw_tbs,
            })
        }
        _ => return Err(Error::Corrupt),
    };
    let conflict_hash = if frozen {
        Some(take::<32>(bytes, &mut position)?)
    } else {
        None
    };
    if frozen && record.is_none() {
        return Err(Error::Corrupt);
    }
    if position != bytes.len() {
        return Err(Error::Corrupt);
    }
    Ok(State {
        record,
        frozen,
        conflict_hash,
    })
}
#[cfg(target_os = "linux")]
fn take<const N: usize>(bytes: &[u8], position: &mut usize) -> Result<[u8; N], Error> {
    let end = position.checked_add(N).ok_or(Error::Corrupt)?;
    let value = bytes.get(*position..end).ok_or(Error::Corrupt)?;
    *position = end;
    value.try_into().map_err(|_| Error::Corrupt)
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
        if mode & 0o022 != 0 && !(metadata.uid() == 0 && mode & 0o1000 != 0) {
            return Err(Error::UnsafePath);
        }
    }
    let canonical = fs::canonicalize(parent)?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if metadata.uid() != owner || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::UnsafePath);
    }
    let output = canonical.join(path.file_name().ok_or(Error::UnsafePath)?);
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
fn reject_any_existing(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
#[cfg(target_os = "linux")]
fn check_lock_path(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1 =>
        {
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
    Ok(options.open(path)?)
}
#[cfg(target_os = "linux")]
fn open_existing(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(LINUX_O_NOFOLLOW | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC);
    options.open(path)
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
    Ok(options.open(path)?)
}
#[cfg(target_os = "linux")]
fn validate_file(path: &Path, file: &File, owner: u32) -> Result<(), Error> {
    let path_meta = fs::symlink_metadata(path)?;
    let file_meta = file.metadata()?;
    if path_meta.file_type().is_symlink()
        || !path_meta.is_file()
        || path_meta.nlink() != 1
        || file_meta.nlink() != 1
        || path_meta.dev() != file_meta.dev()
        || path_meta.ino() != file_meta.ino()
        || file_meta.mode() & 0o777 != 0o600
        || file_meta.uid() != owner
    {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{root_authorization::NetworkRootPin, verify_network_policy};
    use boreas_proto::{network_policy::NetworkPolicyCandidate, objects::MldsaParameterSet};
    use openssl::{
        pkey::{KeyType, PKey},
        sign::Signer,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static ID: AtomicU64 = AtomicU64::new(1);

    fn temp() -> (PathBuf, PathBuf) {
        let id = ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("boreas-network-policy-{}-{id}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        (dir.clone(), dir.join("state"))
    }
    fn keys() -> (
        NetworkRootPin,
        PKey<openssl::pkey::Private>,
        PKey<openssl::pkey::Private>,
    ) {
        let ed = PKey::generate_ed25519().unwrap();
        let pq = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[19; 32]).unwrap();
        let pin = NetworkRootPin::provisioned(
            [7; 16],
            ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        (pin, ed, pq)
    }
    fn signed(
        pin: &NetworkRootPin,
        ed: &PKey<openssl::pkey::Private>,
        pq: &PKey<openssl::pkey::Private>,
        seq: u64,
        issued: u64,
        prefix: [u8; 4],
        lifetime: u64,
    ) -> (Vec<u8>, VerifiedNetworkPolicy) {
        let candidate = NetworkPolicyCandidate {
            net_id: [7; 16],
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: prefix,
            version: 1,
            seq,
            issued_at: issued,
            expires: issued + lifetime,
        };
        let raw = candidate.encode_tbs().unwrap();
        let message = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        let mut signer = Signer::new_without_digest(ed).unwrap();
        let ed_sig = signer.sign_oneshot_to_vec(&message).unwrap();
        let mut signer = Signer::new_without_digest(pq).unwrap();
        let pq_sig = signer.sign_oneshot_to_vec(&message).unwrap();
        let token = verify_network_policy(&raw, &ed_sig, &pq_sig, pin, [7; 16], issued).unwrap();
        (raw, token)
    }
    fn open(path: &Path, dir: &Path, pin: &NetworkRootPin) -> NetworkPolicyStore {
        NetworkPolicyStore::open(
            path,
            [7; 16],
            pin.fingerprint().unwrap(),
            fs::metadata(dir).unwrap().uid(),
        )
        .unwrap()
    }
    fn try_open(
        path: &Path,
        dir: &Path,
        pin: &NetworkRootPin,
    ) -> Result<NetworkPolicyStore, Error> {
        NetworkPolicyStore::open(
            path,
            [7; 16],
            pin.fingerprint().unwrap(),
            fs::metadata(dir).unwrap().uid(),
        )
    }

    #[test]
    fn restart_rollback_equivocation_freeze_and_expected_watermark() {
        let (dir, path) = temp();
        let uid = fs::metadata(&dir).unwrap().uid();
        let (pin, ed, pq) = keys();
        let (first, token) = signed(&pin, &ed, &pq, 4, 10, [10, 20, 0, 0], 1);
        let (lower, lower_token) = signed(&pin, &ed, &pq, 3, 11, [10, 20, 0, 0], 1);
        let (conflict, conflict_token) = signed(&pin, &ed, &pq, 4, 10, [10, 20, 0, 0], 2);
        let mut store = NetworkPolicyStore::open_with_expected(
            &path,
            [7; 16],
            pin.fingerprint().unwrap(),
            uid,
            None,
        )
        .unwrap();
        assert_eq!(
            store.commit(&token, &first).unwrap(),
            CommitResult::Committed
        );
        drop(store);
        let mut store = NetworkPolicyStore::open_with_expected(
            &path,
            [7; 16],
            pin.fingerprint().unwrap(),
            uid,
            Some((4, sha256(&first).unwrap())),
        )
        .unwrap();
        assert!(matches!(
            store.commit(&lower_token, &lower),
            Err(Error::SequenceRollback)
        ));
        assert!(matches!(
            store.commit(&conflict_token, &conflict),
            Err(Error::Equivocation)
        ));
        drop(store);
        let store = open(&path, &dir, &pin);
        assert!(store.is_frozen());
        drop(store);
        assert!(matches!(
            NetworkPolicyStore::open_with_expected(
                &path,
                [7; 16],
                pin.fingerprint().unwrap(),
                uid,
                None
            ),
            Err(Error::Corrupt)
        ));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn lock_reopen_busy_prefix_conflict_and_raw_binding() {
        let (dir, path) = temp();
        let (pin, ed, pq) = keys();
        let (raw, token) = signed(&pin, &ed, &pq, 1, 10, [10, 20, 0, 0], 1);
        let store = open(&path, &dir, &pin);
        assert!(matches!(try_open(&path, &dir, &pin), Err(Error::Busy)));
        drop(store);
        let mut store = open(&path, &dir, &pin);
        store.commit(&token, &raw).unwrap();
        let (changed_prefix, changed_token) = signed(&pin, &ed, &pq, 2, 11, [172, 19, 0, 0], 1);
        let (other_raw, _) = signed(&pin, &ed, &pq, 2, 11, [10, 20, 0, 0], 1);
        assert!(matches!(
            store.commit(&changed_token, &changed_prefix),
            Err(Error::PrefixConflict)
        ));
        assert!(matches!(
            store.commit(&changed_token, &other_raw),
            Err(Error::RawTokenMismatch)
        ));
        drop(store);
        let store = open(&path, &dir, &pin);
        assert_eq!(store.sequence(), Some(1));
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn expected_prior_and_every_truncation_fail_closed() {
        let (dir, path) = temp();
        let uid = fs::metadata(&dir).unwrap().uid();
        let (pin, ed, pq) = keys();
        let (raw, token) = signed(&pin, &ed, &pq, 1, 10, [10, 20, 0, 0], 1);
        assert!(matches!(
            NetworkPolicyStore::open_with_expected(
                &path,
                [7; 16],
                pin.fingerprint().unwrap(),
                uid,
                Some((9, [3; 32]))
            ),
            Err(Error::Corrupt)
        ));
        let state = State {
            record: Some(Record {
                net: [7; 16],
                root: token.root_key_fingerprint(),
                prefix: token.overlay_base(),
                seq: token.seq(),
                issued: token.validity().0,
                object_hash: sha256(&raw).unwrap(),
                raw_tbs: raw,
            }),
            frozen: false,
            conflict_hash: None,
        };
        let bytes = encode(&state).unwrap();
        for length in 0..bytes.len() {
            assert!(decode(&bytes[..length]).is_err(), "truncated at {length}");
        }
        assert!(decode(&bytes).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn disk_link_permission_and_staging_paths_are_rejected() {
        use std::os::unix::fs::symlink;

        let (pin, ed, pq) = keys();

        let (dir, path) = temp();
        fs::write(dir.join("target"), b"not a state").unwrap();
        symlink(dir.join("target"), &path).unwrap();
        assert!(matches!(try_open(&path, &dir, &pin), Err(Error::UnsafePath)));
        fs::remove_dir_all(dir).unwrap();

        let (dir, path) = temp();
        fs::write(dir.join("target"), b"not a state").unwrap();
        fs::hard_link(dir.join("target"), &path).unwrap();
        assert!(matches!(try_open(&path, &dir, &pin), Err(Error::UnsafePath)));
        fs::remove_dir_all(dir).unwrap();

        let (dir, path) = temp();
        let (raw, token) = signed(&pin, &ed, &pq, 1, 10, [10, 20, 0, 0], 1);
        let state_bytes = encode(&State {
            record: Some(Record {
                net: [7; 16],
                root: token.root_key_fingerprint(),
                prefix: token.overlay_base(),
                seq: token.seq(),
                issued: token.validity().0,
                object_hash: sha256(&raw).unwrap(),
                raw_tbs: raw,
            }),
            frozen: false,
            conflict_hash: None,
        })
        .unwrap();
        fs::write(&path, &state_bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(try_open(&path, &dir, &pin), Err(Error::UnsafePath)));
        assert_eq!(fs::read(&path).unwrap(), state_bytes);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_dir_all(dir).unwrap();

        let (dir, path) = temp();
        fs::write(suffix(&path, ".staging"), b"leftover staging").unwrap();
        assert!(matches!(try_open(&path, &dir, &pin), Err(Error::UnsafePath)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persistence_failure_poisons_and_restart_freeze_rejects_higher_sequence() {
        let (dir, path) = temp();
        let (pin, ed, pq) = keys();
        let (first, first_token) = signed(&pin, &ed, &pq, 4, 10, [10, 20, 0, 0], 1);
        let (conflict, conflict_token) = signed(&pin, &ed, &pq, 4, 10, [10, 20, 0, 0], 2);
        let (higher, higher_token) = signed(&pin, &ed, &pq, 5, 11, [10, 20, 0, 0], 1);
        let mut store = open(&path, &dir, &pin);
        store.commit(&first_token, &first).unwrap();
        let durable_before_duplicate = fs::read(&path).unwrap();
        assert_eq!(store.commit(&first_token, &first).unwrap(), CommitResult::Duplicate);
        assert_eq!(fs::read(&path).unwrap(), durable_before_duplicate);

        // Introduce the existing staging artifact only after open; persist fails before
        // touching it, and commit_or_poison must prevent any further mutation.
        fs::write(suffix(&path, ".staging"), b"fixture").unwrap();
        assert!(matches!(store.commit(&conflict_token, &conflict), Err(Error::UnsafePath)));
        assert!(matches!(store.commit(&higher_token, &higher), Err(Error::Poisoned)));
        drop(store);
        fs::remove_file(suffix(&path, ".staging")).unwrap();

        let mut store = open(&path, &dir, &pin);
        assert!(matches!(store.commit(&conflict_token, &conflict), Err(Error::Equivocation)));
        drop(store);
        let mut restarted = open(&path, &dir, &pin);
        assert!(restarted.is_frozen());
        assert!(matches!(restarted.commit(&higher_token, &higher), Err(Error::Frozen)));
        drop(restarted);
        fs::remove_dir_all(dir).unwrap();
    }
}
