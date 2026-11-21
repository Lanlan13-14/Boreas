//! Linux mesh CoreLSA replay/evidence ledger. The filesystem state is not a
//! source of authority: `ManagementTrust` verifies every envelope on restore.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};

use crate::{
    MAX_HOME_CORE_ID,
    management::MAX_SIGNED_OBJECT_BYTES,
    status_store::{
        checked_path, open_existing, open_private, open_staging, suffix, validate_file,
    },
};

const MAGIC: &[u8; 8] = b"BRLS\0\0\0\x01";
const HEADER: usize = MAGIC.len() + 16 + 32 + 1;
const DIGEST: usize = 32;
const MAX_BYTES: usize =
    HEADER + DIGEST + MAX_HOME_CORE_ID as usize * (1 + 4 + 2 * MAX_SIGNED_OBJECT_BYTES);

#[derive(Debug)]
pub(crate) struct Ledger {
    path: PathBuf,
    staging: PathBuf,
    lock: File,
    owner: u32,
    header: [u8; HEADER],
    pub(crate) heads: BTreeMap<u8, Pair>,
    pub(crate) blocked: bool,
    pub(crate) conflict_pending: bool,
}

#[derive(Debug)]
pub(crate) struct Pair {
    pub(crate) head: Vec<u8>,
    pub(crate) conflict: Option<Vec<u8>>,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid CoreLSA ledger")
}

fn absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Err(invalid()),
    }
}

impl Ledger {
    pub(crate) fn open(
        path: &Path,
        owner: u32,
        net: [u8; 16],
        root: [u8; 32],
        local: u8,
    ) -> Result<Self, crate::status_store::Error> {
        if !(1..=MAX_HOME_CORE_ID).contains(&local) {
            return Err(invalid().into());
        }
        let path = checked_path(path, owner)?;
        let lock_path = suffix(&path, ".lock");
        let staging = suffix(&path, ".staging");
        let lock = open_private(&lock_path, true)?;
        validate_file(&lock_path, &lock, owner)?;
        lock.try_lock().map_err(|e| match e {
            fs::TryLockError::WouldBlock => crate::status_store::Error::Busy,
            fs::TryLockError::Error(e) => e.into(),
        })?;
        absent(&staging)?;
        let mut byte = [0];
        let marker = match lock.metadata()?.len() {
            0 => 0,
            1 => {
                lock.read_exact_at(&mut byte, 0)?;
                match byte[0] {
                    b'1' | b'2' => byte[0],
                    _ => return Err(invalid().into()),
                }
            }
            _ => return Err(invalid().into()),
        };
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(MAGIC);
        header[8..24].copy_from_slice(&net);
        header[24..56].copy_from_slice(&root);
        header[56] = local;
        let (heads, initialize) = match open_existing(&path) {
            Ok(file) => {
                validate_file(&path, &file, owner)?;
                let mut raw = Vec::new();
                file.take((MAX_BYTES + 1) as u64).read_to_end(&mut raw)?;
                if raw.len() > MAX_BYTES || raw.len() < HEADER + DIGEST || !raw.starts_with(&header)
                {
                    return Err(invalid().into());
                }
                let (payload, checksum) = raw.split_at(raw.len() - DIGEST);
                if openssl::sha::sha256(payload).as_slice() != checksum {
                    return Err(invalid().into());
                }
                (decode(&payload[HEADER..])?, false)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && marker == 0 => (BTreeMap::new(), true),
            Err(e) => return Err(e.into()),
        };
        let store = Self {
            path,
            staging,
            lock,
            owner,
            header,
            heads,
            blocked: false,
            conflict_pending: marker == b'2',
        };
        if initialize {
            store.commit()?;
        }
        if marker == 0 {
            store.mark(b'1')?;
            File::open(store.path.parent().ok_or_else(invalid)?)?.sync_all()?;
        }
        Ok(store)
    }

    fn mark(&self, state: u8) -> io::Result<()> {
        self.lock.write_all_at(&[state], 0)?;
        self.lock.sync_all()
    }

    pub(crate) fn mark_conflict(&self) -> io::Result<()> {
        // Persist a stop marker before allocating or replacing the image. If
        // the evidence write later fails (e.g. ENOSPC), the old image is not
        // mistaken for an unconflicted directory on restart.
        self.mark(b'2')
    }

    pub(crate) fn commit(&self) -> Result<(), crate::status_store::Error> {
        // Never clean up a failed staging file. Once its directory entry is
        // durable, an interrupted/failed transaction blocks restart, even if
        // only the previous image made it to disk.
        let parent = File::open(self.path.parent().ok_or_else(invalid)?)?;
        let mut file = open_staging(&self.staging)?;
        validate_file(&self.staging, &file, self.owner)?;
        parent.sync_all()?;
        let mut bytes = self.header.to_vec();
        for (&id, pair) in &self.heads {
            bytes.push(id);
            for side in [Some(pair.head.as_slice()), pair.conflict.as_deref()] {
                let raw = side.unwrap_or_default();
                bytes.extend_from_slice(&(raw.len() as u16).to_be_bytes());
                bytes.extend_from_slice(raw);
            }
        }
        let checksum = openssl::sha::sha256(&bytes);
        file.write_all(&bytes)?;
        file.write_all(&checksum)?;
        file.sync_all()?;
        fs::rename(&self.staging, &self.path)?;
        parent.sync_all()?;
        Ok(())
    }
}

fn decode(mut raw: &[u8]) -> io::Result<BTreeMap<u8, Pair>> {
    let mut heads = BTreeMap::new();
    let mut last = 0;
    while let Some((&id, rest)) = raw.split_first() {
        if id <= last || id > MAX_HOME_CORE_ID {
            return Err(invalid());
        }
        raw = rest;
        let head = envelope(&mut raw)?;
        let other = envelope(&mut raw)?;
        if head.is_empty() {
            return Err(invalid());
        }
        heads.insert(id, Pair {
            head: head.to_vec(),
            conflict: (!other.is_empty()).then(|| other.to_vec()),
        });
        last = id;
    }
    Ok(heads)
}

fn envelope<'a>(raw: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let (len, rest) = raw.split_first_chunk::<2>().ok_or_else(invalid)?;
    let size = usize::from(u16::from_be_bytes(*len));
    if size > MAX_SIGNED_OBJECT_BYTES {
        return Err(invalid());
    }
    let (object, rest) = rest.split_at_checked(size).ok_or_else(invalid)?;
    *raw = rest;
    Ok(object)
}
