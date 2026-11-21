//! Offline, binary-only staging for the external Linux supervisor.
//!
//! The store and its ancestry are an administrator trust boundary, not an
//! isolation boundary against a process already running with the store UID.
//! Config, provisioned keys, routes and daemon state are not release assets.

use std::{fs, io, path::Path};

pub use crate::ready_client::DAEMON_STATE_SCHEMA;

pub(crate) const WATERMARK: &str = "verified-release.state";

#[cfg(target_os = "linux")]
pub fn validate_store_path(root: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    if !root.is_absolute() || root.parent().is_none() {
        return Err(io::Error::other(
            "verified store must be a private absolute path",
        ));
    }
    // SAFETY: geteuid takes no arguments and does not modify memory.
    let uid = unsafe { libc::geteuid() };
    let mut path = std::path::PathBuf::from("/");
    for component in root.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(io::Error::other("invalid verified store path component"));
        };
        path.push(name);
        let meta = fs::symlink_metadata(&path)?;
        let sticky_root = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != uid)
            || (meta.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(io::Error::other("verified store has an unsafe ancestor"));
        }
        if path == root && (meta.uid() != uid || meta.mode() & 0o077 != 0) {
            return Err(io::Error::other(
                "verified store must be owned by the caller and private",
            ));
        }
    }
    Ok(())
}

pub fn is_verified_store(root: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(root.join(WATERMARK)) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(io::Error::other("invalid verified release watermark")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(all(target_os = "linux", feature = "openssl-backend"))]
mod linux {
    use super::*;
    use crate::manifest::VerifiedCandidate;
    use crate::preflight::{MAX_ELF_BYTES, Machine, inspect_elf};
    use crate::{
        Journal, Phase, UpgradeError, UpgradeStore, atomic_write, create_private_dir, flush_file,
        sync_dir,
    };
    use std::fmt::Write as _;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;

    type StageResult<T> = Result<T, Box<dyn std::error::Error>>;

    pub fn native_asset() -> StageResult<(&'static str, Machine)> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(("x86_64-unknown-linux-musl", Machine::X86_64)),
            "aarch64" => Ok(("aarch64-unknown-linux-musl", Machine::Aarch64)),
            _ => {
                Err(io::Error::other("verified staging supports x86-64/AArch64 Linux only").into())
            }
        }
    }

    /// Open once with no symlink following and copy into a bounded buffer.
    /// Validation and publication use the *same* bytes, not a reopened input.
    pub fn read_input(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        let pre = fs::symlink_metadata(path)?;
        if !pre.is_file() || pre.len() > limit {
            return Err(io::Error::other("input must be a bounded regular file"));
        }
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let meta = f.metadata()?;
        if !meta.is_file()
            || meta.dev() != pre.dev()
            || meta.ino() != pre.ino()
            || meta.len() > limit
        {
            return Err(io::Error::other("input changed or exceeds limit"));
        }
        let mut bytes = Vec::new();
        f.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(io::Error::other("input exceeds limit"));
        }
        Ok(bytes)
    }

    fn sha256(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(64);
        for b in openssl::sha::sha256(bytes) {
            write!(&mut hex, "{b:02x}").expect("String write cannot fail");
        }
        hex
    }

    fn is_sha256(hex: &str) -> bool {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    fn parse_version(version: &str) -> StageResult<(u64, &str)> {
        let (seq, digest) = version
            .strip_prefix("release-")
            .and_then(|s| s.split_once('-'))
            .ok_or_else(|| io::Error::other("invalid verified release id"))?;
        let n = seq.parse::<u64>()?;
        if n == 0 || n.to_string() != seq || !is_sha256(digest) {
            return Err(io::Error::other("invalid verified release id").into());
        }
        Ok((n, digest))
    }

    fn read_watermark(root: &Path) -> StageResult<Option<(String, String)>> {
        if !is_verified_store(root)? {
            return Ok(None);
        }
        let bytes = read_input(&root.join(WATERMARK), 192)?;
        let raw = std::str::from_utf8(&bytes)?;
        let (version, manifest_hash) = raw
            .strip_suffix('\n')
            .and_then(|s| s.split_once(' '))
            .ok_or_else(|| io::Error::other("invalid verified release watermark"))?;
        parse_version(version)?;
        if !is_sha256(manifest_hash) {
            return Err(io::Error::other("invalid manifest hash in release watermark").into());
        }
        Ok(Some((version.to_owned(), manifest_hash.to_owned())))
    }

    /// Stage the selected asset of an authenticated and policy-checked manifest.
    /// A retained prior binary is never copied over or removed. A failed trial
    /// requires an explicit reset (same release) or a newer signed release.
    pub fn stage(root: &Path, candidate: &VerifiedCandidate, binary: &[u8]) -> StageResult<String> {
        validate_store_path(root)?;
        let (arch, machine) = native_asset()?;
        if candidate.arch() != arch || inspect_elf(binary)?.machine != machine {
            return Err(io::Error::other("verified artifact must be a native static ELF").into());
        }
        if candidate.manifest().manifest().min_compatible_state() != DAEMON_STATE_SCHEMA {
            return Err(
                io::Error::other("manifest must support the current daemon state schema").into(),
            );
        }
        candidate.verify_bytes(binary)?;
        let version = format!(
            "release-{}-{}",
            candidate.sequence(),
            candidate.asset()?.sha256()
        );
        let manifest_hash = sha256(candidate.manifest().raw_bytes());
        let store = UpgradeStore::open(root)?;
        let _lock = store.lock_exclusive()?;
        let watermark = read_watermark(root)?;
        let before = store.journal()?;
        let active = store.active_version()?;
        if let Some((previous, previous_manifest)) = &watermark {
            let (highest, _) = parse_version(previous)?;
            if candidate.sequence() < highest {
                return Err(io::Error::other("release sequence rollback").into());
            }
            if candidate.sequence() == highest
                && (&version != previous || &manifest_hash != previous_manifest)
            {
                return Err(io::Error::other(
                    "signed manifest equivocation at the same release sequence",
                )
                .into());
            }
            if before.as_ref().is_some_and(|j| j.new_version == version) {
                if before.as_ref().is_some_and(|j| j.phase == Phase::Activated) {
                    return Err(UpgradeError::WrongState.into());
                }
                if let Some(journal) = &before
                    && journal.phase == Phase::Confirmed
                    && active.as_deref() != Some(version.as_str())
                {
                    return Err(UpgradeError::WrongState.into());
                }
                validate_binary(&store, &version)?;
                return Ok(version);
            }
        } else if before.is_some() || active.is_some() || store.trial_state()?.is_some() {
            return Err(io::Error::other("cannot adopt an existing generic upgrade store").into());
        }
        if let Some(journal) = &before {
            match journal.phase {
                Phase::Activated => return Err(UpgradeError::WrongState.into()),
                Phase::Prepared => {
                    // Only replace a failed (not merely pending) release.
                    let trial = store.trial_state()?;
                    if active != journal.old_version
                        || !trial.is_some_and(|t| t.version == journal.new_version && !t.in_flight)
                    {
                        return Err(UpgradeError::WrongState.into());
                    }
                }
                Phase::Confirmed if active.as_deref() != Some(journal.new_version.as_str()) => {
                    return Err(UpgradeError::WrongState.into());
                }
                Phase::Confirmed => {}
            }
        }
        // Persist the acceptance floor first. A crash after this point can
        // resume only the exact signed manifest, or a newer signed sequence.
        atomic_write(
            root,
            WATERMARK,
            format!("{version} {manifest_hash}\n").as_bytes(),
        )?;
        let dest = store.version_dir(&version)?;
        match fs::symlink_metadata(&dest) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let temp = root.join("staging").join(format!("{version}.verified.tmp"));
                match fs::symlink_metadata(&temp) {
                    Ok(meta) if meta.is_dir() => fs::remove_dir_all(&temp)?,
                    Ok(_) => return Err(io::Error::other("unsafe verified staging entry").into()),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                create_private_dir(&temp)?;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o700)
                    .open(temp.join("boreas"))?;
                file.write_all(binary)?;
                flush_file(&file)?;
                sync_dir(&temp)?;
                fs::rename(&temp, &dest)?;
            }
            Ok(_) => {
                validate_binary(&store, &version)?;
            }
            Err(e) => return Err(e.into()),
        }
        sync_dir(&root.join("staging"))?;
        sync_dir(&root.join("versions"))?;
        store.write_journal(&Journal {
            old_version: active,
            new_version: version.clone(),
            phase: Phase::Prepared,
        })?;
        Ok(version)
    }

    pub fn validate_binary(store: &UpgradeStore, version: &str) -> StageResult<PathBuf> {
        checked_binary(store, version).map(|(path, _)| path)
    }

    pub fn checked_binary(store: &UpgradeStore, version: &str) -> StageResult<(PathBuf, Vec<u8>)> {
        let (seq, digest) = parse_version(version)?;
        let (highest, _) = read_watermark(store.root())?
            .ok_or_else(|| io::Error::other("missing verified release watermark"))?;
        let highest_sequence = parse_version(&highest)?.0;
        if seq > highest_sequence || (seq == highest_sequence && version != highest) {
            return Err(io::Error::other(
                "version disagrees with the authenticated release watermark",
            )
            .into());
        }
        store.ensure_version_exists(version)?;
        let path = store.version_dir(version)?.join("boreas");
        let binary = read_input(&path, MAX_ELF_BYTES)?;
        if sha256(&binary) != digest {
            return Err(io::Error::other("stored binary SHA-256 mismatch").into());
        }
        let (_, machine) = native_asset()?;
        if inspect_elf(&binary)?.machine != machine {
            return Err(io::Error::other("stored image is not a native static ELF").into());
        }
        Ok((path, binary))
    }

    pub fn sequence(version: &str) -> StageResult<u64> {
        parse_version(version).map(|(n, _)| n)
    }
}

#[cfg(all(target_os = "linux", feature = "openssl-backend"))]
pub use linux::{checked_binary, native_asset, read_input, sequence, stage, validate_binary};
