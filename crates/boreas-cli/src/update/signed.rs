//! Shared signed metadata verification for read-only discovery and the
//! explicit, digest-approved online handoff to the installed offline helper.

mod online;
pub(super) use online::apply_online;

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use boreas_supervisor::manifest::{
    MAX_ED25519_PUBLIC_KEY_DER_BYTES, MAX_MANIFEST_BYTES, MAX_METADATA_LIFETIME_SECONDS,
    MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES, MAX_SIGNING_KEY_ID_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    ReleasePolicy, ReleaseRoot, SignatureEnvelope, VerifiedCandidate, validate_https_url, verify_release,
};
use boreas_supervisor::preflight::MAX_ELF_BYTES;
use boreas_supervisor::verified_stage::{DAEMON_STATE_SCHEMA, native_asset};

use super::{Issue, TOTAL, transport::fetch_https};
use crate::i18n::Lang;

const ED25519_SIGNATURE_BYTES: usize = 64;
const JSON: &str = "Accept: application/json";
const BINARY: &str = "Accept: application/octet-stream";

struct Feed {
    manifest: String,
    ed25519: String,
    mldsa65: String,
}

impl Feed {
    fn new(base: &str) -> Result<Self, Error> {
        validate_https_url(base).map_err(|_| Error::Feed)?;
        let base = base.trim_end_matches('/');
        let object = |name| -> Result<String, Error> {
            let url = format!("{base}/{name}");
            validate_https_url(&url).map_err(|_| Error::Feed)?;
            Ok(url)
        };
        Ok(Self {
            manifest: object("release-manifest.json")?,
            ed25519: object("release-manifest.ed25519.sig")?,
            mldsa65: object("release-manifest.mldsa65.sig")?,
        })
    }
}

struct Trust {
    root: ReleaseRoot,
    min_sequence: u64,
}

impl Trust {
    fn load(dir: &Path, uid: u32) -> Result<Self, Error> {
        // Trust is explicitly provisioned by the local operator. Reject links
        // and writable ancestry; root and the invoking UID are trusted here.
        if !dir.is_absolute() || dir.parent().is_none() {
            return Err(Error::Trust);
        }
        let mut ancestor = std::path::PathBuf::new();
        for component in dir.components() {
            if !matches!(component, Component::RootDir | Component::Normal(_)) {
                return Err(Error::Trust);
            }
            ancestor.push(component.as_os_str());
            let meta = fs::symlink_metadata(&ancestor).map_err(|_| Error::Trust)?;
            if !meta.is_dir() || !trusted_metadata(&meta, uid) {
                return Err(Error::Trust);
            }
        }
        let key_id = line(read_trust_file(dir, "key-id", MAX_SIGNING_KEY_ID_BYTES + 1, uid)?)?;
        let sequence = line(read_trust_file(dir, "min-sequence", 21, uid)?)?;
        let min_sequence = sequence
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == sequence)
            .ok_or(Error::Trust)?;
        let ed = read_trust_file(dir, "ed25519.der", MAX_ED25519_PUBLIC_KEY_DER_BYTES, uid)?;
        let pq = read_trust_file(dir, "mldsa65.der", MAX_ML_DSA_65_PUBLIC_KEY_DER_BYTES, uid)?;
        let root = ReleaseRoot::new(key_id, ed, pq).map_err(|_| Error::Trust)?;
        root.check_key_types().map_err(|_| Error::Trust)?;
        Ok(Self { root, min_sequence })
    }
}

fn trusted_metadata(meta: &fs::Metadata, uid: u32) -> bool {
    (meta.uid() == 0 || meta.uid() == uid) && meta.mode() & 0o022 == 0
}

fn read_trust_file(dir: &Path, name: &str, max: usize, uid: u32) -> Result<Vec<u8>, Error> {
    let path = dir.join(name);
    let expected = fs::symlink_metadata(&path).map_err(|_| Error::Trust)?;
    if !expected.is_file() || !trusted_metadata(&expected, uid) || expected.len() > max as u64 {
        return Err(Error::Trust);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::Trust)?;
    let meta = file.metadata().map_err(|_| Error::Trust)?;
    if !meta.is_file()
        || !trusted_metadata(&meta, uid)
        || meta.len() > max as u64
        || (meta.dev(), meta.ino()) != (expected.dev(), expected.ino())
    {
        return Err(Error::Trust);
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Trust)?;
    if bytes.len() > max {
        return Err(Error::Trust);
    }
    Ok(bytes)
}

fn line(mut bytes: Vec<u8>) -> Result<String, Error> {
    if bytes.pop() != Some(b'\n') || !bytes.iter().all(u8::is_ascii_graphic) {
        return Err(Error::Trust);
    }
    String::from_utf8(bytes).map_err(|_| Error::Trust)
}

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Feed,
    Trust,
    Architecture,
    Clock,
    Request(Object, Issue),
    SignatureLength(Object),
    Manifest,
    Policy,
    Unavailable(Issue),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Object {
    Manifest,
    Ed25519,
    MlDsa65,
}

impl Object {
    fn name(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Ed25519 => "Ed25519",
            Self::MlDsa65 => "ML-DSA-65",
        }
    }
}

impl Error {
    fn message(&self, lang: Lang) -> String {
        match self {
            Self::Feed => "Invalid signed feed base URL; expected a strict HTTPS URL".into(),
            Self::Trust => "Cannot load independently provisioned ReleaseRoot and sequence floor".into(),
            Self::Architecture => "Signed feed check requires x86-64 or AArch64 Linux".into(),
            Self::Clock => "Local UTC is unavailable or earlier than manifest issuance".into(),
            Self::Request(object, issue) => format!("{}: {}", object.name(), issue.message(lang)),
            Self::SignatureLength(object) => format!("Incorrect raw {} signature length", object.name()),
            Self::Manifest => "ReleaseRoot dual-signature or strict manifest validation failed".into(),
            Self::Policy => "Manifest rejected by freshness, sequence floor, or native asset/state policy".into(),
            Self::Unavailable(issue) => issue.message(lang),
        }
    }
}

#[derive(Debug)]
struct Receipt {
    sequence: u64,
    expires: String,
    arch: String,
    asset: String,
    manifest_sha256: String,
}

fn discover(
    feed: &Feed,
    trust: Trust,
    arch: &str,
    deadline: Instant,
    mut get: impl FnMut(&str, usize, &'static str, Instant) -> Result<Vec<u8>, Issue>,
    now: impl FnOnce() -> Result<u64, Error>,
) -> Result<Receipt, Error> {
    let (candidate, _) = authenticate_metadata(feed, trust, arch, deadline, &mut get, now)?;
    let manifest = candidate.manifest();
    let receipt = Receipt {
        sequence: candidate.sequence(),
        expires: manifest.manifest().expires().to_owned(),
        arch: arch.to_owned(),
        asset: candidate.asset().map_err(|_| Error::Policy)?.name().to_owned(),
        manifest_sha256: manifest_digest(&candidate),
    };
    if Instant::now() >= deadline {
        return Err(Error::Unavailable(Issue::Timeout));
    }
    Ok(receipt)
}

fn authenticate_metadata(
    feed: &Feed,
    trust: Trust,
    arch: &str,
    deadline: Instant,
    get: &mut impl FnMut(&str, usize, &'static str, Instant) -> Result<Vec<u8>, Issue>,
    now: impl FnOnce() -> Result<u64, Error>,
) -> Result<(VerifiedCandidate, SignatureEnvelope), Error> {
    let mut read = |object, url: &str, max, accept: &'static str| {
        if Instant::now() >= deadline {
            return Err(Error::Request(object, Issue::Timeout));
        }
        let bytes = get(url, max, accept, deadline).map_err(|issue| Error::Request(object, issue))?;
        if bytes.len() > max {
            return Err(Error::Request(object, Issue::TooLarge));
        }
        Ok(bytes)
    };
    let manifest = read(Object::Manifest, feed.manifest.as_str(), MAX_MANIFEST_BYTES, JSON)?;
    let ed25519 = read(Object::Ed25519, feed.ed25519.as_str(), ED25519_SIGNATURE_BYTES, BINARY)?
        .try_into()
        .map_err(|_| Error::SignatureLength(Object::Ed25519))?;
    let mldsa65 = read(Object::MlDsa65, feed.mldsa65.as_str(), ML_DSA_65_SIGNATURE_BYTES, BINARY)?;
    let envelope = SignatureEnvelope::new(trust.root.key_id(), ed25519, mldsa65)
        .map_err(|_| Error::SignatureLength(Object::MlDsa65))?;
    let verified = verify_release(&manifest, &envelope, &[trust.root]).map_err(|_| Error::Manifest)?;
    let now = now()?;
    if now < verified.manifest().issued_unix_seconds() {
        return Err(Error::Clock);
    }
    let policy = ReleasePolicy::new(vec![arch.to_owned()], MAX_METADATA_LIFETIME_SECONDS, trust.min_sequence)
        .map_err(|_| Error::Policy)?;
    let candidate = verified.into_candidate(&policy, arch, now).map_err(|_| Error::Policy)?;
    let manifest = candidate.manifest();
    let asset = candidate.asset().map_err(|_| Error::Policy)?;
    if manifest.manifest().min_compatible_state() != DAEMON_STATE_SCHEMA || asset.size() > MAX_ELF_BYTES {
        return Err(Error::Policy);
    }
    if Instant::now() >= deadline {
        return Err(Error::Unavailable(Issue::Timeout));
    }
    Ok((candidate, envelope))
}

fn manifest_digest(candidate: &VerifiedCandidate) -> String {
    use std::fmt::Write as _;

    let mut digest = String::with_capacity(64);
    for byte in openssl::sha::sha256(candidate.manifest().raw_bytes()) {
        write!(&mut digest, "{byte:02x}").expect("writing to String cannot fail");
    }
    digest
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|_| Error::Clock)
}

pub(super) fn run(base: &str, trust_dir: &str, lang: Lang) -> (u8, String, String) {
    let failure = |message| (1, String::new(), format!("Signed update check unavailable: {message}"));
    let feed = match Feed::new(base) {
        Ok(feed) => feed,
        Err(error) => return (2, String::new(), error.message(lang)),
    };
    if !Path::new(trust_dir).is_absolute() {
        return (2, String::new(), "--trust-dir must be absolute".into());
    }
    // SAFETY: both functions take no arguments and only query process IDs.
    let (uid, real_uid) = unsafe { (libc::geteuid(), libc::getuid()) };
    if uid == 0 || uid != real_uid {
        return failure("run without elevated privileges; use a separately provisioned public trust directory".into());
    }
    let Ok((arch, _)) = native_asset() else {
        return failure(Error::Architecture.message(lang));
    };
    let path = trust_dir.to_owned();
    let deadline = Instant::now() + TOTAL;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    if std::thread::Builder::new().spawn(move || {
        let result = Trust::load(Path::new(&path), uid).and_then(|trust| {
            discover(&feed, trust, arch, deadline, fetch_https, unix_now)
        });
        let _ = sender.send(result);
    }).is_err() {
        return failure(Issue::Transport.message(lang));
    }
    let result = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(Error::Unavailable(Issue::Timeout)),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(Error::Unavailable(Issue::Transport)),
    };
    match result {
        Ok(Receipt { sequence, expires, arch, asset, manifest_sha256 }) => (
            0,
            format!("ReleaseRoot dual signatures verified (metadata only)\nSequence: {sequence}\nExpires: {expires}\nTarget: {arch}\nAsset: {asset}\nManifest SHA-256: {manifest_sha256}\n{}", super::blocked(lang)),
            String::new(),
        ),
        Err(error) => failure(error.message(lang)),
    }
}

#[cfg(test)]
mod tests;
