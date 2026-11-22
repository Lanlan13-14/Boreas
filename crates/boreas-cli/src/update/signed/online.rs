//! No online execution path: pin the reviewed manifest before fetching its
//! asset, then hand four local files to the unchanged offline helper.

use std::ffi::{CString, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::num::NonZeroU32;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use boreas_supervisor::preflight::{Machine, inspect_elf};

use super::super::{offline, transport::fetch_unprivileged};
use super::{
    BINARY, Error, Feed, Issue, Lang, SignatureEnvelope, Trust, VerifiedCandidate,
    authenticate_metadata, manifest_digest, native_asset, unix_now,
};

const TRUST_DIR: &str = "/etc/boreas/release-trust";
const BUDGET: Duration = Duration::from_secs(120);
const NAMES: [&str; 4] = ["manifest", "artifact", "ed25519.sig", "mldsa65.sig"];

#[derive(Debug, PartialEq, Eq)]
enum Rejected {
    Metadata(Error),
    Approval,
    ArtifactRequest(Issue),
    ArtifactIdentity,
    ArtifactElf,
}

impl Rejected {
    fn message(&self, lang: Lang) -> String {
        match self {
            Self::Metadata(error) => error.message(lang),
            Self::Approval => "Manifest SHA-256 does not match operator approval; no artifact requested".into(),
            Self::ArtifactRequest(issue) => format!("Artifact: {}", issue.message(lang)),
            Self::ArtifactIdentity => "Artifact does not match the signed length and SHA-256".into(),
            Self::ArtifactElf => "Artifact is not a native static ELF".into(),
        }
    }
}

#[derive(Debug)]
struct Bundle {
    candidate: VerifiedCandidate,
    signatures: SignatureEnvelope,
    artifact: Vec<u8>,
}

fn download(
    feed: &Feed,
    trust: Trust,
    (arch, machine): (&str, Machine),
    approved: &str,
    deadline: Instant,
    mut get: impl FnMut(&str, usize, &'static str, Instant) -> Result<Vec<u8>, Issue>,
    mut now: impl FnMut() -> Result<u64, Error>,
) -> Result<Bundle, Rejected> {
    let (candidate, signatures) = authenticate_metadata(feed, trust, arch, deadline, &mut get, &mut now)
        .map_err(Rejected::Metadata)?;
    if manifest_digest(&candidate) != approved {
        return Err(Rejected::Approval);
    }
    let asset = candidate.asset().map_err(|_| Rejected::ArtifactIdentity)?;
    let max = usize::try_from(asset.size()).map_err(|_| Rejected::ArtifactIdentity)?;
    if Instant::now() >= deadline {
        return Err(Rejected::ArtifactRequest(Issue::Timeout));
    }
    let artifact = get(asset.url(), max, BINARY, deadline).map_err(Rejected::ArtifactRequest)?;
    asset.verify_bytes(&artifact).map_err(|_| Rejected::ArtifactIdentity)?;
    let image = inspect_elf(&artifact).map_err(|_| Rejected::ArtifactElf)?;
    if image.machine != machine {
        return Err(Rejected::ArtifactElf);
    }
    let manifest = candidate.manifest().manifest();
    let at = now().map_err(Rejected::Metadata)?;
    if at < manifest.issued_unix_seconds() || manifest.check_expiry(at).is_err() {
        return Err(Rejected::Metadata(Error::Policy));
    }
    if Instant::now() >= deadline {
        return Err(Rejected::ArtifactRequest(Issue::Timeout));
    }
    Ok(Bundle { candidate, signatures, artifact })
}

struct Spool(PathBuf);

impl Spool {
    fn create(parent: &Path) -> io::Result<Self> {
        let template = CString::new(parent.join("boreas-online.XXXXXX").as_os_str().as_bytes())?;
        let mut bytes = template.into_bytes_with_nul();
        // SAFETY: writable NUL-terminated template; mkdtemp creates a fresh 0700 directory.
        if unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) }.is_null() {
            return Err(io::Error::last_os_error());
        }
        bytes.pop();
        Ok(Self(OsString::from_vec(bytes).into()))
    }

    fn prepare(&self, bundle: &Bundle, reader_gid: u32, approved: &str) -> io::Result<Vec<String>> {
        let inputs = [
            bundle.candidate.manifest().raw_bytes(),
            bundle.artifact.as_slice(),
            bundle.signatures.ed25519().as_slice(),
            bundle.signatures.ml_dsa_65(),
        ];
        let mut args = vec!["apply".into(), "--confirm-manifest-sha256".into(), approved.into()];
        for (name, bytes) in NAMES.into_iter().zip(inputs) {
            let path = self.0.join(name);
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            chown(&path, None, Some(reader_gid))?;
            file.set_permissions(fs::Permissions::from_mode(0o640))?;
            args.push(path.into_os_string().into_string().map_err(|_| io::Error::other("invalid spool path"))?);
        }
        // Open the directory to the service group only after all files are complete.
        chown(&self.0, None, Some(reader_gid))?;
        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o750))?;
        Ok(args)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("Could not remove temporary update spool {}: {error}", self.0.display());
        }
    }
}

fn account(name: &std::ffi::CStr) -> Option<(NonZeroU32, NonZeroU32)> {
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = [0; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: each argument points to a live buffer of the specified type and size.
    let status = unsafe {
        libc::getpwnam_r(name.as_ptr(), entry.as_mut_ptr(), buffer.as_mut_ptr(), buffer.len(), &mut result)
    };
    if status != 0 || result.is_null() {
        return None;
    }
    // SAFETY: success with a nonnull result initialized entry; only copy the numeric IDs.
    let entry = unsafe { entry.assume_init() };
    Some((NonZeroU32::new(entry.pw_uid)?, NonZeroU32::new(entry.pw_gid)?))
}

pub(in crate::update) fn apply_online(base: &str, approved: &str, lang: Lang) -> (u8, String, String) {
    let feed = match Feed::new(base) {
        Ok(feed) => feed,
        Err(error) => return (2, String::new(), error.message(lang)),
    };
    let helper = match offline::installed_helper() {
        Ok(helper) => helper,
        Err(message) => return offline::failed(message),
    };
    let Ok(target) = native_asset() else {
        return offline::failed(Error::Architecture.message(lang));
    };
    let Ok(trust) = Trust::load(Path::new(TRUST_DIR), 0) else {
        return offline::failed(Error::Trust.message(lang));
    };
    let (Some((uid, gid)), Some((service_uid, service_gid))) = (account(c"nobody"), account(c"boreas")) else {
        return offline::failed("Online apply requires non-root nobody and boreas accounts");
    };
    if uid == service_uid || gid == service_gid {
        return offline::failed("Update transport must not share the boreas UID or GID");
    }
    // Do not follow environment-selected temporary directories or an untrusted /run.
    let parent = Path::new("/run");
    if !parent.ancestors().all(|path| {
        fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)
    }) {
        return offline::failed("Temporary update spool ancestry is not trusted");
    }
    let deadline = Instant::now() + BUDGET;
    let bundle = match download(&feed, trust, target, approved, deadline, |url, cap, accept, until| {
        fetch_unprivileged(url, cap, accept, until, uid, gid)
    }, unix_now) {
        Ok(bundle) => bundle,
        Err(error) => return offline::failed(format!("Online apply rejected: {}", error.message(lang))),
    };
    let args_and_spool = Spool::create(parent).and_then(|spool| {
        let args = spool.prepare(&bundle, service_gid.get(), approved)?;
        Ok((args, spool))
    });
    let (args, _spool) = match args_and_spool {
        Ok(inputs) => inputs,
        Err(error) => return offline::failed(format!("Cannot prepare temporary update spool: {error}")),
    };
    // The offline helper verifies independently as boreas, with the installed
    // trust, current time and persistent watermark, before stopping the unit.
    offline::invoke(helper, &args)
}

#[cfg(test)]
mod tests;
