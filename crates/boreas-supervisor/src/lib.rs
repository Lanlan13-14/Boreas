//! Minimal, self-contained primitives for an external Boreas supervisor.
//!
//! This crate intentionally does not download, authenticate, execute, or install a
//! release. A future release-verification layer must provide independently
//! verified artifact and manifest bytes plus provenance before calling
//! [`UpgradeStore::prepare`]. There is no `bool`/"verified" escape hatch here.
//! Hash/signature verification, preflight, process supervision, and OS service
//! integration are NOT IMPLEMENTED and this crate makes no production-readiness
//! or release-authenticity claim.
//!
//! Transactions use a durable journal and one atomically replaced active pointer.
//! Unconfirmed activations are rolled back by [`UpgradeStore::recover`], which a
//! separate supervisor process must invoke before starting the selected version.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

const JOURNAL_FILE: &str = "upgrade.journal";
const ACTIVE_FILE: &str = "active.version";
const FORMAT: &str = "BOREAS-UPGRADE-1";

#[derive(Debug)]
pub enum UpgradeError {
    Io(io::Error),
    Invalid(&'static str),
    CorruptJournal,
    NoTransaction,
    WrongState,
    UnsupportedPlatform(&'static str),
}
impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "upgrade I/O error: {e}"),
            Self::Invalid(s) => write!(f, "invalid upgrade input: {s}"),
            Self::CorruptJournal => f.write_str("upgrade journal is corrupt or unsupported"),
            Self::NoTransaction => f.write_str("no upgrade transaction exists"),
            Self::WrongState => f.write_str("operation is invalid in the current state"),
            Self::UnsupportedPlatform(s) => write!(f, "unsupported durability operation: {s}"),
        }
    }
}
impl Error for UpgradeError { fn source(&self) -> Option<&(dyn Error + 'static)> { if let Self::Io(e) = self { Some(e) } else { None } } }
impl From<io::Error> for UpgradeError { fn from(value: io::Error) -> Self { Self::Io(value) } }
pub type Result<T> = std::result::Result<T, UpgradeError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Phase { Prepared, Activated, Confirmed }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Journal { pub old_version: Option<String>, pub new_version: String, pub phase: Phase }

/// Caller-supplied release facts. Strings are identifiers only, not evidence of
/// authenticity. `prepare` enforces safe layout but does not validate the binary.
#[derive(Clone, Debug)]
pub struct Candidate { pub version: String }

/// Filesystem-backed transaction store rooted in an administrator-chosen directory.
/// The root and all its parents must be trusted and not writable by attackers.
/// Linux is the only platform with the documented directory-fsync durability
/// contract. Windows currently fails closed rather than claiming equivalent
/// parent-directory durability. No paths outside `root` are accepted.
pub struct UpgradeStore { root: PathBuf, versions: PathBuf, staging: PathBuf }

impl UpgradeStore {
    /// Create/open a store. Root must already exist and be a real directory (not a symlink).
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        reject_symlink_components(&root)?;
        let meta = fs::symlink_metadata(&root)?;
        if !meta.is_dir() || meta.file_type().is_symlink() { return Err(UpgradeError::Invalid("root must be a non-symlink directory")); }
        let versions = root.join("versions");
        let staging = root.join("staging");
        ensure_child_dir(&root, &versions)?;
        ensure_child_dir(&root, &staging)?;
        sync_dir(&root)?;
        Ok(Self { root, versions, staging })
    }
    pub fn root(&self) -> &Path { &self.root }

    /// Install an already-verified candidate directory. `artifact` must be a
    /// real directory on the same filesystem as this store; files are copied
    /// without following symlinks, then synced before an atomic rename.
    /// Authenticity MUST be established by a genuine verifier before this call.
    pub fn prepare(&self, candidate: &Candidate, artifact: impl AsRef<Path>) -> Result<Journal> {
        validate_version(&candidate.version)?;
        let old = self.active_version()?;
        if old.as_deref() == Some(candidate.version.as_str()) { return Err(UpgradeError::Invalid("candidate is already active")); }
        if self.read_journal()?.is_some_and(|j| j.phase != Phase::Confirmed) { return Err(UpgradeError::WrongState); }
        let src = artifact.as_ref();
        reject_symlink_components(src)?;
        let src_meta = fs::symlink_metadata(src)?;
        if !src_meta.is_dir() || src_meta.file_type().is_symlink() { return Err(UpgradeError::Invalid("artifact must be a real directory")); }
        if same_device(&self.root, src)? == false { return Err(UpgradeError::Invalid("artifact must be on the store filesystem")); }
        let stage = self.staging.join(format!("{}.tmp", candidate.version));
        let dest = self.versions.join(&candidate.version);
        if stage.exists() || dest.exists() { return Err(UpgradeError::Invalid("candidate stage/version already exists")); }
        copy_tree_no_symlinks(src, &stage)?;
        sync_tree(&stage)?;
        sync_dir(&self.staging)?;
        fs::rename(&stage, &dest)?;
        sync_dir(&self.versions)?;
        let journal = Journal { old_version: old, new_version: candidate.version.clone(), phase: Phase::Prepared };
        self.write_journal(&journal)?;
        Ok(journal)
    }

    /// Atomically select the prepared version. The old version directory remains intact.
    pub fn activate(&self) -> Result<()> {
        let mut j = self.read_journal()?.ok_or(UpgradeError::NoTransaction)?;
        if j.phase != Phase::Prepared { return Err(UpgradeError::WrongState); }
        self.ensure_version_exists(&j.new_version)?;
        self.write_active(Some(&j.new_version))?;
        j.phase = Phase::Activated;
        self.write_journal(&j)
    }

    /// Mark the new version healthy. Only the running new program should request this
    /// after its externally defined health gate; this API alone does not prove health.
    pub fn confirm(&self) -> Result<()> {
        let mut j = self.read_journal()?.ok_or(UpgradeError::NoTransaction)?;
        if j.phase != Phase::Activated || self.active_version()?.as_deref() != Some(&j.new_version) { return Err(UpgradeError::WrongState); }
        j.phase = Phase::Confirmed;
        self.write_journal(&j)
    }

    /// Recover before launching anything. Any unconfirmed journal rolls the active
    /// pointer back to the retained old version (or clears it for first install).
    /// Prepared candidates are left on disk for diagnosis/retry; they are never run.
    pub fn recover(&self) -> Result<Recovery> {
        let Some(mut j) = self.read_journal()? else { return Ok(Recovery::NoTransaction); };
        if j.phase == Phase::Confirmed { return Ok(Recovery::Confirmed { active: self.active_version()? }); }
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
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => Err(UpgradeError::Invalid("active pointer is not a regular file")),
            Ok(_) => { let mut s = String::new(); File::open(path)?.take(256).read_to_string(&mut s)?; let s=s.trim_end_matches('\n'); if s.is_empty() { Ok(None) } else { validate_version(s)?; self.ensure_version_exists(s)?; Ok(Some(s.to_owned())) } }
        }
    }
    pub fn journal(&self) -> Result<Option<Journal>> { self.read_journal() }

    fn ensure_version_exists(&self, v: &str) -> Result<()> {
        validate_version(v)?;
        let p = self.versions.join(v);
        let m = fs::symlink_metadata(&p)?;
        if !m.is_dir() || m.file_type().is_symlink() { return Err(UpgradeError::Invalid("version target is not a real directory")); }
        Ok(())
    }
    fn read_journal(&self) -> Result<Option<Journal>> {
        let p=self.root.join(JOURNAL_FILE);
        let meta=match fs::symlink_metadata(&p) { Ok(m)=>m, Err(e) if e.kind()==io::ErrorKind::NotFound=>return Ok(None), Err(e)=>return Err(e.into()) };
        if meta.file_type().is_symlink() || !meta.is_file() { return Err(UpgradeError::CorruptJournal); }
        let mut f=File::open(&p)?;
        let mut s=String::new(); f.take(1024).read_to_string(&mut s)?;
        let lines:Vec<_>=s.lines().collect();
        if lines.len()!=4 || lines[0]!=FORMAT { return Err(UpgradeError::CorruptJournal); }
        let old=if lines[1]=="-" {None} else {validate_version(lines[1]).map_err(|_|UpgradeError::CorruptJournal)?;Some(lines[1].to_owned())};
        validate_version(lines[2]).map_err(|_|UpgradeError::CorruptJournal)?;
        let phase=match lines[3] {"Prepared"=>Phase::Prepared,"Activated"=>Phase::Activated,"Confirmed"=>Phase::Confirmed,_=>return Err(UpgradeError::CorruptJournal)};
        Ok(Some(Journal{old_version:old,new_version:lines[2].to_owned(),phase}))
    }
    fn write_journal(&self,j:&Journal)->Result<()> {
        let old=j.old_version.as_deref().unwrap_or("-");
        let data=format!("{FORMAT}\n{old}\n{}\n{:?}\n",j.new_version,j.phase);
        atomic_write(&self.root, JOURNAL_FILE, data.as_bytes())
    }
    fn write_active(&self,v:Option<&str>)->Result<()> {
        if let Some(v)=v { self.ensure_version_exists(v)?; }
        atomic_write(&self.root, ACTIVE_FILE, v.unwrap_or("").as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recovery { NoTransaction, Confirmed { active: Option<String> }, RolledBack { active: Option<String> } }

fn validate_version(v:&str)->Result<()> {
    if v.is_empty() || v.len()>128 || v=="." || v==".." || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) || v.starts_with('.') { return Err(UpgradeError::Invalid("version must be a simple safe identifier")); }
    Ok(())
}
fn ensure_child_dir(root:&Path,path:&Path)->Result<()> {
    match fs::symlink_metadata(path) { Ok(m) if m.is_dir()&&!m.file_type().is_symlink()=>Ok(()), Ok(_)=>Err(UpgradeError::Invalid("store child must be a real directory")), Err(e) if e.kind()==io::ErrorKind::NotFound=>{fs::create_dir(path)?;sync_dir(root)},Err(e)=>Err(e.into()) }
}
fn reject_symlink_components(path:&Path)->Result<()> {
    let abs=if path.is_absolute(){path.to_path_buf()}else{std::env::current_dir()?.join(path)};
    let mut current=PathBuf::new();
    for c in abs.components(){ match c { Component::CurDir=>{}, Component::ParentDir=>return Err(UpgradeError::Invalid("path contains parent traversal")), Component::Normal(n)=>{current.push(n); if let Ok(m)=fs::symlink_metadata(&current){if m.file_type().is_symlink(){return Err(UpgradeError::Invalid("symlink path component"));}}}, _=>current.push(c.as_os_str()) } }
    Ok(())
}
fn copy_tree_no_symlinks(src:&Path,dst:&Path)->Result<()> {
    fs::create_dir(dst)?;
    for entry in fs::read_dir(src)? { let e=entry?; let ty=e.file_type()?; let to=dst.join(e.file_name()); if ty.is_symlink(){return Err(UpgradeError::Invalid("artifact contains symlink"));} if ty.is_dir(){copy_tree_no_symlinks(&e.path(),&to)?;} else if ty.is_file(){ let mut i=File::open(e.path())?; let mut o=OpenOptions::new().write(true).create_new(true).open(to)?; io::copy(&mut i,&mut o)?; o.sync_all()?; } else {return Err(UpgradeError::Invalid("artifact contains special file"));} }
    sync_dir(dst)
}
fn sync_tree(path:&Path)->Result<()> { for e in fs::read_dir(path)? { let e=e?; if e.file_type()?.is_dir(){sync_tree(&e.path())?;} else {File::open(e.path())?.sync_all()?;} } sync_dir(path) }
fn atomic_write(root:&Path,name:&str,data:&[u8])->Result<()> {
    let tmp=root.join(format!(".{name}.tmp"));
    // A crash can leave the uncommitted temporary file behind. Under the
    // documented single-writer/trusted-root model it is safe to discard and
    // recreate it; never remove a symlink or non-regular object.
    match fs::symlink_metadata(&tmp) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => { fs::remove_file(&tmp)?; sync_dir(root)?; },
        Ok(_) => return Err(UpgradeError::Invalid("temporary path is not a regular file")),
        Err(e) if e.kind()==io::ErrorKind::NotFound=>{},
        Err(e)=>return Err(e.into())
    }
    let mut f=OpenOptions::new().write(true).create_new(true).open(&tmp)?; f.write_all(data)?; f.sync_all()?; drop(f);
    fs::rename(&tmp,root.join(name))?; sync_dir(root)
}
#[cfg(target_os="linux")]
fn sync_dir(p:&Path)->Result<()> { File::open(p)?.sync_all()?; Ok(()) }
#[cfg(windows)]
fn sync_dir(_p:&Path)->Result<()> { Err(UpgradeError::UnsupportedPlatform("Windows directory fsync semantics are not implemented")) }
#[cfg(not(any(target_os="linux",windows)))]
fn sync_dir(_p:&Path)->Result<()> { Err(UpgradeError::UnsupportedPlatform("only Linux directory fsync is supported")) }
#[cfg(unix)]
fn same_device(a:&Path,b:&Path)->Result<bool> { use std::os::unix::fs::MetadataExt; Ok(fs::metadata(a)?.dev()==fs::metadata(b)?.dev()) }
#[cfg(not(unix))]
fn same_device(_a:&Path,_b:&Path)->Result<bool> { Err(UpgradeError::UnsupportedPlatform("same-filesystem identity check is not implemented")) }

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn directory_fsync_fails_closed_on_windows() {
        let err = sync_dir(Path::new(".")).unwrap_err();
        assert!(matches!(err, UpgradeError::UnsupportedPlatform(_)));
    }
}

#[cfg(all(test, target_os="linux"))]
mod tests {
    use super::*;
    use std::time::{SystemTime,UNIX_EPOCH};
    struct Temp(PathBuf);
    impl Temp { fn new()->Self {let p=std::env::temp_dir().join(format!("boreas-supervisor-test-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())); fs::create_dir(&p).unwrap(); Self(p)} fn path(&self)->&Path{&self.0} }
    impl Drop for Temp { fn drop(&mut self){let _=fs::remove_dir_all(&self.0);} }
    fn artifact(t:&Temp,name:&str){let p=t.path().join(name);fs::create_dir(&p).unwrap();fs::write(p.join("boreas"),b"test binary").unwrap();}
    fn setup()->(Temp,UpgradeStore,Temp){let t=Temp::new();let root=t.path().join("store");fs::create_dir(&root).unwrap();let store=UpgradeStore::open(root).unwrap_or_else(|_|panic!("platform must support directory fsync for success-path tests"));let a=Temp::new();artifact(&a,"candidate");(t,store,a)}
    #[cfg(target_os="linux")]
    #[test] fn first_install_prepare_activate_crash_rolls_back_to_empty(){let(_t,s,a)=setup();s.prepare(&Candidate{version:"1.0.0".into()},a.path().join("candidate")).unwrap();s.activate().unwrap();assert_eq!(s.active_version().unwrap().as_deref(),Some("1.0.0"));assert_eq!(s.recover().unwrap(),Recovery::RolledBack{active:None});assert_eq!(s.active_version().unwrap(),None);}
    #[cfg(target_os="linux")]
    #[test] fn confirmed_upgrade_preserves_old_version_and_active_new(){let(_t,s,a)=setup();let old=s.versions.join("1.0.0");fs::create_dir(&old).unwrap();s.write_active(Some("1.0.0")).unwrap();s.prepare(&Candidate{version:"2.0.0".into()},a.path().join("candidate")).unwrap();s.activate().unwrap();s.confirm().unwrap();assert!(old.is_dir());assert_eq!(s.active_version().unwrap().as_deref(),Some("2.0.0"));assert_eq!(s.recover().unwrap(),Recovery::Confirmed{active:Some("2.0.0".into())});}
    #[cfg(target_os="linux")]
    #[test] fn crash_after_pointer_rename_before_journal_activated_still_rolls_back(){let(_t,s,a)=setup();let old=s.versions.join("1.0.0");fs::create_dir(&old).unwrap();s.write_active(Some("1.0.0")).unwrap();s.prepare(&Candidate{version:"2.0.0".into()},a.path().join("candidate")).unwrap();s.write_active(Some("2.0.0")).unwrap();assert_eq!(s.recover().unwrap(),Recovery::RolledBack{active:Some("1.0.0".into())});}
    #[test] fn unsafe_version_and_symlink_artifact_rejected(){let(_t,s,a)=setup();assert!(s.prepare(&Candidate{version:"../oops".into()},a.path().join("candidate")).is_err());#[cfg(unix)] {use std::os::unix::fs::symlink;let link=a.path().join("link");symlink(a.path().join("candidate"),&link).unwrap();assert!(s.prepare(&Candidate{version:"1.0.0".into()},&link).is_err());}}
    #[test] fn journal_parser_rejects_traversal(){let(_t,s,_a)=setup();fs::write(s.root.join(JOURNAL_FILE),format!("{FORMAT}\n-\n../evil\nPrepared\n")).unwrap();assert!(matches!(s.journal(),Err(UpgradeError::CorruptJournal)));}
}
