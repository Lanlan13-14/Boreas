//! Durable NetworkRoot authorization store (candidate L1).
//!
//! Linux-only durability; other platforms deliberately fail closed. Each open cryptographically
//! re-verifies persisted authorization history against an external root pin; `issuer` checks
//! current validity using caller-supplied trusted UTC on every use.
#![cfg(feature = "openssl-backend")]

use std::{collections::BTreeMap, fmt, fs::{self, File, OpenOptions}, io::{self, Read, Write}, path::{Path, PathBuf}};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use openssl::hash::{hash, MessageDigest};
use crate::root_authorization::{self, NetworkRootPin, VerifiedIssuerAuthorization, MAX_CANDIDATE_BYTES};

const MAGIC: &[u8; 8] = b"BRTS\0\0\0\x01";
pub const MAX_STORE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_AUTHORIZATIONS: usize = 256;

#[derive(Debug)]
pub enum Error { Io(io::Error), Unsupported, UnsafePath, Busy, TooLarge, Corrupt, WrongNetwork, BadAuthorization, StaleGeneration, Equivocation, Full, Poisoned }
impl fmt::Display for Error { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") } }
impl std::error::Error for Error {}
impl From<io::Error> for Error { fn from(e: io::Error) -> Self { Self::Io(e) } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportResult { Added, DuplicateNotRenewed }
#[derive(Clone)]
struct Entry { raw: Vec<u8>, ed: Vec<u8>, pq: Vec<u8> }
#[derive(Clone)]
struct Conflict { generation: u64, first: Entry, second: Entry }

/// Exclusive, network-bound durable store. Directory/files must be owned by `trusted_owner_uid`.
pub struct DurableTrustStore {
    path: PathBuf, _lock: File, net_id: [u8; 16], net_fingerprint: [u8; 32],
    root_fingerprint: [u8; 32], trusted_owner_uid: u32,
    entries: BTreeMap<Vec<u8>, Entry>, conflicts: BTreeMap<Vec<u8>, Conflict>, poisoned: bool,
    #[cfg(test)] fail_next_commit: bool,
}
impl fmt::Debug for DurableTrustStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("DurableTrustStore").field("net_id", &self.net_id).field("entry_count", &self.entries.len()).field("conflict_count", &self.conflicts.len()).finish() }
}
impl DurableTrustStore {
    /// `trusted_owner_uid` is an independent trusted input, never decoded from this file. Current
    /// authorization validity is checked with explicit trusted UTC by `issuer`.
    pub fn open(path: impl AsRef<Path>, net_id: [u8; 16], pin: &NetworkRootPin, trusted_owner_uid: u32) -> Result<Self, Error> {
        #[cfg(not(target_os = "linux"))] { let _ = (path, net_id, pin, trusted_owner_uid); return Err(Error::Unsupported); }
        #[cfg(target_os = "linux")] {
            if pin.net_id() != net_id { return Err(Error::WrongNetwork); }
            let path = checked_path(path.as_ref(), trusted_owner_uid)?;
            let lock_path = suffix(&path, ".lock");
            let staging_path = suffix(&path, ".staging");
            let lock = open_private(&lock_path, true, false)?;
            validate_file(&lock_path, &lock, trusted_owner_uid)?;
            match lock.try_lock() { Ok(()) => (), Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Busy), Err(std::fs::TryLockError::Error(e)) => return Err(Error::Io(e)) }
            if fs::symlink_metadata(&staging_path).is_ok() { return Err(Error::UnsafePath); }
            File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
            let mut store = Self { path, _lock: lock, net_id, net_fingerprint: net_fingerprint(net_id)?, root_fingerprint: pin.fingerprint().map_err(|_| Error::BadAuthorization)?, trusted_owner_uid, entries: BTreeMap::new(), conflicts: BTreeMap::new(), poisoned: false, #[cfg(test)] fail_next_commit: false };
            store.load(pin)?;
            Ok(store)
        }
    }
    pub fn net_id(&self) -> [u8; 16] { self.net_id }
    pub fn network_fingerprint(&self) -> [u8; 32] { self.net_fingerprint }
    /// Current external NetworkRoot pin fingerprint; it is a report identifier, not provenance proof.
    pub fn root_pin_fingerprint(&self) -> [u8; 32] { self.root_fingerprint }
    pub fn issuer_count(&self) -> usize { self.entries.len() }
    pub fn is_quarantined(&self, issuer_key_id: &[u8]) -> bool { self.conflicts.contains_key(issuer_key_id) }
    pub fn equivocation_evidence(&self, issuer_key_id: &[u8]) -> Option<(&[u8], &[u8])> { self.conflicts.get(issuer_key_id).map(|c| (c.first.raw.as_slice(), c.second.raw.as_slice())) }

    /// Verify exact candidate bytes and both signatures now, then persist before returning.
    pub fn import(&mut self, raw: &[u8], ed: &[u8], pq: &[u8], pin: &NetworkRootPin, trusted_now_us: u64) -> Result<ImportResult, Error> {
        self.healthy()?;
        if pin.net_id() != self.net_id || pin.fingerprint().map_err(|_| Error::BadAuthorization)? != self.root_fingerprint { return Err(Error::WrongNetwork); }
        let verified = root_authorization::verify_raw(raw, ed, pq, pin, self.net_id, trusted_now_us).map_err(|_| Error::BadAuthorization)?;
        let (key, generation) = identity(&verified)?;
        if self.conflicts.contains_key(&key) { return Err(Error::Equivocation); }
        if let Some(old) = self.entries.get(&key) {
            let old_v = verify_persisted(old, pin, self.net_id)?;
            let old_gen = identity(&old_v)?.1;
            if generation < old_gen { return Err(Error::StaleGeneration); }
            if generation == old_gen {
                if old.raw == raw { return Ok(ImportResult::DuplicateNotRenewed); }
                self.conflicts.insert(key.clone(), Conflict { generation, first: old.clone(), second: Entry { raw: raw.to_vec(), ed: ed.to_vec(), pq: pq.to_vec() } });
                self.entries.remove(&key);
                if let Err(e) = self.commit() { self.poisoned = true; return Err(e); }
                return Err(Error::Equivocation);
            }
        } else if self.entries.len() + self.conflicts.len() >= MAX_AUTHORIZATIONS { return Err(Error::Full); }
        self.entries.insert(key, Entry { raw: raw.to_vec(), ed: ed.to_vec(), pq: pq.to_vec() });
        if let Err(e) = self.commit() { self.poisoned = true; return Err(e); }
        Ok(ImportResult::Added)
    }
    /// Return only a currently valid authorization; signed validity is checked every call.
    pub fn issuer(&self, issuer_key_id: &[u8], pin: &NetworkRootPin, trusted_now_us: u64) -> Result<Option<VerifiedIssuerAuthorization>, Error> {
        self.healthy()?;
        if pin.net_id() != self.net_id || pin.fingerprint().map_err(|_| Error::BadAuthorization)? != self.root_fingerprint { return Err(Error::WrongNetwork); }
        if self.conflicts.contains_key(issuer_key_id) { return Err(Error::Equivocation); }
        self.entries.get(issuer_key_id).map(|e| verify_entry(e,pin,self.net_id,trusted_now_us)).transpose()
    }
    fn healthy(&self) -> Result<(), Error> { if self.poisoned { Err(Error::Poisoned) } else { Ok(()) } }
    #[cfg(target_os = "linux")] fn load(&mut self, pin: &NetworkRootPin) -> Result<(), Error> {
        let file = match open_existing_private(&self.path) { Ok(f) => f, Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()), Err(e) => return Err(e.into()) };
        validate_file(&self.path,&file,self.trusted_owner_uid)?;
        let len=usize::try_from(file.metadata()?.len()).map_err(|_|Error::TooLarge)?; if len>MAX_STORE_BYTES{return Err(Error::TooLarge)}
        let mut b=Vec::with_capacity(len);file.take((MAX_STORE_BYTES as u64)+1).read_to_end(&mut b)?;if b.len()>MAX_STORE_BYTES{return Err(Error::TooLarge)}
        let (net,root,entries,conflicts)=decode(&b)?;
        if net!=self.net_id{return Err(Error::WrongNetwork)} if root!=self.root_fingerprint{return Err(Error::WrongNetwork)}
        for(k,e)in &entries{let v=verify_persisted(e,pin,self.net_id).map_err(|_|Error::Corrupt)?;if identity(&v)?.0!=*k{return Err(Error::Corrupt)}}
        for(k,c)in &conflicts{if c.first.raw==c.second.raw{return Err(Error::Corrupt)}for e in [&c.first,&c.second]{let v=verify_persisted(e,pin,self.net_id).map_err(|_|Error::Corrupt)?;let(ek,g)=identity(&v)?;if ek!=*k||g!=c.generation{return Err(Error::Corrupt)}}}
        self.entries=entries;self.conflicts=conflicts;Ok(())
    }
    #[cfg(target_os = "linux")] fn commit(&self)->Result<(),Error>{
        #[cfg(test)] if self.fail_next_commit{return Err(Error::Io(io::Error::other("injected commit failure")))}
        let bytes=encode(self.net_id,self.root_fingerprint,&self.entries,&self.conflicts)?;if bytes.len()>MAX_STORE_BYTES{return Err(Error::TooLarge)}
        let tmp=suffix(&self.path,".staging");if fs::symlink_metadata(&tmp).is_ok(){return Err(Error::UnsafePath)}let mut f=open_staging(&tmp)?;validate_file(&tmp,&f,self.trusted_owner_uid)?;
        if let Err(e)=(||->io::Result<()>{f.write_all(&bytes)?;f.sync_all()?;drop(f);fs::rename(&tmp,&self.path)?;File::open(self.path.parent().ok_or_else(||io::Error::other("parent"))?)?.sync_all()})(){let _=fs::remove_file(&tmp);return Err(Error::Io(e))}Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    fn commit(&self)->Result<(),Error>{Err(Error::Unsupported)}
}
#[cfg(target_os = "linux")] fn verify_entry(e:&Entry,p:&NetworkRootPin,n:[u8;16],now:u64)->Result<VerifiedIssuerAuthorization,Error>{root_authorization::verify_raw(&e.raw,&e.ed,&e.pq,p,n,now).map_err(|_|Error::BadAuthorization)}
#[cfg(target_os = "linux")] fn verify_persisted(e:&Entry,p:&NetworkRootPin,n:[u8;16])->Result<VerifiedIssuerAuthorization,Error>{let c=root_authorization::RootAuthorizationCandidate::decode_candidate(&e.raw).map_err(|_|Error::BadAuthorization)?;root_authorization::verify_raw(&e.raw,&e.ed,&e.pq,p,n,c.not_before).map_err(|_|Error::BadAuthorization)}
#[cfg(target_os = "linux")] fn identity(v:&VerifiedIssuerAuthorization)->Result<(Vec<u8>,u64),Error>{let r=v.issuer_record();Ok((r.issuer_key_id,r.issuer_generation))}
#[cfg(target_os = "linux")] fn net_fingerprint(net:[u8;16])->Result<[u8;32],Error>{let mut b=b"BOREAS-NETWORK-ID-FINGERPRINT\0".to_vec();b.extend_from_slice(&net);let d=hash(MessageDigest::sha256(),&b).map_err(|_|Error::Corrupt)?;d.as_ref().try_into().map_err(|_|Error::Corrupt)}
#[cfg(target_os = "linux")] fn suffix(p:&Path,s:&str)->PathBuf{let mut x=p.as_os_str().to_os_string();x.push(s);PathBuf::from(x)}
#[cfg(target_os = "linux")] fn checked_path(p:&Path,owner:u32)->Result<PathBuf,Error>{if !p.is_absolute()||p.file_name().is_none(){return Err(Error::UnsafePath)}let mut cursor=PathBuf::new();for component in p.parent().ok_or(Error::UnsafePath)?.components(){cursor.push(component.as_os_str());let meta=fs::symlink_metadata(&cursor)?;if meta.file_type().is_symlink()||!meta.is_dir(){return Err(Error::UnsafePath)}let mode=meta.permissions().mode();let trusted_ancestor=meta.uid()==0&&mode&0o1000!=0;if mode&0o022!=0&&!trusted_ancestor{return Err(Error::UnsafePath)}}let cp=fs::canonicalize(p.parent().ok_or(Error::UnsafePath)?)?;let m=fs::symlink_metadata(&cp)?;if !m.is_dir()||m.file_type().is_symlink()||m.permissions().mode()&0o077!=0||m.uid()!=owner{return Err(Error::UnsafePath)}let out=cp.join(p.file_name().ok_or(Error::UnsafePath)?);match fs::symlink_metadata(&out){Ok(m)if m.file_type().is_symlink()||!m.is_file()||m.nlink()!=1=>return Err(Error::UnsafePath),Err(e)if e.kind()!=io::ErrorKind::NotFound=>return Err(e.into()),_=>()}Ok(out)}
#[cfg(target_os = "linux")] fn open_private(p:&Path,create:bool,_exclusive:bool)->Result<File,Error>{let mut o=OpenOptions::new();o.read(true).write(true).create(create).mode(0o600).custom_flags(0x20000|0x800);let f=o.open(p)?;if !f.metadata()?.is_file(){return Err(Error::UnsafePath)}Ok(f)}
#[cfg(target_os = "linux")] fn open_staging(p:&Path)->Result<File,Error>{let mut o=OpenOptions::new();o.read(true).write(true).create_new(true).mode(0o600).custom_flags(0x20000|0x800);let f=o.open(p)?;if !f.metadata()?.is_file(){return Err(Error::UnsafePath)}Ok(f)}
#[cfg(target_os = "linux")] fn open_existing_private(p:&Path)->io::Result<File>{let mut o=OpenOptions::new();o.read(true).write(true).custom_flags(0x20000|0x800);let f=o.open(p)?;if !f.metadata()?.is_file(){return Err(io::Error::other("not a regular file"))}Ok(f)}
#[cfg(target_os = "linux")] fn validate_file(p:&Path,f:&File,owner:u32)->Result<(),Error>{let a=fs::symlink_metadata(p)?;let b=f.metadata()?;let pm=fs::metadata(p.parent().ok_or(Error::UnsafePath)?)?;if a.file_type().is_symlink()||!a.is_file()||a.nlink()!=1||b.nlink()!=1||a.dev()!=b.dev()||a.ino()!=b.ino()||b.mode()&0o777!=0o600||b.uid()!=owner||b.uid()!=pm.uid(){return Err(Error::UnsafePath)}Ok(())}
#[cfg(target_os = "linux")] fn decode(b:&[u8])->Result<([u8;16],[u8;32],BTreeMap<Vec<u8>,Entry>,BTreeMap<Vec<u8>,Conflict>),Error>{if b.len()<56||&b[..8]!=MAGIC{return Err(Error::Corrupt)}let net=b[8..24].try_into().map_err(|_|Error::Corrupt)?;let root=b[24..56].try_into().map_err(|_|Error::Corrupt)?;let mut r=Reader{b,p:56};let n=r.u16()?as usize;if n>MAX_AUTHORIZATIONS{return Err(Error::TooLarge)}let mut es=BTreeMap::new();for _ in 0..n{let k=r.blob(64)?.to_vec();if k.is_empty()||es.insert(k,r.entry()?).is_some(){return Err(Error::Corrupt)}}let cn=r.u16()?as usize;if n+cn>MAX_AUTHORIZATIONS{return Err(Error::TooLarge)}let mut cs=BTreeMap::new();for _ in 0..cn{let k=r.blob(64)?.to_vec();let g=r.u64()?;let a=r.entry()?;let z=r.entry()?;if k.is_empty()||es.contains_key(&k)||cs.insert(k,Conflict{generation:g,first:a,second:z}).is_some(){return Err(Error::Corrupt)}}if r.p!=b.len(){return Err(Error::Corrupt)}Ok((net,root,es,cs))}
#[cfg(target_os = "linux")] fn encode(net:[u8;16],root:[u8;32],es:&BTreeMap<Vec<u8>,Entry>,cs:&BTreeMap<Vec<u8>,Conflict>)->Result<Vec<u8>,Error>{if es.len()+cs.len()>MAX_AUTHORIZATIONS{return Err(Error::Full)}let mut b=MAGIC.to_vec();b.extend_from_slice(&net);b.extend_from_slice(&root);put16(&mut b,es.len())?;for(k,e)in es{putblob(&mut b,k)?;putentry(&mut b,e)?}put16(&mut b,cs.len())?;for(k,c)in cs{putblob(&mut b,k)?;b.extend_from_slice(&c.generation.to_be_bytes());putentry(&mut b,&c.first)?;putentry(&mut b,&c.second)?}Ok(b)}
#[cfg(target_os = "linux")] fn put16(b:&mut Vec<u8>,n:usize)->Result<(),Error>{b.extend_from_slice(&u16::try_from(n).map_err(|_|Error::TooLarge)?.to_be_bytes());Ok(())}
#[cfg(target_os = "linux")] fn putblob(b:&mut Vec<u8>,x:&[u8])->Result<(),Error>{put16(b,x.len())?;b.extend_from_slice(x);Ok(())}
#[cfg(target_os = "linux")] fn putentry(b:&mut Vec<u8>,e:&Entry)->Result<(),Error>{if e.raw.len()>MAX_CANDIDATE_BYTES||e.ed.len()>64||e.pq.len()>4627{return Err(Error::TooLarge)}putblob(b,&e.raw)?;putblob(b,&e.ed)?;putblob(b,&e.pq)}
#[cfg(target_os = "linux")] struct Reader<'a>{b:&'a[u8],p:usize}
#[cfg(target_os = "linux")] impl<'a> Reader<'a>{fn take(&mut self,n:usize)->Result<&'a[u8],Error>{let e=self.p.checked_add(n).ok_or(Error::Corrupt)?;if e>self.b.len(){return Err(Error::Corrupt)}let x=&self.b[self.p..e];self.p=e;Ok(x)}fn u16(&mut self)->Result<u16,Error>{Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_|Error::Corrupt)?))}fn u64(&mut self)->Result<u64,Error>{Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_|Error::Corrupt)?))}fn blob(&mut self,max:usize)->Result<&'a[u8],Error>{let n=self.u16()?as usize;if n>max{return Err(Error::TooLarge)}self.take(n)}fn entry(&mut self)->Result<Entry,Error>{Ok(Entry{raw:self.blob(MAX_CANDIDATE_BYTES)?.to_vec(),ed:self.blob(64)?.to_vec(),pq:self.blob(4627)?.to_vec()})}}

#[cfg(all(test, target_os = "linux"))]
mod tests {
 use super::*; use openssl::{pkey::{KeyType,PKey,Private},sign::Signer}; use crate::{NodeRole,root_authorization::{Purpose,Scope,RootAuthorizationCandidate}}; use std::sync::atomic::{AtomicU64,Ordering};
 static ID:AtomicU64=AtomicU64::new(1); const NET:[u8;16]=[7;16];
 fn keypair(seed:u8)->(PKey<Private>,PKey<Private>){(PKey::generate_ed25519().unwrap(),PKey::private_key_from_seed(None,KeyType::ML_DSA_65,None,&[seed;32]).unwrap())}
 fn signature(k:&PKey<Private>,m:&[u8])->Vec<u8>{let mut s=Signer::new_without_digest(k).unwrap();s.sign_oneshot_to_vec(m).unwrap()}
 fn signed(gen:u64,issuer:u8,issuer_keys:&(PKey<Private>,PKey<Private>),roots:&(PKey<Private>,PKey<Private>))->(Vec<u8>,Vec<u8>,Vec<u8>){let c=RootAuthorizationCandidate{net_id:NET,issuer_key_id:vec![issuer],issuer_generation:gen,purpose:Purpose::Identity,ed25519_public_key_der:issuer_keys.0.public_key_to_der().unwrap(),mldsa_parameter_set:boreas_proto::objects::MldsaParameterSet::Mldsa65,mldsa_public_key_der:issuer_keys.1.public_key_to_der().unwrap(),scope:Scope::Identity{roles:vec![NodeRole::Edge],home_cores:vec![1]},not_before:10,expires:100,chain_depth:1,may_delegate:false};let raw=c.encode_candidate().unwrap();let mut msg=b"BOREAS-ROOT-AUTHORIZATION-CANDIDATE\0".to_vec();msg.extend_from_slice(&raw);(raw,signature(&roots.0,&msg),signature(&roots.1,&msg))}
 fn pin(r:&(PKey<Private>,PKey<Private>))->NetworkRootPin{NetworkRootPin::provisioned(NET,r.0.public_key_to_der().unwrap(),boreas_proto::objects::MldsaParameterSet::Mldsa65,r.1.public_key_to_der().unwrap()).unwrap()}
 fn dir()->(PathBuf,PathBuf){let id=ID.fetch_add(1,Ordering::Relaxed);let d=std::env::temp_dir().join(format!("boreas-trust-{}-{id}",std::process::id()));fs::create_dir(&d).unwrap();fs::set_permissions(&d,fs::Permissions::from_mode(0o700)).unwrap();(d.clone(),d.join("state"))}
 #[cfg(target_os = "linux")] use std::os::unix::fs::PermissionsExt;
 #[test] fn restart_duplicate_expiry_bad_signature_and_network(){let roots=keypair(1);let issuer=keypair(2);let p=pin(&roots);let(raw,ed,pq)=signed(1,3,&issuer,&roots);let(d,path)=dir();let uid=fs::metadata(&d).unwrap().uid();let mut s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();assert_eq!(s.import(&raw,&ed,&pq,&p,10).unwrap(),ImportResult::Added);assert!(s.issuer(&[3],&p,99).unwrap().is_some());assert!(matches!(s.issuer(&[3],&p,100),Err(Error::BadAuthorization)));assert_eq!(s.import(&raw,&ed,&pq,&p,11).unwrap(),ImportResult::DuplicateNotRenewed);drop(s);let s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();assert!(s.issuer(&[3],&p,99).unwrap().is_some());assert!(matches!(s.issuer(&[3],&p,100),Err(Error::BadAuthorization)));assert!(matches!(DurableTrustStore::open(&path,[8;16],&p,uid),Err(Error::WrongNetwork)));drop(s);let mut bad=ed.clone();bad[0]^=1;let mut s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();assert!(matches!(s.import(&raw,&bad,&pq,&p,11),Err(Error::BadAuthorization)));drop(s);fs::remove_dir_all(d).unwrap();}
 #[test] fn restart_rejects_tampered_signature(){let roots=keypair(11);let issuer=keypair(12);let p=pin(&roots);let(d,path)=dir();let uid=fs::metadata(&d).unwrap().uid();let(raw,ed,pq)=signed(1,4,&issuer,&roots);let mut s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();s.import(&raw,&ed,&pq,&p,10).unwrap();drop(s);let bytes=fs::read(&path).unwrap();let(net,root,mut entries,conflicts)=decode(&bytes).unwrap();entries.get_mut(&[4][..]).unwrap().ed[0]^=1;let bytes=encode(net,root,&entries,&conflicts).unwrap();fs::write(&path,&bytes).unwrap();fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();assert!(matches!(DurableTrustStore::open(&path,NET,&p,uid),Err(Error::Corrupt)));fs::remove_dir_all(d).unwrap();}
 #[test] fn stale_generation_equivocation_is_durable(){let roots=keypair(4);let issuer=keypair(5);let p=pin(&roots);let(d,path)=dir();let uid=fs::metadata(&d).unwrap().uid();let mut s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();let(a,ae,ap)=signed(2,9,&issuer,&roots);let(b,be,bp)=signed(1,9,&issuer,&roots);s.import(&a,&ae,&ap,&p,10).unwrap();assert!(matches!(s.import(&b,&be,&bp,&p,10),Err(Error::StaleGeneration)));let(c,ce,cp)=signed(2,9,&keypair(6),&roots);assert!(matches!(s.import(&c,&ce,&cp,&p,10),Err(Error::Equivocation)));assert_eq!(s.equivocation_evidence(&[9]).unwrap(),(a.as_slice(),c.as_slice()));drop(s);let s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();assert!(s.is_quarantined(&[9]));assert_eq!(s.equivocation_evidence(&[9]).unwrap(),(a.as_slice(),c.as_slice()));assert!(matches!(s.issuer(&[9],&p,10),Err(Error::Equivocation)));drop(s);fs::remove_dir_all(d).unwrap();}
 #[test] fn symlink_mode_size_and_commit_failure_fail_closed(){let roots=keypair(7);let issuer=keypair(8);let p=pin(&roots);let(d,path)=dir();let uid=fs::metadata(&d).unwrap().uid();let mut s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();assert!(matches!(DurableTrustStore::open(&path,NET,&p,uid),Err(Error::Busy)));s.fail_next_commit=true;let(raw,ed,pq)=signed(1,1,&issuer,&roots);assert!(matches!(s.import(&raw,&ed,&pq,&p,10),Err(Error::Io(_))));assert!(matches!(s.issuer(&[1],&p,10),Err(Error::Poisoned)));drop(s);assert!(!path.exists());fs::write(&path,vec![0;MAX_STORE_BYTES+1]).unwrap();fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();assert!(matches!(DurableTrustStore::open(&path,NET,&p,uid),Err(Error::TooLarge)));fs::remove_file(&path).unwrap();std::os::unix::fs::symlink("missing",&path).unwrap();assert!(matches!(DurableTrustStore::open(&path,NET,&p,uid),Err(Error::UnsafePath)));fs::remove_dir_all(d).unwrap();}
 #[test] fn rejects_wrong_owner_mode_and_relative_path(){let roots=keypair(10);let p=pin(&roots);let(d,path)=dir();let uid=fs::metadata(&d).unwrap().uid();let s=DurableTrustStore::open(&path,NET,&p,uid).unwrap();drop(s);let lock=suffix(&path,".lock");fs::set_permissions(&lock,fs::Permissions::from_mode(0o644)).unwrap();assert!(matches!(DurableTrustStore::open(&path,NET,&p,uid),Err(Error::UnsafePath)));fs::set_permissions(&lock,fs::Permissions::from_mode(0o600)).unwrap();assert!(matches!(DurableTrustStore::open("relative-state",NET,&p,uid),Err(Error::UnsafePath)));fs::remove_dir_all(d).unwrap();}
 #[test] fn codec_rejects_trailing_and_roundtrips_bounds(){let mut e=BTreeMap::new();let mut c=BTreeMap::new();let x=Entry{raw:vec![1],ed:vec![2],pq:vec![3]};e.insert(vec![4],x.clone());c.insert(vec![5],Conflict{generation:3,first:x.clone(),second:Entry{raw:vec![2],..x}});let b=encode(NET,[9;32],&e,&c).unwrap();let(n,r,ee,cc)=decode(&b).unwrap();assert_eq!(n,NET);assert_eq!(r,[9;32]);assert_eq!(ee.len(),1);assert_eq!(cc.len(),1);let mut extra=b;extra.push(0);assert!(matches!(decode(&extra),Err(Error::Corrupt)));}
}
