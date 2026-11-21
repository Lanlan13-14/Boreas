//! Terminal identity-generation denials, authenticated independently of status.

use super::{Error, Reader, StatusStore, put_u32_blob};
use crate::authority_revocation::{
    AuthorityRevocationTrust, ED25519_SIGNATURE_LEN, MLDSA65_SIGNATURE_LEN,
    VerifiedAuthorityRevocation,
};
use boreas_proto::authority_revocation::{AuthorityRevocation, MAX_TBS_LEN};

/// Local mailbox carrier: magic, Ed25519 signature, ML-DSA-65 signature, exact TBS.
/// The carrier itself adds no signing authority or unsigned policy fields.
pub const IDENTITY_REVOCATION_MAGIC: &[u8; 8] = b"BRIR\0\0\0\x01";
pub const MAX_IDENTITY_REVOCATION_BYTES: usize =
    IDENTITY_REVOCATION_MAGIC.len() + ED25519_SIGNATURE_LEN + MLDSA65_SIGNATURE_LEN + MAX_TBS_LEN;
const MAX_DECISIONS: usize = 16;
pub(super) const MAX_EXTENSION_BYTES: usize = 32 + 1 + MAX_DECISIONS * (12 + MAX_IDENTITY_REVOCATION_BYTES);

type Key<'a> = (&'a [u8], u64, u16, u64);

#[derive(Clone, Eq, PartialEq)]
struct Evidence {
    raw: Vec<u8>,
    accepted_at: u64,
    object: AuthorityRevocation,
}

impl Evidence {
    fn new(raw: Vec<u8>, accepted_at: u64) -> Result<Self, Error> {
        let (tbs, _, _) = split(&raw)?;
        let object = AuthorityRevocation::decode_tbs(tbs).map_err(|_| Error::Corrupt)?;
        Ok(Self { raw, accepted_at, object })
    }

    fn key(&self) -> Key<'_> {
        (
            &self.object.issuer_key_id,
            self.object.issuer_generation,
            self.object.subject_node_id,
            self.object.identity_generation,
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Decisions {
    root: [u8; 32],
    evidence: Vec<Evidence>,
}

impl Decisions {
    pub(super) fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        bytes.extend_from_slice(&self.root);
        bytes.push(u8::try_from(self.evidence.len()).map_err(|_| Error::RevocationTooLarge)?);
        for evidence in &self.evidence {
            bytes.extend_from_slice(&evidence.accepted_at.to_be_bytes());
            put_u32_blob(bytes, &evidence.raw, MAX_IDENTITY_REVOCATION_BYTES)?;
        }
        Ok(())
    }

    pub(super) fn decode(reader: &mut Reader<'_>, utc_floor: u64) -> Result<Self, Error> {
        let root = reader.take(32)?.try_into().map_err(|_| Error::Corrupt)?;
        let count = usize::from(reader.u8()?);
        if count == 0 || count > MAX_DECISIONS {
            return Err(Error::Corrupt);
        }
        let mut evidence: Vec<Evidence> = Vec::with_capacity(count);
        for _ in 0..count {
            let accepted_at = reader.u64()?;
            if accepted_at == 0 || accepted_at > utc_floor {
                return Err(Error::Corrupt);
            }
            let raw = reader.blob_u32(MAX_IDENTITY_REVOCATION_BYTES)?.to_vec();
            let record = Evidence::new(raw, accepted_at)?;
            if evidence.last().is_some_and(|previous| previous.key() >= record.key()) {
                return Err(Error::Corrupt);
            }
            evidence.push(record);
        }
        Ok(Self { root, evidence })
    }

    pub(super) fn verify_loaded(
        &self,
        root: [u8; 32],
        trust: &AuthorityRevocationTrust,
    ) -> Result<(), Error> {
        if self.root != root {
            return Err(Error::RevocationPermission);
        }
        for record in &self.evidence {
            // Authenticate historical evidence at the persisted acceptance time.
            // This does not authorize any new submission after expiry.
            verify(trust, &record.raw, record.accepted_at)?;
        }
        Ok(())
    }
}

type SignedParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

fn split(raw: &[u8]) -> Result<SignedParts<'_>, Error> {
    let ed_end = IDENTITY_REVOCATION_MAGIC.len() + ED25519_SIGNATURE_LEN;
    let pq_end = ed_end + MLDSA65_SIGNATURE_LEN;
    if raw.len() <= pq_end
        || raw.len() > MAX_IDENTITY_REVOCATION_BYTES
        || !raw.starts_with(IDENTITY_REVOCATION_MAGIC)
    {
        return Err(Error::RevocationPermission);
    }
    Ok((&raw[pq_end..], &raw[IDENTITY_REVOCATION_MAGIC.len()..ed_end], &raw[ed_end..pq_end]))
}

fn verify(
    trust: &AuthorityRevocationTrust,
    raw: &[u8],
    now: u64,
) -> Result<VerifiedAuthorityRevocation, Error> {
    let (tbs, ed, pq) = split(raw)?;
    trust.verify(tbs, ed, pq, now).map_err(Error::AuthorityRevocation)
}

impl StatusStore {
    /// Verify a fresh, independent IdentityAuthority decision and commit it before
    /// exposing the denial. The caller uses the same trusted UTC source as status.
    /// A signed object is terminal for its exact identity generation once accepted;
    /// expiry limits admission, not the lifetime of a committed denial.
    pub fn accept_identity_revocation(&mut self, raw: &[u8], utc_us: u64) -> Result<(), Error> {
        if self.is_frozen() {
            return Err(Error::Frozen);
        }
        let now = self.observe_trusted_utc(utc_us)?;
        let (root, trust) = self.identity_trust.as_ref().ok_or(Error::RevocationPermission)?;
        if self.state.identity.as_ref().is_some_and(|decisions| {
            decisions.evidence.iter().any(|r| r.raw == raw)
        }) {
            // Already authenticated and committed (also re-verified on reopen).
            // No renewal or acceptance at the current time occurs here.
            return Ok(());
        }
        let verified = verify(trust, raw, now)?;
        let key = (
            verified.issuer_key_id(),
            verified.issuer_generation(),
            verified.subject_node_id(),
            verified.identity_generation(),
        );
        let decisions = self.state.identity.get_or_insert_with(|| Decisions {
            root: *root,
            evidence: Vec::new(),
        });
        let index = match decisions.evidence.binary_search_by(|r| r.key().cmp(&key)) {
            Ok(index) => {
                let old = &decisions.evidence[index];
                match verified.sequence().cmp(&old.object.seq) {
                    std::cmp::Ordering::Less => return Err(Error::RevocationStale),
                    std::cmp::Ordering::Equal => {
                        // Compare exact canonical TBS, not randomized signatures.
                        if split(raw)?.0 == split(&old.raw)?.0 {
                            return Ok(());
                        }
                        return Err(Error::IdentityRevocationConflict);
                    }
                    std::cmp::Ordering::Greater => (),
                }
                index
            }
            Err(index) => {
                if decisions.evidence.len() >= MAX_DECISIONS {
                    return Err(Error::RevocationTooLarge);
                }
                decisions.evidence.insert(index, Evidence::new(raw.to_vec(), now)?);
                return self.commit_or_poison();
            }
        };
        decisions.evidence[index] = Evidence::new(raw.to_vec(), now)?;
        self.commit_or_poison()
    }

    /// Query a previously committed IdentityAuthority denial for an authenticated
    /// endpoint. Unusable state is an error, never an empty decision set.
    pub fn identity_revoked(&self, peer: &super::AuthenticatedPeer) -> Result<bool, Error> {
        self.healthy()?;
        if self.identity_trust.is_none() {
            return Err(Error::RevocationPermission);
        }
        if peer.net_id() != self.net_id() {
            return Err(Error::WrongNetwork);
        }
        if self.is_frozen() {
            return Err(Error::Frozen);
        }
        if self.is_clock_latched() {
            return Err(Error::ClockRollback);
        }
        Ok(self.state.identity.as_ref().is_some_and(|decisions| {
            decisions.evidence.iter().any(|r| {
                r.object.subject_node_id == peer.node_id()
                    && r.object.identity_generation == peer.identity_generation()
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Authority, NodeRole,
        management::{IssuerRecord, IssuerScope, ManagementTrust},
        status_store::AuthenticatedPeer,
    };
    use boreas_proto::{
        authority_revocation::{RevocationClass, RevocationScope},
        objects::MldsaParameterSet,
    };
    use openssl::{pkey::{KeyType, PKey}, sign::Signer};
    use std::{fs, os::unix::fs::{MetadataExt, PermissionsExt}};

    #[test]
    fn commits_only_verified_in_scope_evidence_and_cannot_roll_back_or_bypass_failed_write() {
        let dir = std::env::temp_dir().join(format!("boreas-identity-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&dir).unwrap().uid();
        let path = dir.join("status.state");
        let net = [2; 16];
        let root = [1; 32];
        let ed = PKey::generate_ed25519().unwrap();
        let pq = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[9; 32]).unwrap();
        let build_trust = || {
            let mut trust = AuthorityRevocationTrust::new(net);
            trust.add_issuer(IssuerRecord {
                issuer_key_id: b"ia".to_vec(),
                issuer_generation: 3,
                authority: Authority::IdentityAuthority,
                ed25519_public_key_der: ed.public_key_to_der().unwrap(),
                mldsa_parameter_set: MldsaParameterSet::Mldsa65,
                mldsa_public_key_der: pq.public_key_to_der().unwrap(),
                scope: IssuerScope::for_identity(vec![NodeRole::Edge], vec![1]).unwrap(),
            }, 100, 500).unwrap();
            trust
        };
        let open = |root| StatusStore::open_with_identity_revocations(
            &path, net, uid, ManagementTrust::new(net), root, build_trust(),
        );
        let sign = |issuer: &[u8], node, seq, next_update| {
            let tbs = AuthorityRevocation {
                net_id: net,
                class: RevocationClass::Identity,
                subject_node_id: node,
                identity_generation: 9,
                issuer_key_id: issuer.to_vec(),
                issuer_generation: 3,
                scope: RevocationScope::default(),
                seq,
                issued_at: 150,
                next_update,
            }.encode_tbs().unwrap();
            let input = AuthorityRevocation::signature_input(&tbs).unwrap();
            let mut raw = IDENTITY_REVOCATION_MAGIC.to_vec();
            for key in [&ed, &pq] {
                let sig = Signer::new_without_digest(key).unwrap().sign_oneshot_to_vec(&input).unwrap();
                raw.extend_from_slice(&sig);
            }
            raw.extend_from_slice(&tbs);
            raw
        };
        let peer = AuthenticatedPeer::new(net, 2, 9).unwrap();
        let other = AuthenticatedPeer::new(net, 3, 9).unwrap();
        let raw = sign(b"ia", 2, 2, 700);
        let mut store = open(root).unwrap();
        assert!(matches!(
            store.accept_identity_revocation(&sign(b"status-signer-v1", 2, 3, 700), 200),
            Err(Error::AuthorityRevocation(crate::authority_revocation::Error::UnknownIssuer))
        ));
        assert!(matches!(
            store.accept_identity_revocation(&sign(b"ia", 258, 3, 700), 200),
            Err(Error::AuthorityRevocation(crate::authority_revocation::Error::OutOfScope))
        ));
        let mut corrupt = raw.clone();
        corrupt[IDENTITY_REVOCATION_MAGIC.len() + ED25519_SIGNATURE_LEN] ^= 1;
        assert!(matches!(store.accept_identity_revocation(&corrupt, 200), Err(Error::AuthorityRevocation(_))));
        assert!(!store.identity_revoked(&peer).unwrap());
        store.accept_identity_revocation(&raw, 200).unwrap();
        drop(store);
        assert!(matches!(open([9; 32]), Err(Error::RevocationPermission)));
        assert!(matches!(StatusStore::open(&path, net, uid, ManagementTrust::new(net)), Err(Error::RevocationPermission)));
        let mut store = open(root).unwrap();
        assert!(store.identity_revoked(&peer).unwrap());
        assert!(!store.identity_revoked(&other).unwrap());
        assert!(matches!(store.accept_identity_revocation(&sign(b"ia", 2, 1, 700), 201), Err(Error::RevocationStale)));
        assert!(matches!(store.accept_identity_revocation(&sign(b"ia", 2, 2, 701), 201), Err(Error::IdentityRevocationConflict)));
        assert!(matches!(
            store.accept_identity_revocation(&sign(b"ia", 3, 3, 700), 500),
            Err(Error::AuthorityRevocation(crate::authority_revocation::Error::IssuerNotValid))
        ));
        store.accept_identity_revocation(&raw, 500).unwrap();
        assert!(store.identity_revoked(&peer).unwrap());
        // Exercise failure on the decision commit, not on the preliminary UTC observation.
        let replacement = sign(b"ia", 3, 3, 700);
        drop(store);
        let failure_path = dir.join("failure.state");
        let open_failure = || StatusStore::open_with_identity_revocations(
            &failure_path, net, uid, ManagementTrust::new(net), root, build_trust(),
        );
        let mut store = open_failure().unwrap();
        store.observe_trusted_utc(200).unwrap();
        store.fail_next_commit = true;
        assert!(matches!(store.accept_identity_revocation(&replacement, 200), Err(Error::Io(_))));
        assert!(matches!(store.identity_revoked(&peer), Err(Error::Poisoned)));
        drop(store);
        let store = open_failure().unwrap();
        assert!(!store.identity_revoked(&other).unwrap());
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
}
