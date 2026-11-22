//! Terminal authority denials, authenticated independently of status.

use super::{Error, Reader, StatusStore, put_u32_blob};
use crate::authority_revocation::{
    AuthorityRevocationTrust, ED25519_SIGNATURE_LEN, MLDSA65_SIGNATURE_LEN,
    VerifiedAuthorityRevocation,
};
use boreas_proto::{
    authority_revocation::{
        AuthorityRevocation, MAX_IDENTITY_REVOCATIONS, MAX_SCOPED_REVOCATIONS,
        RevocationClass,
    },
    objects::ObjectBody,
};
use crate::management::VerifiedObject;
pub use boreas_proto::authority_revocation::{
    IDENTITY_REVOCATION_MAGIC, MAX_IDENTITY_REVOCATION_BYTES, MAX_SCOPED_REVOCATION_BYTES,
    SCOPED_REVOCATION_MAGIC,
};
pub(super) const MAX_EXTENSION_BYTES: usize = 32 + 1 + MAX_IDENTITY_REVOCATIONS * (12 + MAX_IDENTITY_REVOCATION_BYTES);

pub(super) const MAX_SCOPED_EXTENSION_BYTES: usize =
    32 + 1 + MAX_SCOPED_REVOCATIONS * (12 + MAX_SCOPED_REVOCATION_BYTES);

type Key<'a> = (RevocationClass, &'a [u8], u64, u16, u64, &'a [u8], u8, u8);

fn magic(identity: bool) -> &'static [u8; 8] {
    if identity { IDENTITY_REVOCATION_MAGIC } else { SCOPED_REVOCATION_MAGIC }
}

#[derive(Clone, Eq, PartialEq)]
struct Evidence {
    raw: Vec<u8>,
    accepted_at: u64,
    object: AuthorityRevocation,
}

impl Evidence {
    fn new(raw: Vec<u8>, accepted_at: u64, identity: bool) -> Result<Self, Error> {
        let (tbs, _, _) = split(&raw, magic(identity))?;
        let object = AuthorityRevocation::decode_tbs(tbs).map_err(|_| Error::Corrupt)?;
        if (object.class == RevocationClass::Identity) != identity {
            return Err(Error::RevocationPermission);
        }
        Ok(Self { raw, accepted_at, object })
    }

    fn key(&self) -> Key<'_> {
        (
            self.object.class,
            &self.object.issuer_key_id,
            self.object.issuer_generation,
            self.object.subject_node_id,
            self.object.identity_generation,
            &self.object.scope.prefix,
            self.object.scope.prefix_len,
            self.object.scope.core_id,
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

    pub(super) fn decode(reader: &mut Reader<'_>, utc_floor: u64, identity: bool) -> Result<Self, Error> {
        let root = reader.take(32)?.try_into().map_err(|_| Error::Corrupt)?;
        let count = usize::from(reader.u8()?);
        if count == 0 || count > if identity { MAX_IDENTITY_REVOCATIONS } else { MAX_SCOPED_REVOCATIONS } {
            return Err(Error::Corrupt);
        }
        let mut evidence: Vec<Evidence> = Vec::with_capacity(count);
        for _ in 0..count {
            let accepted_at = reader.u64()?;
            if accepted_at == 0 || accepted_at > utc_floor {
                return Err(Error::Corrupt);
            }
            let raw = reader.blob_u32(MAX_IDENTITY_REVOCATION_BYTES)?.to_vec();
            let record = Evidence::new(raw, accepted_at, identity)?;
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
        identity: bool,
    ) -> Result<(), Error> {
        if self.root != root {
            return Err(Error::RevocationPermission);
        }
        for record in &self.evidence {
            // Authenticate historical evidence at the persisted acceptance time.
            // This does not authorize any new submission after expiry.
            verify(trust, &record.raw, record.accepted_at, identity)?;
        }
        Ok(())
    }
}

type SignedParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

fn split<'a>(raw: &'a [u8], header: &[u8; 8]) -> Result<SignedParts<'a>, Error> {
    let ed_end = header.len() + ED25519_SIGNATURE_LEN;
    let pq_end = ed_end + MLDSA65_SIGNATURE_LEN;
    if raw.len() <= pq_end
        || raw.len() > MAX_IDENTITY_REVOCATION_BYTES
        || !raw.starts_with(header)
    {
        return Err(Error::RevocationPermission);
    }
    Ok((&raw[pq_end..], &raw[header.len()..ed_end], &raw[ed_end..pq_end]))
}

fn verify(
    trust: &AuthorityRevocationTrust,
    raw: &[u8],
    now: u64,
    identity: bool,
) -> Result<VerifiedAuthorityRevocation, Error> {
    let (tbs, ed, pq) = split(raw, magic(identity))?;
    let verified = trust.verify(tbs, ed, pq, now).map_err(Error::AuthorityRevocation)?;
    if (verified.class() == RevocationClass::Identity) != identity {
        return Err(Error::RevocationPermission);
    }
    Ok(verified)
}

impl StatusStore {
    /// Bind an existing store to the exact local root and issuer grants, not
    /// just to a network id or the presence of an identity verifier.
    pub fn has_same_identity_authorities(
        &self,
        root: [u8; 32],
        expected: &AuthorityRevocationTrust,
    ) -> bool {
        self.identity_trust.as_ref().is_some_and(|(pinned, trust)| {
            *pinned == root && trust.same_issuers(expected)
        })
    }

    /// Export original signed carriers only from committed evidence and only
    /// while still admissible on a new recipient. Never send acceptance UTC.
    pub fn relayable_identity_revocations(&mut self, utc_us: u64) -> Result<Vec<&[u8]>, Error> {
        if self.is_frozen() {
            return Err(Error::Frozen);
        }
        let now = self.observe_trusted_utc(utc_us)?;
        let (_, trust) = self.identity_trust.as_ref().ok_or(Error::RevocationPermission)?;
        Ok(self.state.identity.iter()
            .flat_map(|decisions| &decisions.evidence)
            .filter(|record| trust.can_relay(&record.object, now))
            .map(|record| record.raw.as_slice())
            .collect())
    }

    /// Verify a fresh, independent IdentityAuthority decision and commit it before
    /// exposing the denial. The caller uses the same trusted UTC source as status.
    /// A signed object is terminal for its exact identity generation once accepted;
    /// expiry limits admission, not the lifetime of a committed denial.
    pub fn accept_identity_revocation(&mut self, raw: &[u8], utc_us: u64) -> Result<(), Error> {
        self.accept_authority_revocation(raw, utc_us, RevocationClass::Identity)
    }

    /// Commit a scoped decision only for the class assigned to the input.
    /// The class is also signed; a mailbox filename supplies no trust.
    pub fn accept_scoped_revocation(
        &mut self,
        class: RevocationClass,
        raw: &[u8],
        utc_us: u64,
    ) -> Result<(), Error> {
        if class == RevocationClass::Identity {
            return Err(Error::RevocationPermission);
        }
        self.accept_authority_revocation(raw, utc_us, class)
    }

    fn accept_authority_revocation(
        &mut self,
        raw: &[u8],
        utc_us: u64,
        class: RevocationClass,
    ) -> Result<(), Error> {
        if self.is_frozen() {
            return Err(Error::Frozen);
        }
        let identity = class == RevocationClass::Identity;
        let now = self.observe_trusted_utc(utc_us)?;
        let (root, trust) = self.identity_trust.as_ref().ok_or(Error::RevocationPermission)?;
        let slot = if identity { &mut self.state.identity } else { &mut self.state.scoped };
        if slot.as_ref().is_some_and(|decisions| {
            decisions.evidence.iter().any(|r| r.object.class == class && r.raw == raw)
        }) {
            // Already authenticated and committed, including after reopen.
            return Ok(());
        }
        let verified = verify(trust, raw, now, identity)?;
        if verified.class() != class {
            return Err(Error::RevocationPermission);
        }
        let key = (
            class,
            verified.issuer_key_id(),
            verified.issuer_generation(),
            verified.subject_node_id(),
            verified.identity_generation(),
            verified.scope().prefix.as_slice(),
            verified.scope().prefix_len,
            verified.scope().core_id,
        );
        let decisions = slot.get_or_insert_with(|| Decisions {
            root: *root,
            evidence: Vec::new(),
        });
        let limit = if identity { MAX_IDENTITY_REVOCATIONS } else { MAX_SCOPED_REVOCATIONS };
        match decisions.evidence.binary_search_by(|r| r.key().cmp(&key)) {
            Ok(index) => {
                let old = &decisions.evidence[index];
                match verified.sequence().cmp(&old.object.seq) {
                    std::cmp::Ordering::Less => return Err(Error::RevocationStale),
                    std::cmp::Ordering::Equal => {
                        // Compare exact canonical TBS, not randomized signatures.
                        if split(raw, magic(identity))?.0 == split(&old.raw, magic(identity))?.0 {
                            return Ok(());
                        }
                        return Err(if identity { Error::IdentityRevocationConflict }
                                   else { Error::ScopedRevocationConflict });
                    }
                    std::cmp::Ordering::Greater => (),
                }
                decisions.evidence[index] = Evidence::new(raw.to_vec(), now, identity)?;
            }
            Err(index) => {
                if decisions.evidence.len() >= limit {
                    return Err(Error::RevocationTooLarge);
                }
                decisions.evidence.insert(index, Evidence::new(raw.to_vec(), now, identity)?);
            }
        }
        self.commit_or_poison()
    }

    /// Query a previously committed IdentityAuthority denial for an authenticated
    /// endpoint. Unusable state is an error, never an empty decision set.
    pub fn identity_revoked(&self, peer: &super::AuthenticatedPeer) -> Result<bool, Error> {
        self.endpoint_decision_matches(peer, RevocationClass::Identity)
    }

    /// Independently root-issued denial for this authenticated Core generation.
    pub fn core_revoked(&self, peer: &super::AuthenticatedPeer) -> Result<bool, Error> {
        self.endpoint_decision_matches(peer, RevocationClass::Core)
    }

    /// Invalidate only a verified grant's own issuer/subject/prefix binding.
    /// The grant format does not carry an identity generation: callers must
    /// supply the authenticated beneficiary bound to this grant at admission,
    /// not a successor or a generation copied from the revocation object.
    /// A negative answer does not verify grant freshness or authorize use.
    pub fn route_grant_revoked(
        &self,
        subject: &super::AuthenticatedPeer,
        grant: &VerifiedObject,
    ) -> Result<bool, Error> {
        let object = grant.object();
        let ObjectBody::RouteGrant(route) = &object.body else {
            return Err(Error::RevocationPermission);
        };
        self.check_grant_subject(subject, object, route.subject_node_id)?;
        Ok(self.identity_revoked(subject)? || self.core_revoked(subject)?
            || self.decision_matches(subject, RevocationClass::Route, |r| {
                r.issuer_key_id == object.issuer_key_id
                    && r.issuer_generation == object.issuer_generation
                    && r.scope.prefix == route.prefix && r.scope.prefix_len == route.prefix_len
            })?)
    }

    /// A Direct denial matches the verified grant's Core, issuer key ID and
    /// issuer generation, and the authenticated beneficiary's generation.
    /// It does not affect CDN sessions or another operational key's grants.
    /// As with [`Self::route_grant_revoked`], use the original admission binding
    /// and check grant freshness separately.
    pub fn direct_grant_revoked(
        &self,
        subject: &super::AuthenticatedPeer,
        grant: &VerifiedObject,
    ) -> Result<bool, Error> {
        let object = grant.object();
        let ObjectBody::DirectGrant(direct) = &object.body else {
            return Err(Error::RevocationPermission);
        };
        self.check_grant_subject(subject, object, direct.subject_node_id)?;
        let crate::Authority::CoreOperationalKey { core_id } = grant.issuer_authority() else {
            return Err(Error::RevocationPermission);
        };
        Ok(self.identity_revoked(subject)? || self.core_revoked(subject)?
            || self.decision_matches(subject, RevocationClass::Direct, |r| {
                r.scope.core_id == core_id
                    && r.issuer_key_id == object.issuer_key_id
                    && r.issuer_generation == object.issuer_generation
            })?)
    }

    /// An attachment lease depends on both its owner and its authenticated
    /// target Core generation. Route and Direct denials never revoke a lease.
    /// Use the target generation captured when the owner admitted the lease;
    /// attaching an old lease to a successor identity is not recovery.
    pub fn attachment_lease_revoked(
        &self,
        target: &super::AuthenticatedPeer,
        lease: &VerifiedObject,
    ) -> Result<bool, Error> {
        let object = lease.object();
        let ObjectBody::AttachmentLease(lease) = &object.body else {
            return Err(Error::RevocationPermission);
        };
        let subject = super::AuthenticatedPeer::new(
            object.net_id, lease.node_id, lease.identity_generation,
        ).ok_or(Error::RevocationPermission)?;
        let target_node = (u16::from(lease.target_core_id) - 1) * 256 + 1;
        self.check_grant_subject(target, object, target_node)?;
        Ok(self.identity_revoked(&subject)? || self.core_revoked(&subject)?
            || self.identity_revoked(target)? || self.core_revoked(target)?)
    }

    fn check_grant_subject(
        &self,
        peer: &super::AuthenticatedPeer,
        object: &boreas_proto::objects::ManagementObject,
        node_id: u16,
    ) -> Result<(), Error> {
        if object.net_id != self.net_id() || peer.net_id() != self.net_id() {
            return Err(Error::WrongNetwork);
        }
        if peer.node_id() != node_id {
            return Err(Error::RevocationPermission);
        }
        Ok(())
    }

    fn endpoint_decision_matches(
        &self,
        peer: &super::AuthenticatedPeer,
        class: RevocationClass,
    ) -> Result<bool, Error> {
        if self.decision_matches(peer, class, |_| true)? {
            return Ok(true);
        }
        // A migration is not a new key or independent authorization. Explicit
        // denials of a source continue to deny its exact approved successor.
        if let Some(source) = self.pool_cutover_sources.iter().flatten().find(|source| {
            source.node_id() == peer.node_id()
                && source.identity_generation().checked_add(1) == Some(peer.identity_generation())
        }) {
            return self.decision_matches(source, class, |_| true);
        }
        Ok(false)
    }

    fn decision_matches(
        &self,
        peer: &super::AuthenticatedPeer,
        class: RevocationClass,
        scope: impl Fn(&AuthorityRevocation) -> bool,
    ) -> Result<bool, Error> {
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
        let decisions = if class == RevocationClass::Identity {
            &self.state.identity
        } else {
            &self.state.scoped
        };
        Ok(decisions.as_ref().is_some_and(|decisions| {
            decisions.evidence.iter().any(|r| {
                r.object.class == class && r.object.subject_node_id == peer.node_id()
                    && r.object.identity_generation == peer.identity_generation() && scope(&r.object)
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
        authority_revocation::RevocationScope,
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
        assert_eq!(store.relayable_identity_revocations(250).unwrap(), vec![raw.as_slice()]);
        assert!(matches!(
            store.accept_identity_revocation(&sign(b"ia", 3, 3, 700), 500),
            Err(Error::AuthorityRevocation(crate::authority_revocation::Error::IssuerNotValid))
        ));
        store.accept_identity_revocation(&raw, 500).unwrap();
        assert!(store.relayable_identity_revocations(500).unwrap().is_empty());
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
