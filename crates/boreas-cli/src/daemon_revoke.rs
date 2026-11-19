//! Runtime revocation gate for one business path.
//!
//! `StatusStore::accept_signed_snapshot` is the store's public verify-and-commit
//! entry, but its only production policy is [`boreas_pki::status_store::RevocationRelayPolicy::none`].
//! That policy rejects every non-empty `revocations` payload with
//! `RevocationPermission` before the snapshot is stored, and `apply_revocations`
//! is private. This module therefore cannot ask the store to apply a revocation.
//!
//! What it does verify, through [`boreas_pki::management::verify_signed_identity`]
//! (the same `ManagementTrust::verify_and_authorize` path the store uses):
//! - both Ed25519 and ML-DSA-65 signatures over the canonical TBS;
//! - the issuer is a trusted `StatusSigner` for this `net_id`;
//! - `issued_at <= now_us < expires`, where `now_us` is the caller's trusted UTC.
//!
//! What it does **not** verify:
//! - that `now_us` came from a trusted clock (`observe_trusted_utc` is not called);
//! - that the `StatusSigner` is the `IdentityAuthority`, `NetworkRoot`, or a Core
//!   key. A snapshot entry is not per-authority evidence;
//! - durable anti-replay. A rejected snapshot leaves [`RevocationSet`] unchanged,
//!   but a previously accepted node id is not forgotten by a later snapshot.

#![cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]

use std::collections::BTreeSet;

use boreas_pki::management::{ManagementTrust, verify_signed_identity};
use boreas_pki::revoke_cleanup::{self, ApplyResult, CleanupTable, VerifiedRevocationScope};
use boreas_proto::objects::ObjectBody;
use boreas_proto::revocation::{IssuerClass, RevocationEntry, RevocationPayload};

/// Node slots whose business path must stop.
///
/// Membership is `(node_id, identity_generation)` taken from revocation entries
/// that [`apply_signed_status`] decoded from a dual-signed, still-fresh snapshot
/// and that [`revoke_cleanup::apply_verified_scoped`] accepted. It is not itself
/// a signature check, and it is not durable across process restart.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationSet {
    revoked: BTreeSet<(u16, u64)>,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self {
            revoked: BTreeSet::new(),
        }
    }

    /// `true` when this exact node slot and generation was admitted by
    /// [`apply_signed_status`]. A different generation of the same node is not a match.
    pub fn contains(&self, node_id: u16, identity_generation: u64) -> bool {
        self.revoked.contains(&(node_id, identity_generation))
    }

    // Used by tests/revoke_runtime.rs through the lib target. The bin target
    // never calls it, and clippy lints that target without seeing the integration
    // tests, so the use is invisible to it.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Replace membership with the session-withdrawing scopes from a verified store.
    ///
    /// `scopes` must already come from [`boreas_pki::status_store::StatusStore::revocation_scopes`]
    /// (or an equivalent verified source). This does not verify signatures. Route-only
    /// and direct scopes are ignored because they do not withdraw the peer's path.
    /// The previous membership is discarded, so the set tracks that one source.
    pub fn sync_verified_scopes(&mut self, scopes: &[VerifiedRevocationScope]) {
        self.revoked.clear();
        for scope in scopes {
            if entry_withdraws_sessions(scope.class) {
                self.revoked.insert((scope.node_id, scope.generation));
            }
        }
    }
}

/// Why one snapshot did not change the revocation set.
///
/// `dead_code` is allowed because only `tests/revoke_runtime.rs` matches on these
/// variants, and clippy's bin-target lint does not see that integration test.
#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevokeApplyError {
    /// The trust layer rejected the envelope: signature, issuer, network, or window.
    SnapshotRejected,
    /// The envelope verified but its body is not a StatusSnapshot.
    NotStatusSnapshot,
    /// The signed window is internally inconsistent.
    InvalidWindow,
    /// `revocations` bytes are not a canonical payload.
    UndecodableRevocations,
    /// An entry's class/scope binding is outside the cleanup model's permission.
    ScopeNotPermitted,
}

/// Summary of one accepted snapshot.
///
/// Read by `tests/revoke_runtime.rs`; the bin target never constructs it.
#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedStatus {
    /// Signed snapshot sequence.
    pub sequence: u64,
    /// Size of the revocation set after this snapshot's entries were inserted.
    /// This is not a delta and it is not a signature count.
    pub revoked_peers: usize,
}

/// Verify one `status.signed` envelope and apply its revocation entries.
///
/// On success, every permitted entry is passed to
/// [`revoke_cleanup::apply_verified_scoped`] and its `(node_id, generation)` is
/// inserted into `set`. On any error, neither `set` nor `cleanup` is modified.
///
/// `now_us` must be trusted UTC microseconds. This function does not read the
/// system clock and does not extend freshness when the same bytes are applied again.
#[allow(dead_code)] // exercised by tests/revoke_runtime.rs, not by the bin target
pub fn apply_signed_status(
    trust: &mut ManagementTrust,
    raw_signed: &[u8],
    now_us: u64,
    set: &mut RevocationSet,
    cleanup: &mut CleanupTable,
) -> Result<AppliedStatus, RevokeApplyError> {
    let verified = verify_signed_identity(trust, raw_signed, now_us)
        .map_err(|_| RevokeApplyError::SnapshotRejected)?;
    let object = verified.object();
    let ObjectBody::StatusSnapshot(body) = &object.body else {
        return Err(RevokeApplyError::NotStatusSnapshot);
    };
    if body.issued_at != object.issued_at
        || body.next_update != object.expires
        || body.sequence != object.seq
        || body.issued_at >= body.next_update
    {
        return Err(RevokeApplyError::InvalidWindow);
    }
    let payload = if body.revocations.is_empty() {
        RevocationPayload::empty()
    } else {
        RevocationPayload::decode(&body.revocations)
            .map_err(|_| RevokeApplyError::UndecodableRevocations)?
    };
    let scopes = scopes_from_payload(&payload)?;
    // The snapshot is fully checked before either table grows. A later entry that
    // the cleanup model refuses therefore cannot leave a partial revocation behind.
    let mut next_cleanup = cleanup.clone();
    for scope in &scopes {
        if revoke_cleanup::apply_verified_scoped(&mut next_cleanup, scope) != ApplyResult::Cleared {
            return Err(RevokeApplyError::ScopeNotPermitted);
        }
    }
    *cleanup = next_cleanup;
    for scope in &scopes {
        set.revoked.insert((scope.node_id, scope.generation));
    }
    Ok(AppliedStatus {
        sequence: body.sequence,
        revoked_peers: set.revoked.len(),
    })
}

#[allow(dead_code)] // reached only through apply_signed_status
fn scopes_from_payload(
    payload: &RevocationPayload,
) -> Result<Vec<VerifiedRevocationScope>, RevokeApplyError> {
    let mut scopes = Vec::with_capacity(payload.len());
    for entry in payload.entries() {
        let scope = scope_from_entry(entry);
        if !scope.permitted() {
            return Err(RevokeApplyError::ScopeNotPermitted);
        }
        scopes.push(scope);
    }
    Ok(scopes)
}

#[allow(dead_code)] // reached only through apply_signed_status
fn scope_from_entry(entry: &RevocationEntry) -> VerifiedRevocationScope {
    VerifiedRevocationScope {
        class: entry.class,
        origin_core: entry.origin_core,
        node_id: entry.node_id,
        generation: entry.identity_generation,
        target_id: entry.target_id,
        epoch: entry.epoch,
    }
}

/// Decision for one poll of a business path, before any packet is forwarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardPoll {
    /// The peer is not in the revocation set. The caller may forward.
    Forward,
    /// The peer's node id and generation were revoked. The caller must close the path.
    Revoked,
}

/// Whether the path's current peer may be forwarded on this poll.
///
/// This does not verify a snapshot and does not read a clock. It only looks up
/// `(peer_node_id, peer_generation)` in a set previously filled by
/// [`apply_signed_status`]. `forwarded` is incremented only for [`ForwardPoll::Forward`];
/// `failures` is incremented only for [`ForwardPoll::Revoked`].
pub fn poll_peer_forward(
    set: &RevocationSet,
    peer_node_id: u16,
    peer_generation: u64,
    forwarded: &mut u64,
    failures: &mut u64,
) -> ForwardPoll {
    if set.contains(peer_node_id, peer_generation) {
        *failures = failures.saturating_add(1);
        ForwardPoll::Revoked
    } else {
        *forwarded = forwarded.saturating_add(1);
        ForwardPoll::Forward
    }
}

/// `true` when a decoded entry withdraws the peer's sessions.
///
/// Route-only entries still enter [`RevocationSet`] (the path stops rather than
/// keeping a half-revoked peer), but this reports the session-relevant classes.
/// It does not verify a signature.
pub fn entry_withdraws_sessions(class: IssuerClass) -> bool {
    matches!(class, IssuerClass::Identity | IssuerClass::Core)
}
