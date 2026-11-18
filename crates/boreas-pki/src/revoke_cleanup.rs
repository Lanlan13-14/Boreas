//! Identifiers that must be dropped after a revocation the trust layer already accepted.
//!
//! No signature is checked here. The caller must pass only a revocation the trust
//! layer already accepted. Gate `G-REVOKE` is not passed: nothing in this file
//! verifies a revocation, extends snapshot freshness, or disconnects a live peer.
//!
//! A verified revocation names a subject node id and a generation. Applying it
//! removes that identity's TLS session ids, circuit ids, attachment leases,
//! direct-grant ids and route prefixes. Those values are ids in this table, not
//! live sockets. After apply, lookups of that subject and generation return none.
//! A second apply is idempotent. An unverified revocation is refused and leaves the
//! table unchanged. There is no path that disconnects a peer because an unverified
//! revocation arrived.
//!
//! [`apply_verified_scoped`] is the class-aware path. The class of a verified entry
//! limits which categories it may drop, so a Core-class decision can clear only that
//! Core's own node and never another Core's sessions, and a Route-class decision can
//! touch only route-prefix ids. A scope whose class/origin binding is not permitted is
//! refused with [`ApplyResult::RefusedOutOfScope`] and the table is left unchanged.
//!
//! `Direct` is deliberately refused. The subject's home Core is not the issuer of its
//! direct grants: a roaming Core may sign a `DirectGrant` that covers the same
//! subject, and the entry carries no grant-issuer evidence. Treating
//! `origin_core == home_core_id(node_id)` as authority would therefore let the model
//! mislabel a roaming Core's decision as the home Core's. Direct-grant revocation
//! needs a per-authority `DirectRevocation` object (or equivalent per-grant issuer
//! proof), not this class. `DropSet::direct_grants` remains because an `Identity` or
//! `Core` decision may still clear those ids.
//!
//! Clock source: this file does not read `SystemTime` or `Instant`.

use std::collections::{BTreeMap, BTreeSet};

use boreas_proto::revocation::IssuerClass;

/// Highest overlay home-Core slot id.
const MAX_HOME_CORE_ID: u8 = 16;

/// Inner TLS session identifier. Not a socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TlsSessionId(pub u64);

/// End-to-end virtual circuit identifier. Not a socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CircuitId(pub u128);

/// Attachment-lease identifier. Not a live lease object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AttachmentLeaseId(pub u64);

/// Route-prefix identifier. Not an installed kernel route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RoutePrefixId(pub u64);

/// Direct-grant identifier. Not a live endpoint or socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DirectGrantId(pub u64);

/// Ids recorded against one subject node id and one identity generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DropSet {
    pub tls_sessions: BTreeSet<TlsSessionId>,
    pub circuits: BTreeSet<CircuitId>,
    pub attachment_leases: BTreeSet<AttachmentLeaseId>,
    pub route_prefixes: BTreeSet<RoutePrefixId>,
    pub direct_grants: BTreeSet<DirectGrantId>,
}
impl DropSet {
    /// `true` when no category holds an id any more.
    pub fn is_empty(&self) -> bool {
        self.tls_sessions.is_empty()
            && self.circuits.is_empty()
            && self.attachment_leases.is_empty()
            && self.route_prefixes.is_empty()
            && self.direct_grants.is_empty()
    }
}

/// A class-scoped revocation record already checked by the trust layer.
///
/// Nothing here re-verifies a signature, and the fields are not evidence on their own:
/// [`VerifiedRevocationScope::permitted`] re-checks the class/scope binding so a caller
/// cannot smuggle an out-of-scope decision past the table. The name records the
/// caller's contract; it is not proof of an `IdentityAuthority`, `NetworkRoot`,
/// `RouteAuthority` or `CoreOperationalKey` signature. In particular, `Direct` is not
/// permitted at all (see the module documentation).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRevocationScope {
    pub class: IssuerClass,
    pub origin_core: u8,
    pub node_id: u16,
    pub generation: u64,
    pub target_id: u64,
    pub epoch: u64,
}
impl VerifiedRevocationScope {
    /// Home Core slot of this scope's node, if the node id is a valid overlay slot.
    ///
    /// This is the node's permanent slot owner, **not** the issuer of a
    /// `DirectGrant` that may cover the node.
    pub fn home_core(&self) -> Option<u8> {
        home_core_id(self.node_id)
    }

    /// Structural permission: does this class/scope combination make sense at all?
    ///
    /// `Direct` is always refused. The home Core of `node_id` is not the issuer of
    /// its direct grants, so the old `origin_core == home_core` test was not an
    /// issuer check and must not be used as one. The remaining classes are
    /// structural checks only; the caller still owns the authority proof.
    pub fn permitted(&self) -> bool {
        if self.generation == 0 || home_core_id(self.node_id).is_none() {
            return false;
        }
        match self.class {
            IssuerClass::Identity => self.origin_core == 0 && self.target_id == 0,
            IssuerClass::Route => self.origin_core == 0,
            IssuerClass::Core => {
                self.target_id == 0
                    && self.origin_core != 0
                    && home_core_id(self.node_id) == Some(self.origin_core)
            }
            IssuerClass::Direct => false,
        }
    }
}

/// In-memory cleanup registry. Keys are `(subject node id, generation)`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CleanupTable {
    entries: BTreeMap<(u16, u64), DropSet>,
}

impl CleanupTable {
    fn slot(&mut self, subject: u16, generation: u64) -> &mut DropSet {
        self.entries.entry((subject, generation)).or_default()
    }

    pub fn record_tls_session(&mut self, subject: u16, generation: u64, id: TlsSessionId) {
        self.slot(subject, generation).tls_sessions.insert(id);
    }

    pub fn record_circuit(&mut self, subject: u16, generation: u64, id: CircuitId) {
        self.slot(subject, generation).circuits.insert(id);
    }

    pub fn record_attachment_lease(
        &mut self,
        subject: u16,
        generation: u64,
        id: AttachmentLeaseId,
    ) {
        self.slot(subject, generation).attachment_leases.insert(id);
    }

    pub fn record_route_prefix(&mut self, subject: u16, generation: u64, id: RoutePrefixId) {
        self.slot(subject, generation).route_prefixes.insert(id);
    }

    pub fn record_direct_grant(&mut self, subject: u16, generation: u64, id: DirectGrantId) {
        self.slot(subject, generation).direct_grants.insert(id);
    }

    /// `None` when that subject and generation have nothing left to drop.
    pub fn lookup(&self, subject: u16, generation: u64) -> Option<&DropSet> {
        self.entries.get(&(subject, generation))
    }
}

/// Home Core slot of a permanent overlay node id.
fn home_core_id(node_id: u16) -> Option<u8> {
    let home_core = (node_id >> 8) + 1;
    if !(1..=u16::from(MAX_HOME_CORE_ID)).contains(&home_core) {
        return None;
    }
    let octet = (node_id & 0xff) as u8;
    if octet == 1 || (2..=251).contains(&octet) {
        u8::try_from(home_core).ok()
    } else {
        None
    }
}

/// `true` when a Core-scoped decision from `origin_core` covers `node_id`'s slot.
pub fn core_scope_covers(origin_core: u8, node_id: u16) -> bool {
    home_core_id(node_id) == Some(origin_core)
}

/// Result of offering a revocation to the cleanup registry.
/// There is no variant that disconnects a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyResult {
    /// Bindings for this subject and generation are absent.
    Cleared,
    /// The revocation was not verified. The table was not modified.
    Refused,
    /// The scope's class/origin binding is not permitted. The table was not modified.
    RefusedOutOfScope,
}

/// Drop every recorded id for `subject` at `generation`.
/// The caller must already have accepted this revocation. This function does
/// not check a signature. Repeating the call leaves lookups at `None`.
pub fn apply_verified(table: &mut CleanupTable, subject: u16, generation: u64) -> ApplyResult {
    table.entries.remove(&(subject, generation));
    ApplyResult::Cleared
}

/// Apply one verified, class-scoped revocation entry.
///
/// The category set is decided by the entry's class, so a decision can never drop
/// more than its authority may:
///
/// - `Identity`: every category for the subject.
/// - `Core`: sessions, circuits, leases and direct grants of a node of that same
///   home Core only; route prefixes are not touched.
/// - `Route`: route-prefix ids only, and only the named id when `target_id != 0`.
/// - `Direct`: refused. The subject's home Core is not the grant issuer, so this
///   model has no sound way to apply a Direct-class decision.
///
/// A scope whose class/origin binding fails [`VerifiedRevocationScope::permitted`]
/// is refused with [`ApplyResult::RefusedOutOfScope`] and the table is unchanged,
/// so a Core cannot clear another Core's sessions through this path.
pub fn apply_verified_scoped(
    table: &mut CleanupTable,
    scope: &VerifiedRevocationScope,
) -> ApplyResult {
    if !scope.permitted() {
        return ApplyResult::RefusedOutOfScope;
    }
    let Some(slot) = table.entries.get_mut(&(scope.node_id, scope.generation)) else {
        return ApplyResult::Cleared;
    };
    match scope.class {
        IssuerClass::Identity => {
            slot.tls_sessions.clear();
            slot.circuits.clear();
            slot.attachment_leases.clear();
            slot.route_prefixes.clear();
            slot.direct_grants.clear();
        }
        IssuerClass::Core => {
            slot.tls_sessions.clear();
            slot.circuits.clear();
            slot.attachment_leases.clear();
            slot.direct_grants.clear();
        }
        IssuerClass::Route => {
            if scope.target_id == 0 {
                slot.route_prefixes.clear();
            } else {
                slot.route_prefixes.remove(&RoutePrefixId(scope.target_id));
            }
        }
        // `permitted()` already refuses Direct. Keep the arm fail-closed rather
        // than letting a future relaxation silently borrow the Core category set.
        IssuerClass::Direct => return ApplyResult::RefusedOutOfScope,
    }
    if slot.is_empty() {
        table.entries.remove(&(scope.node_id, scope.generation));
    }
    ApplyResult::Cleared
}

/// Refuse an unverified revocation. The table is left unchanged, including when
/// the named subject currently has sessions, circuits, leases, or prefixes.
/// A normal core cannot use this path to disconnect someone else.
pub fn apply_unverified(table: &mut CleanupTable, subject: u16, generation: u64) -> ApplyResult {
    let _observed = table.lookup(subject, generation);
    ApplyResult::Refused
}

/// A normal forwarding core cannot revoke someone else's identity.
/// `true` only when `revoker_is_subject_authority` is `true`.
pub const fn core_may_revoke_other(revoker_is_subject_authority: bool) -> bool {
    revoker_is_subject_authority
}

/// Re-delivering a snapshot or revocation does not extend signed freshness.
/// This file does not read a local receive clock and does not touch
/// `issued_at` or `next_update`.
pub const fn redelivery_extends_freshness() -> bool {
    false
}

/// Stale status does not keep existing flows.
/// Stopping business forwarding is already decided by [`crate::enforcement::Decision`]:
/// `StopBusiness` and `ClockHold` stop packets already in flight, and only `Forward`
/// allows them. This registry does not make that decision.
pub const fn stale_keeps_existing_flows() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populated() -> CleanupTable {
        let mut table = CleanupTable::default();
        table.record_tls_session(7, 2, TlsSessionId(11));
        table.record_circuit(7, 2, CircuitId(12));
        table.record_attachment_lease(7, 2, AttachmentLeaseId(13));
        table.record_route_prefix(7, 2, RoutePrefixId(14));
        table.record_direct_grant(7, 2, DirectGrantId(15));
        table.record_tls_session(7, 3, TlsSessionId(21));
        table.record_circuit(8, 2, CircuitId(32));
        table.record_attachment_lease(8, 2, AttachmentLeaseId(33));
        table.record_route_prefix(8, 2, RoutePrefixId(34));
        table.record_direct_grant(8, 2, DirectGrantId(35));
        table.record_tls_session(8, 2, TlsSessionId(31));
        table
    }

    fn scope(
        class: IssuerClass,
        origin_core: u8,
        node_id: u16,
        generation: u64,
        target_id: u64,
    ) -> VerifiedRevocationScope {
        VerifiedRevocationScope {
            class,
            origin_core,
            node_id,
            generation,
            target_id,
            epoch: 1,
        }
    }

    #[test]
    fn verified_revocation_clears_only_named_generation() {
        let mut table = populated();
        let found = table.lookup(7, 2).expect("recorded");
        assert!(found.tls_sessions.contains(&TlsSessionId(11)));
        assert!(found.circuits.contains(&CircuitId(12)));
        assert!(found.attachment_leases.contains(&AttachmentLeaseId(13)));
        assert!(found.route_prefixes.contains(&RoutePrefixId(14)));

        assert_eq!(apply_verified(&mut table, 7, 2), ApplyResult::Cleared);
        assert!(table.lookup(7, 2).is_none());
        assert!(table.lookup(7, 3).is_some());
        assert!(table.lookup(8, 2).is_some());
    }

    #[test]
    fn second_verified_apply_is_idempotent() {
        let mut table = populated();
        assert_eq!(apply_verified(&mut table, 7, 2), ApplyResult::Cleared);
        let after_first = table.clone();
        assert_eq!(apply_verified(&mut table, 7, 2), ApplyResult::Cleared);
        assert_eq!(apply_verified(&mut table, 9, 1), ApplyResult::Cleared);
        assert_eq!(table, after_first);
        assert!(table.lookup(7, 2).is_none());
        assert!(table.lookup(9, 1).is_none());
    }

    #[test]
    fn unverified_revocation_is_refused_and_does_not_disconnect() {
        let mut table = populated();
        let before = table.clone();
        assert_eq!(apply_unverified(&mut table, 7, 2), ApplyResult::Refused);
        assert_eq!(apply_unverified(&mut table, 8, 2), ApplyResult::Refused);
        assert_eq!(table, before);
        assert!(
            table
                .lookup(7, 2)
                .unwrap()
                .tls_sessions
                .contains(&TlsSessionId(11))
        );
        assert!(
            table
                .lookup(8, 2)
                .unwrap()
                .circuits
                .contains(&CircuitId(32))
        );
        assert!(!core_may_revoke_other(false));
        assert!(core_may_revoke_other(true));
    }

    #[test]
    fn redelivery_does_not_extend_freshness() {
        assert!(!redelivery_extends_freshness());
    }

    #[test]
    fn stale_does_not_keep_existing_flows() {
        assert!(!stale_keeps_existing_flows());
        assert!(!crate::enforcement::business_forwarding_allowed(
            crate::enforcement::Decision::StopBusiness
        ));
        assert!(!crate::enforcement::business_forwarding_allowed(
            crate::enforcement::Decision::ClockHold
        ));
        assert!(crate::enforcement::business_forwarding_allowed(
            crate::enforcement::Decision::Forward
        ));
    }

    #[test]
    fn core_scoped_entry_cannot_clear_another_cores_node() {
        let mut table = populated();
        let before = table.clone();
        // Node 7 lives in home Core 1, so a decision from Core 4 is out of scope.
        let foreign = scope(IssuerClass::Core, 4, 7, 2, 0);
        assert_eq!(
            apply_verified_scoped(&mut table, &foreign),
            ApplyResult::RefusedOutOfScope
        );
        assert_eq!(table, before);
        assert!(!core_scope_covers(4, 7));
        assert!(core_scope_covers(1, 7));

        // Its own Core may drop sessions, circuits, leases and direct grants.
        let own = scope(IssuerClass::Core, 1, 7, 2, 0);
        assert_eq!(
            apply_verified_scoped(&mut table, &own),
            ApplyResult::Cleared
        );
        let remaining = table.lookup(7, 2).expect("route prefixes remain");
        assert!(remaining.tls_sessions.is_empty());
        assert!(remaining.circuits.is_empty());
        assert!(remaining.attachment_leases.is_empty());
        assert!(remaining.direct_grants.is_empty());
        assert!(remaining.route_prefixes.contains(&RoutePrefixId(14)));
        assert!(table.lookup(7, 3).is_some());
    }

    #[test]
    fn route_class_removes_only_route_prefix_ids() {
        let mut table = populated();
        table.record_route_prefix(7, 2, RoutePrefixId(16));
        let named = scope(IssuerClass::Route, 0, 7, 2, 14);
        assert_eq!(
            apply_verified_scoped(&mut table, &named),
            ApplyResult::Cleared
        );
        let remaining = table.lookup(7, 2).expect("other ids remain");
        assert!(!remaining.route_prefixes.contains(&RoutePrefixId(14)));
        assert!(remaining.route_prefixes.contains(&RoutePrefixId(16)));
        assert!(!remaining.tls_sessions.is_empty());

        let all = scope(IssuerClass::Route, 0, 7, 2, 0);
        assert_eq!(
            apply_verified_scoped(&mut table, &all),
            ApplyResult::Cleared
        );
        let remaining = table.lookup(7, 2).expect("session ids remain");
        assert!(remaining.route_prefixes.is_empty());
        assert!(!remaining.tls_sessions.is_empty());
    }

    #[test]
    fn direct_class_is_refused_even_when_origin_matches_home_core() {
        let mut table = populated();
        let before = table.clone();
        // Node 7 has home Core 1. The old model treated that equality as grant
        // issuer evidence; a roaming Core may actually have signed the grant, and
        // the entry carries no issuer proof. Both the matching and a foreign
        // origin_core must be refused without touching the table.
        for origin_core in [1, 4] {
            let direct = scope(IssuerClass::Direct, origin_core, 7, 2, 0);
            assert!(!direct.permitted());
            assert_eq!(
                apply_verified_scoped(&mut table, &direct),
                ApplyResult::RefusedOutOfScope
            );
            assert_eq!(table, before);
        }
        // Core and Identity can still remove direct-grant ids for a node they
        // legitimately cover; only the Direct class itself is unavailable.
        let core = scope(IssuerClass::Core, 1, 7, 2, 0);
        assert_eq!(
            apply_verified_scoped(&mut table, &core),
            ApplyResult::Cleared
        );
        assert!(table.lookup(7, 2).unwrap().direct_grants.is_empty());
    }

    #[test]
    fn identity_class_clears_every_category_and_out_of_scope_is_refused() {
        let mut table = populated();
        let identity = scope(IssuerClass::Identity, 0, 7, 2, 0);
        assert_eq!(
            apply_verified_scoped(&mut table, &identity),
            ApplyResult::Cleared
        );
        assert!(table.lookup(7, 2).is_none());
        assert!(table.lookup(7, 3).is_some());
        assert!(table.lookup(8, 2).is_some());

        let before = table.clone();
        let bogus = scope(IssuerClass::Identity, 1, 7, 3, 0);
        assert_eq!(
            apply_verified_scoped(&mut table, &bogus),
            ApplyResult::RefusedOutOfScope
        );
        assert_eq!(table, before);
        assert!(matches!(
            apply_verified_scoped(&mut table, &scope(IssuerClass::Core, 0, 7, 3, 0)),
            ApplyResult::RefusedOutOfScope
        ));
        assert_eq!(table, before);
    }
}
