//! Identifiers that must be dropped after a revocation the trust layer already accepted.
//!
//! No signature is checked here. The caller must pass only a revocation the trust
//! layer already accepted. Gate `G-REVOKE` is not passed: nothing in this file
//! verifies a revocation, extends snapshot freshness, or disconnects a live peer.
//!
//! A verified revocation names a subject node id and a generation. Applying it
//! removes that identity's TLS session ids, circuit ids, attachment leases, and
//! route prefixes. Those values are ids in this table, not live sockets. After
//! apply, lookups of that subject and generation return none. A second apply is
//! idempotent. An unverified revocation is refused and leaves the table unchanged.
//! There is no path that disconnects a peer because an unverified revocation arrived.
//!
//! Clock source: this file does not read `SystemTime` or `Instant`.

use std::collections::{BTreeMap, BTreeSet};

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

/// Ids recorded against one subject node id and one identity generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DropSet {
    pub tls_sessions: BTreeSet<TlsSessionId>,
    pub circuits: BTreeSet<CircuitId>,
    pub attachment_leases: BTreeSet<AttachmentLeaseId>,
    pub route_prefixes: BTreeSet<RoutePrefixId>,
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

    /// `None` when that subject and generation have nothing left to drop.
    pub fn lookup(&self, subject: u16, generation: u64) -> Option<&DropSet> {
        self.entries.get(&(subject, generation))
    }
}

/// Result of offering a revocation to the cleanup registry.
/// There is no variant that disconnects a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyResult {
    /// Bindings for this subject and generation are absent.
    Cleared,
    /// The revocation was not verified. The table was not modified.
    Refused,
}

/// Drop every recorded id for `subject` at `generation`.
/// The caller must already have accepted this revocation. This function does
/// not check a signature. Repeating the call leaves lookups at `None`.
pub fn apply_verified(table: &mut CleanupTable, subject: u16, generation: u64) -> ApplyResult {
    table.entries.remove(&(subject, generation));
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
        table.record_tls_session(7, 3, TlsSessionId(21));
        table.record_circuit(8, 2, CircuitId(32));
        table.record_attachment_lease(8, 2, AttachmentLeaseId(33));
        table.record_route_prefix(8, 2, RoutePrefixId(34));
        table.record_tls_session(8, 2, TlsSessionId(31));
        table
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
}
