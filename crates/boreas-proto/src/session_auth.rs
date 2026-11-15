//! Authorization half of master-plan §5.2.
//!
//! TLS completion is not authorization. Callers pass a phase and two
//! already-decoded expectations; this module does not read `SessionHello` /
//! `SessionAccept` bytes, does not perform a handshake, and does not pass
//! `G-AUTHZ`.

use crate::PROTO_MAJOR;

/// Where a connection sits relative to application acceptance.
///
/// `TlsDone` means the inner handshake finished and nothing else. It is not
/// a grant. `SessionAccepted` means the caller has already decided the hello
/// and accept matched; this module does not make that decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Inner TLS is complete. The session is not accepted.
    TlsDone,
    /// Caller has accepted the session after the hello matched.
    SessionAccepted,
}

/// An action a connection might attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Perm {
    /// Enrollment on a registration-incomplete connection.
    Enrollment,
    /// IP forwarding.
    IpForward,
    /// Directory enumeration.
    DirectoryEnumerate,
    /// Accepted-session data.
    Data,
}

/// What `phase` may do.
///
/// `TlsDone` allows only [`Perm::Enrollment`]. IP forward, directory
/// enumeration, and data stay closed: finishing TLS is not authorization.
/// `SessionAccepted` allows all four. The caller supplies the phase.
pub const fn allowed(phase: Phase, perm: Perm) -> bool {
    match phase {
        Phase::TlsDone => matches!(perm, Perm::Enrollment),
        Phase::SessionAccepted => true,
    }
}

/// Session tuple the caller expects, or the tuple a peer presented.
///
/// Field equality is not a handshake and not a signature check. `path_role`
/// is `1` for CDN and `2` for DIR. `security_mode` is `1` for e2e-required
/// and `2` for hop-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Expectation {
    /// Protocol major version. A match requires this to be 3 on both sides.
    pub proto_major: u8,
    /// Network identifier.
    pub net_id: [u8; 16],
    /// Local node id.
    pub local_node: u16,
    /// Local identity generation.
    pub local_gen: u64,
    /// Expected peer node id.
    pub peer_node: u16,
    /// Expected peer identity generation.
    pub peer_gen: u64,
    /// Per-connection instance. Not a secret and not a slot id.
    pub connection_instance: [u8; 16],
    /// `1` = CDN, `2` = DIR.
    pub path_role: u8,
    /// `1` = e2e-required, `2` = hop-only.
    pub security_mode: u8,
}

/// Whether every expectation field is equal.
///
/// `proto_major` must be [`PROTO_MAJOR`] (3) on both sides. Two tuples that
/// agree on any other major still do not match. One differing field is enough
/// to reject. This does not decide that a hello was received.
pub fn hello_matches(expected: &Expectation, presented: &Expectation) -> bool {
    if expected.proto_major != PROTO_MAJOR || presented.proto_major != PROTO_MAJOR {
        return false;
    }
    expected.net_id == presented.net_id
        && expected.local_node == presented.local_node
        && expected.local_gen == presented.local_gen
        && expected.peer_node == presented.peer_node
        && expected.peer_gen == presented.peer_gen
        && expected.connection_instance == presented.connection_instance
        && expected.path_role == presented.path_role
        && expected.security_mode == presented.security_mode
}

/// Core comes only from `IdentityAuthority`.
///
/// `configured_listener` and `has_tls_cert` cannot force this true. An Edge
/// does not become Core by listening or by holding a TLS certificate.
pub const fn edge_can_self_promote(
    configured_listener: bool,
    has_tls_cert: bool,
    identity_authority_says_core: bool,
) -> bool {
    // Both local facts are observed and then discarded. Neither one is a grant.
    let _not_a_grant = (configured_listener, has_tls_cert);
    identity_authority_says_core
}

/// DIR listen: a Core peer, or a valid `DirectGrant` while `allow_edges` is set.
///
/// A grant without `allow_edges` is false. `allow_edges` without a grant and
/// without a Core peer is false.
pub const fn dir_listen_allowed(
    peer_is_core: bool,
    direct_grant_valid: bool,
    allow_edges: bool,
) -> bool {
    peer_is_core || (direct_grant_valid && allow_edges)
}

/// `MemberTicket` references an existing identity. It does not replace the
/// identity CA certificate.
pub const fn member_ticket_replaces_identity_cert() -> bool {
    false
}

/// A roaming Core may not change an identity public key.
pub const fn roaming_core_may_change_identity_key() -> bool {
    false
}

const _: () = assert!(!member_ticket_replaces_identity_cert());
const _: () = assert!(!roaming_core_may_change_identity_key());

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Expectation {
        Expectation {
            proto_major: PROTO_MAJOR,
            net_id: [0x11; 16],
            local_node: 0x0102,
            local_gen: 7,
            peer_node: 0x0304,
            peer_gen: 9,
            connection_instance: [0xAB; 16],
            path_role: 1,
            security_mode: 1,
        }
    }

    #[test]
    fn tls_done_allows_only_enrollment() {
        assert!(allowed(Phase::TlsDone, Perm::Enrollment));
        assert!(!allowed(Phase::TlsDone, Perm::IpForward));
        assert!(!allowed(Phase::TlsDone, Perm::DirectoryEnumerate));
        assert!(!allowed(Phase::TlsDone, Perm::Data));
    }

    #[test]
    fn session_accepted_allows_all_four() {
        assert!(allowed(Phase::SessionAccepted, Perm::Enrollment));
        assert!(allowed(Phase::SessionAccepted, Perm::IpForward));
        assert!(allowed(Phase::SessionAccepted, Perm::DirectoryEnumerate));
        assert!(allowed(Phase::SessionAccepted, Perm::Data));
    }

    #[test]
    fn identical_major_3_expectations_match() {
        assert!(hello_matches(&sample(), &sample()));
    }

    #[test]
    fn agreeing_on_another_major_does_not_match() {
        let mut expected = sample();
        let mut presented = sample();
        expected.proto_major = 2;
        presented.proto_major = 2;
        assert_eq!(expected.proto_major, presented.proto_major);
        assert!(!hello_matches(&expected, &presented));
        presented.proto_major = PROTO_MAJOR;
        assert!(!hello_matches(&expected, &presented));
        assert!(!hello_matches(&presented, &expected));
    }

    #[test]
    fn one_field_mismatch_rejects() {
        let expected = sample();

        let mut presented = sample();
        presented.net_id[0] ^= 0x01;
        assert!(!hello_matches(&expected, &presented));

        let mut presented = sample();
        presented.local_gen = expected.local_gen + 1;
        assert!(!hello_matches(&expected, &presented));

        let mut presented = sample();
        presented.peer_gen = expected.peer_gen + 1;
        assert!(!hello_matches(&expected, &presented));

        let mut presented = sample();
        presented.connection_instance[15] ^= 0x01;
        assert!(!hello_matches(&expected, &presented));

        let mut presented = sample();
        presented.local_node = expected.local_node.wrapping_add(1);
        assert!(!hello_matches(&expected, &presented));

        let mut presented = sample();
        presented.peer_node = expected.peer_node.wrapping_add(1);
        assert!(!hello_matches(&expected, &presented));

        let mut presented = sample();
        presented.path_role = 2;
        assert!(!hello_matches(&expected, &presented));

        let mut presented = sample();
        presented.security_mode = 2;
        assert!(!hello_matches(&expected, &presented));
    }

    #[test]
    fn listener_and_cert_cannot_self_promote() {
        assert!(!edge_can_self_promote(true, true, false));
        assert!(!edge_can_self_promote(true, false, false));
        assert!(!edge_can_self_promote(false, true, false));
        assert!(!edge_can_self_promote(false, false, false));
        assert!(edge_can_self_promote(false, false, true));
        assert!(edge_can_self_promote(true, true, true));
    }

    #[test]
    fn dir_listen_needs_core_or_grant_and_allow_edges() {
        assert!(dir_listen_allowed(true, false, false));
        assert!(dir_listen_allowed(true, true, false));
        assert!(dir_listen_allowed(true, false, true));
        assert!(dir_listen_allowed(false, true, true));
        assert!(!dir_listen_allowed(false, true, false));
        assert!(!dir_listen_allowed(false, false, true));
        assert!(!dir_listen_allowed(false, false, false));
    }

    #[test]
    fn ticket_and_roaming_core_cannot_replace_identity() {
        assert!(!member_ticket_replaces_identity_cert());
        assert!(!roaming_core_may_change_identity_key());
    }
}
