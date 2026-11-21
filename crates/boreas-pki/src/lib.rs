//! Boreas PKI policy and verification boundaries. Default builds provide policy only;
//! `openssl-backend` enables real candidate/management parsing and cryptographic checks.

#![forbid(unsafe_code)]

#[cfg(feature = "openssl-backend")]
pub mod authority_revocation;
#[cfg(all(feature = "openssl-backend", target_os = "linux"))]
mod core_lsa_store;
/// NetworkRoot-authorized, independently dual-signed DNS zone/VIP authority.
/// Produces opaque verified tokens only; it does not enable the DNS runtime.
#[cfg(feature = "openssl-backend")]
pub mod dns_authority;
#[cfg(feature = "openssl-backend")]
pub mod dns_service_policy;
pub mod enforcement;
pub mod enrollment;
/// Real Ed25519 + ML-DSA management-object verification and IdentityAuthority signing.
/// It requires OpenSSL 3.5+ for the ML-DSA provider and is therefore feature-gated.
#[cfg(feature = "openssl-backend")]
pub mod management;
/// Dual-signature verification of isolated NetworkPolicy candidates (not runtime enablement).
#[cfg(feature = "openssl-backend")]
mod network_policy;
/// Offline authority separation, `roots.cbor` verification, ML-DSA-65 X.509 issuance,
/// and signed `StatusSnapshot` lifecycle (§2.2 / §3.1 / §3.4).
#[cfg(feature = "openssl-backend")]
pub mod provisioning;
pub mod revoke_cleanup;
/// Bounded NetworkRoot authorization candidate validation; requires the real crypto backend.
#[cfg(feature = "openssl-backend")]
pub mod root_authorization;
#[cfg(feature = "openssl-backend")]
pub use network_policy::{
    NetworkPolicyError, VerifiedNetworkContext, VerifiedNetworkPolicy, verify_network_policy,
};
#[cfg(feature = "openssl-backend")]
pub use root_authorization::NetworkRootPin;
/// Durable NetworkPolicy anti-replay watermark; Linux durability only, backend required.
#[cfg(feature = "openssl-backend")]
pub mod network_policy_store;
/// Durable signed-status freshness store; Linux durability only, backend required.
#[cfg(feature = "openssl-backend")]
pub mod status_store;
/// Durable NetworkRoot authorization store; Linux durability only, backend required.
#[cfg(feature = "openssl-backend")]
pub mod trust_store;

use core::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub const MAX_HOME_CORE_ID: u8 = 16;
pub const STATUS_MAX_AGE_US: u64 = 24 * 60 * 60 * 1_000_000;
pub const CLOCK_ROLLBACK_TOLERANCE_US: u64 = 60 * 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    Edge,
    Core,
    EnrollmentService,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    NetworkRoot,
    IdentityAuthority,
    RouteAuthority,
    StatusSigner,
    CoreOperationalKey { core_id: u8 },
    ReleaseRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Genesis,
    RootAuthorization,
    Identity,
    IdentityRevocation,
    RouteGrant,
    RouteRevocation,
    CoreRevocation,
    DirectRevocation,
    StatusSnapshot,
    CoreLsa,
    AttachmentLeaseConfirmation,
    OwnDirectGrant,
    ReleaseManifest,
    AttachmentLease,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidCoreId,
    InvalidOverlayPrefix,
    InvalidVip,
    NodeIdMismatch,
    VipMismatch,
    Vip6Mismatch,
    InvalidUla48,
    InvalidGeneration,
    InvalidValidity,
    UnauthorizedIssuer,
    InvalidSnapshotWindow,
    SnapshotExpired,
    SnapshotFromFuture,
    SequenceNotIncreasing,
    SnapshotIssuedAtRegression,
    SnapshotEquivocation,
    StatusCacheFrozen,
    ClockRollback,
    ClockRecoveryRequired,
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PolicyError {}

/// Canonical RFC1918 IPv4 overlay network.
///
/// Candidate policy/address-derivation API, not end-to-end runtime support.
/// This slice deliberately supports `/16` only to preserve the existing
/// two-octet base + home-Core + host mapping. It reserves service block zero
/// and sixteen Core blocks, each with one Core and 250 Edge slots. Other mask
/// lengths require a separately specified layout and are rejected, not rounded.
/// The expected prefix must come from trusted network policy, never be inferred
/// from the identity being verified or an unauthenticated peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OverlayPrefix {
    base: [u8; 4],
}

impl OverlayPrefix {
    pub const PREFIX_LEN: u8 = 16;
    pub const DEFAULT: Self = Self {
        base: [10, 20, 0, 0],
    };

    pub fn new(base: [u8; 4], prefix_len: u8) -> Result<Self, PolicyError> {
        if prefix_len != Self::PREFIX_LEN || base[2] != 0 || base[3] != 0 {
            return Err(PolicyError::InvalidOverlayPrefix);
        }
        let private = base[0] == 10
            || (base[0] == 172 && (16..=31).contains(&base[1]))
            || (base[0] == 192 && base[1] == 168);
        if !private {
            return Err(PolicyError::InvalidOverlayPrefix);
        }
        Ok(Self { base })
    }

    pub const fn base(self) -> [u8; 4] {
        self.base
    }

    pub const fn prefix_len(self) -> u8 {
        Self::PREFIX_LEN
    }

    pub fn vip(
        self,
        home_core_id: u8,
        vip_octet: u8,
        role: NodeRole,
    ) -> Result<[u8; 4], PolicyError> {
        node_id(home_core_id, vip_octet, role)?;
        Ok([self.base[0], self.base[1], home_core_id, vip_octet])
    }

    /// Reserved authoritative DNS address in service block zero (§3.2).
    pub const fn dns_vip(self) -> [u8; 4] {
        [self.base[0], self.base[1], 0, 53]
    }

    /// Whether `vip` belongs to a node slot (not proof of role or signature).
    pub fn contains_node_vip(self, vip: [u8; 4]) -> bool {
        vip[0] == self.base[0]
            && vip[1] == self.base[1]
            && (1..=MAX_HOME_CORE_ID).contains(&vip[2])
            && (1..=251).contains(&vip[3])
    }
}

impl Default for OverlayPrefix {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for OverlayPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), Self::PREFIX_LEN)
    }
}

impl FromStr for OverlayPrefix {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, length) = value
            .split_once('/')
            .ok_or(PolicyError::InvalidOverlayPrefix)?;
        if length != "16" || value.chars().any(char::is_whitespace) {
            return Err(PolicyError::InvalidOverlayPrefix);
        }
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| PolicyError::InvalidOverlayPrefix)?;
        let prefix_len = length
            .parse::<u8>()
            .map_err(|_| PolicyError::InvalidOverlayPrefix)?;
        Self::new(address.octets(), prefix_len)
    }
}

/// Permanent slot mapping from §3.2. Does not infer home core from current attachment.
pub fn node_id(home_core_id: u8, vip_octet: u8, role: NodeRole) -> Result<u16, PolicyError> {
    if !(1..=MAX_HOME_CORE_ID).contains(&home_core_id) {
        return Err(PolicyError::InvalidCoreId);
    }
    match role {
        NodeRole::Core if vip_octet != 1 => return Err(PolicyError::InvalidVip),
        NodeRole::Edge if !(2..=251).contains(&vip_octet) => return Err(PolicyError::InvalidVip),
        NodeRole::EnrollmentService => return Err(PolicyError::InvalidVip),
        _ => (),
    }
    Ok(((u16::from(home_core_id) - 1) << 8) | u16::from(vip_octet))
}

/// IPv4 identity mapping in the backwards-compatible default 10.20.0.0/16 overlay.
pub fn expected_vip(
    home_core_id: u8,
    vip_octet: u8,
    role: NodeRole,
) -> Result<[u8; 4], PolicyError> {
    expected_vip_in(OverlayPrefix::DEFAULT, home_core_id, vip_octet, role)
}

/// Candidate derivation API using the trusted expected network parameter.
/// Existing signing and runtime callers still use [`expected_vip`].
pub fn expected_vip_in(
    overlay: OverlayPrefix,
    home_core_id: u8,
    vip_octet: u8,
    role: NodeRole,
) -> Result<[u8; 4], PolicyError> {
    overlay.vip(home_core_id, vip_octet, role)
}

/// RFC4193 network /48 base must have its low 80 bits clear. Formula in §3.2.
pub fn expected_vip6(
    ula48_base: u128,
    home_core_id: u8,
    vip_octet: u8,
    role: NodeRole,
) -> Result<u128, PolicyError> {
    node_id(home_core_id, vip_octet, role)?;
    if ula48_base >> 120 != 0xfd || ula48_base & ((1u128 << 80) - 1) != 0 {
        return Err(PolicyError::InvalidUla48);
    }
    Ok(ula48_base | (u128::from(home_core_id) << 72) | u128::from(vip_octet))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIdentity {
    pub node_id: u16,
    pub home_core_id: u8,
    pub vip: [u8; 4],
    /// None means the all-zero VIP6 sentinel (IPv6 disabled).
    pub vip6: Option<u128>,
    pub role: NodeRole,
    pub identity_generation: u64,
    /// Unix UTC microseconds, matching the plan's unix_us fields.
    pub not_before: u64,
    pub expires: u64,
}
impl NodeIdentity {
    pub fn validate(&self, ula48_base: Option<u128>, now_utc: u64) -> Result<(), PolicyError> {
        self.validate_in(OverlayPrefix::DEFAULT, ula48_base, now_utc)
    }

    /// Candidate policy check, not signature verification or negotiation wiring.
    /// Validate the signed VIP against the operator's expected network, not against
    /// a value learned from the object or from an unauthenticated handshake.
    pub fn validate_in(
        &self,
        overlay: OverlayPrefix,
        ula48_base: Option<u128>,
        now_utc: u64,
    ) -> Result<(), PolicyError> {
        let octet = self.vip[3];
        let id = node_id(self.home_core_id, octet, self.role)?;
        if self.node_id != id {
            return Err(PolicyError::NodeIdMismatch);
        }
        if self.vip != expected_vip_in(overlay, self.home_core_id, octet, self.role)? {
            return Err(PolicyError::VipMismatch);
        }
        match (self.vip6, ula48_base) {
            (Some(v6), Some(base))
                if v6 == expected_vip6(base, self.home_core_id, octet, self.role)? => {}
            (None, _) => (),
            _ => return Err(PolicyError::Vip6Mismatch),
        }
        if self.identity_generation == 0 {
            return Err(PolicyError::InvalidGeneration);
        }
        if self.not_before >= self.expires {
            return Err(PolicyError::InvalidValidity);
        }
        if now_utc < self.not_before || now_utc >= self.expires {
            return Err(PolicyError::InvalidValidity);
        }
        Ok(())
    }
}

/// Permission mapping is intentionally independent of whether a signature is valid.
pub fn may_issue(authority: Authority, object: ObjectKind) -> bool {
    use Authority::*;
    use ObjectKind::*;
    match authority {
        NetworkRoot => matches!(object, Genesis | RootAuthorization | CoreRevocation),
        IdentityAuthority => matches!(object, Identity | IdentityRevocation),
        RouteAuthority => matches!(object, RouteGrant | RouteRevocation),
        StatusSigner => object == StatusSnapshot,
        // CoreOperationalKey requires a target-specific proof and is denied by this generic API.
        CoreOperationalKey { .. } => false,
        ReleaseRoot => object == ReleaseManifest,
    }
}

/// Target-aware form for CoreOperationalKey operations. It prevents a globally trusted
/// operational key from authorizing a different Core's LSA/grant/lease confirmation.
pub fn may_issue_for_core(authority: Authority, object: ObjectKind, target_core_id: u8) -> bool {
    match authority {
        Authority::CoreOperationalKey { core_id } => {
            core_id == target_core_id
                && (1..=MAX_HOME_CORE_ID).contains(&core_id)
                && matches!(
                    object,
                    ObjectKind::CoreLsa
                        | ObjectKind::AttachmentLeaseConfirmation
                        | ObjectKind::OwnDirectGrant
                        | ObjectKind::DirectRevocation
                )
        }
        _ => may_issue(authority, object),
    }
}

/// Additional ownership constraint for a CoreOperationalKey: it may only sign objects
/// whose target is that same Core.
pub fn core_owns_target(authority: Authority, target_core_id: u8) -> bool {
    matches!(authority, Authority::CoreOperationalKey { core_id } if core_id == target_core_id && (1..=MAX_HOME_CORE_ID).contains(&core_id))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusSnapshot {
    /// Unix UTC microseconds.
    pub issued_at: u64,
    /// Unix UTC microseconds.
    pub next_update: u64,
    pub sequence: u64,
    pub digest: [u8; 32],
}
impl StatusSnapshot {
    pub fn validate(&self, trusted_now: u64) -> Result<(), PolicyError> {
        if self.issued_at >= self.next_update
            || self.next_update - self.issued_at > STATUS_MAX_AGE_US
        {
            return Err(PolicyError::InvalidSnapshotWindow);
        }
        if self.issued_at > trusted_now {
            return Err(PolicyError::SnapshotFromFuture);
        }
        if trusted_now >= self.next_update {
            return Err(PolicyError::SnapshotExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotResult {
    Accepted,
    DuplicateNotRenewed,
}
#[derive(Clone, Debug, Default)]
pub struct StatusCache {
    current: Option<StatusSnapshot>,
    frozen: bool,
}
impl StatusCache {
    pub fn current(&self) -> Option<StatusSnapshot> {
        self.current
    }
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }
    /// Same snapshot re-delivery is idempotent and never changes signed freshness times.
    /// Conflicting bytes at the same sequence permanently freeze this cache pending operator action.
    pub fn accept(
        &mut self,
        incoming: StatusSnapshot,
        trusted_now: u64,
    ) -> Result<SnapshotResult, PolicyError> {
        if self.frozen {
            return Err(PolicyError::StatusCacheFrozen);
        }
        incoming.validate(trusted_now)?;
        if let Some(old) = self.current {
            if incoming == old {
                return Ok(SnapshotResult::DuplicateNotRenewed);
            }
            if incoming.sequence == old.sequence {
                self.frozen = true;
                return Err(PolicyError::SnapshotEquivocation);
            }
            if incoming.sequence < old.sequence {
                return Err(PolicyError::SequenceNotIncreasing);
            }
            if incoming.issued_at < old.issued_at {
                return Err(PolicyError::SnapshotIssuedAtRegression);
            }
        }
        self.current = Some(incoming);
        Ok(SnapshotResult::Accepted)
    }
}

/// Monotonic trusted-UTC lower bound; caller persists this value across restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedUtc {
    last_trusted_utc: u64,
    rollback_tolerance: u64,
    recovery_required: bool,
}
impl TrustedUtc {
    pub fn new(persisted_floor: u64) -> Self {
        Self {
            last_trusted_utc: persisted_floor,
            rollback_tolerance: CLOCK_ROLLBACK_TOLERANCE_US,
            recovery_required: false,
        }
    }
    pub fn with_tolerance(persisted_floor: u64, tolerance_us: u64) -> Self {
        Self {
            last_trusted_utc: persisted_floor,
            rollback_tolerance: tolerance_us,
            recovery_required: false,
        }
    }
    pub fn last_trusted_utc(&self) -> u64 {
        self.last_trusted_utc
    }
    pub fn recovery_required(&self) -> bool {
        self.recovery_required
    }
    pub fn observe(&mut self, utc_now_us: u64) -> Result<u64, PolicyError> {
        if self.recovery_required {
            return Err(PolicyError::ClockRecoveryRequired);
        }
        if utc_now_us.saturating_add(self.rollback_tolerance) < self.last_trusted_utc {
            self.recovery_required = true;
            return Err(PolicyError::ClockRollback);
        }
        self.last_trusted_utc = self.last_trusted_utc.max(utc_now_us);
        Ok(self.last_trusted_utc)
    }
    /// Explicit trusted management recovery only; caller must independently establish UTC trust.
    pub fn recover_with_trusted_utc(&mut self, trusted_utc_us: u64) -> Result<u64, PolicyError> {
        if trusted_utc_us < self.last_trusted_utc {
            return Err(PolicyError::ClockRollback);
        }
        self.last_trusted_utc = trusted_utc_us;
        self.recovery_required = false;
        Ok(self.last_trusted_utc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ULA: u128 = 0xfd12_3456_789a_0000_0000_0000_0000_0000;
    #[test]
    fn overlay_prefix_accepts_only_canonical_rfc1918_layout() {
        for text in [
            "10.0.0.0/16",
            "10.255.0.0/16",
            "172.16.0.0/16",
            "172.31.0.0/16",
            "192.168.0.0/16",
        ] {
            let prefix: OverlayPrefix = text.parse().unwrap();
            assert_eq!(prefix.to_string(), text);
            assert_eq!(prefix.prefix_len(), 16);
            assert_eq!(prefix.base()[2..], [0, 0]);
        }
        for text in [
            "1.1.1.1",
            "1.1.1.1/16",
            "1.1.0.0/16",
            "100.64.0.0/10",
            "100.64.0.0/16",
            "100.127.0.0/16",
            "172.15.0.0/16",
            "172.32.0.0/16",
            "192.169.0.0/16",
            "127.0.0.0/16",
            "169.254.0.0/16",
            "0.0.0.0/16",
            "224.0.0.0/16",
            "10.20.1.0/16",
            "10.20.0.1/16",
            "10.0.0.0/8",
            "10.20.0.0/15",
            "10.20.0.0/17",
            "10.20.0.0/24",
            "10.20.0.0/32",
            "10.20.0.0/016",
            "10.20.0.0/+16",
            "10.20.0.0/16/16",
            " 10.20.0.0/16",
            "10.20.0.0/16\n",
            "fd00::/16",
        ] {
            assert_eq!(
                text.parse::<OverlayPrefix>(),
                Err(PolicyError::InvalidOverlayPrefix),
                "{text:?}"
            );
        }
        assert_eq!(
            OverlayPrefix::new([10, 20, 0, 1], 16),
            Err(PolicyError::InvalidOverlayPrefix)
        );
        assert_eq!(OverlayPrefix::default().to_string(), "10.20.0.0/16");
    }

    #[test]
    fn custom_prefix_preserves_all_core_and_edge_slots() {
        let prefix: OverlayPrefix = "172.19.0.0/16".parse().unwrap();
        let mut slots = std::collections::HashSet::new();
        for core in 1..=MAX_HOME_CORE_ID {
            let vip = prefix.vip(core, 1, NodeRole::Core).unwrap();
            assert_eq!(vip, [172, 19, core, 1]);
            assert!(prefix.contains_node_vip(vip));
            assert!(slots.insert(vip));
            for host in 2..=251 {
                let vip = expected_vip_in(prefix, core, host, NodeRole::Edge).unwrap();
                assert_eq!(vip, [172, 19, core, host]);
                assert!(prefix.contains_node_vip(vip));
                assert!(slots.insert(vip));
            }
        }
        assert_eq!(slots.len(), 16 * (1 + 250));
        assert_eq!(prefix.dns_vip(), [172, 19, 0, 53]);
        assert!(!slots.contains(&prefix.dns_vip()));
        for vip in [
            [172, 19, 0, 53],
            [172, 19, 17, 1],
            [172, 19, 1, 0],
            [172, 19, 1, 252],
            [10, 20, 1, 1],
        ] {
            assert!(!prefix.contains_node_vip(vip));
        }
        for core in [0, 17] {
            assert_eq!(
                prefix.vip(core, 1, NodeRole::Core),
                Err(PolicyError::InvalidCoreId)
            );
        }
        for host in [0, 1, 252, 255] {
            assert_eq!(
                prefix.vip(1, host, NodeRole::Edge),
                Err(PolicyError::InvalidVip)
            );
        }
        assert_eq!(
            prefix.vip(1, 2, NodeRole::Core),
            Err(PolicyError::InvalidVip)
        );
        assert_eq!(
            prefix.vip(1, 1, NodeRole::EnrollmentService),
            Err(PolicyError::InvalidVip)
        );
    }

    #[test]
    fn custom_identity_requires_trusted_matching_prefix_and_keeps_other_checks() {
        let prefix: OverlayPrefix = "192.168.0.0/16".parse().unwrap();
        let identity = NodeIdentity {
            node_id: node_id(16, 251, NodeRole::Edge).unwrap(),
            home_core_id: 16,
            vip: prefix.vip(16, 251, NodeRole::Edge).unwrap(),
            vip6: None,
            role: NodeRole::Edge,
            identity_generation: 1,
            not_before: 10,
            expires: 20,
        };
        assert_eq!(identity.validate_in(prefix, None, 10), Ok(()));
        assert_eq!(identity.validate(None, 10), Err(PolicyError::VipMismatch));
        assert_eq!(
            identity.validate_in("172.19.0.0/16".parse().unwrap(), None, 10),
            Err(PolicyError::VipMismatch)
        );
        assert_eq!(
            identity.validate_in(prefix, None, 20),
            Err(PolicyError::InvalidValidity)
        );
        assert_eq!(
            NodeIdentity {
                node_id: 2,
                ..identity.clone()
            }
            .validate_in(prefix, None, 10),
            Err(PolicyError::NodeIdMismatch)
        );
        assert_eq!(
            NodeIdentity {
                identity_generation: 0,
                ..identity.clone()
            }
            .validate_in(prefix, None, 10),
            Err(PolicyError::InvalidGeneration)
        );
        let default_identity = NodeIdentity {
            vip: [10, 20, 16, 251],
            ..identity
        };
        assert_eq!(default_identity.validate(None, 10), Ok(()));
        assert_eq!(
            default_identity.validate_in(prefix, None, 10),
            Err(PolicyError::VipMismatch)
        );
    }

    #[test]
    fn node_and_vip_mapping_boundaries() {
        assert_eq!(node_id(1, 2, NodeRole::Edge), Ok(2));
        assert_eq!(node_id(16, 251, NodeRole::Edge), Ok(0x0ffb));
        assert_eq!(node_id(1, 1, NodeRole::Core), Ok(1));
        assert_eq!(
            node_id(0, 1, NodeRole::Core),
            Err(PolicyError::InvalidCoreId)
        );
        assert_eq!(
            node_id(1, 252, NodeRole::Edge),
            Err(PolicyError::InvalidVip)
        );
        assert_eq!(expected_vip(4, 7, NodeRole::Edge), Ok([10, 20, 4, 7]));
    }
    #[test]
    fn vip6_mapping_and_identity_generation_role() {
        let v6 = expected_vip6(ULA, 3, 8, NodeRole::Edge).unwrap();
        assert_eq!(v6, ULA | (3u128 << 72) | 8);
        let id = NodeIdentity {
            node_id: 0x0208,
            home_core_id: 3,
            vip: [10, 20, 3, 8],
            vip6: Some(v6),
            role: NodeRole::Edge,
            identity_generation: 1,
            not_before: 10,
            expires: 20,
        };
        assert!(id.validate(Some(ULA), 10).is_ok());
        assert_eq!(
            NodeIdentity {
                identity_generation: 0,
                ..id.clone()
            }
            .validate(Some(ULA), 10),
            Err(PolicyError::InvalidGeneration)
        );
        assert_eq!(
            NodeIdentity { node_id: 8, ..id }.validate(Some(ULA), 10),
            Err(PolicyError::NodeIdMismatch)
        );
        assert_eq!(
            expected_vip6(
                0xfd00_0000_0000_0000_0000_0000_0000_0001,
                3,
                8,
                NodeRole::Edge
            ),
            Err(PolicyError::InvalidUla48)
        );
    }
    #[test]
    fn permissions_are_separated_and_core_bound() {
        assert!(may_issue(
            Authority::IdentityAuthority,
            ObjectKind::Identity
        ));
        assert!(!may_issue(
            Authority::CoreOperationalKey { core_id: 2 },
            ObjectKind::Identity
        ));
        assert!(!may_issue(Authority::ReleaseRoot, ObjectKind::Identity));
        assert!(!may_issue(
            Authority::NetworkRoot,
            ObjectKind::ReleaseManifest
        ));
        assert!(may_issue(
            Authority::StatusSigner,
            ObjectKind::StatusSnapshot
        ));
        assert!(may_issue_for_core(
            Authority::CoreOperationalKey { core_id: 2 },
            ObjectKind::CoreLsa,
            2
        ));
        assert!(!may_issue_for_core(
            Authority::CoreOperationalKey { core_id: 2 },
            ObjectKind::CoreLsa,
            3
        ));
        assert!(may_issue_for_core(
            Authority::CoreOperationalKey { core_id: 2 },
            ObjectKind::DirectRevocation,
            2
        ));
        assert!(!may_issue(
            Authority::CoreOperationalKey { core_id: 2 },
            ObjectKind::CoreLsa
        ));
        assert!(!may_issue(
            Authority::NetworkRoot,
            ObjectKind::IdentityRevocation
        ));
    }
    #[test]
    fn status_freshness_duplicate_and_sequence() {
        let mut cache = StatusCache::default();
        let s = StatusSnapshot {
            issued_at: 100_000_000,
            next_update: 100_000_000 + STATUS_MAX_AGE_US,
            sequence: 1,
            digest: [7; 32],
        };
        assert_eq!(cache.accept(s, 101_000_000), Ok(SnapshotResult::Accepted));
        assert_eq!(
            cache.accept(s, 200_000_000),
            Ok(SnapshotResult::DuplicateNotRenewed)
        );
        assert_eq!(
            cache.accept(s, 100_000_000 + STATUS_MAX_AGE_US),
            Err(PolicyError::SnapshotExpired)
        );
        let mut bad = s;
        bad.sequence = 2;
        bad.next_update += 1;
        assert_eq!(
            cache.accept(bad, 200_000_000),
            Err(PolicyError::InvalidSnapshotWindow)
        );
        let mut equivocation = s;
        equivocation.digest = [8; 32];
        assert_eq!(
            cache.accept(equivocation, 200_000_000),
            Err(PolicyError::SnapshotEquivocation)
        );
        assert!(cache.is_frozen());
        assert_eq!(
            cache.accept(s, 200_000_000),
            Err(PolicyError::StatusCacheFrozen)
        );
        let mut future = s;
        future.issued_at = 201_000_000;
        future.next_update = 202_000_000;
        assert_eq!(
            StatusSnapshot {
                issued_at: future.issued_at,
                next_update: future.next_update,
                sequence: 2,
                digest: future.digest
            }
            .validate(200_000_000),
            Err(PolicyError::SnapshotFromFuture)
        );
    }
    #[test]
    fn trusted_utc_rejects_large_rollback_and_keeps_floor() {
        let mut clock = TrustedUtc::new(1_000_000_000);
        assert_eq!(clock.observe(939_000_000), Err(PolicyError::ClockRollback));
        assert!(clock.recovery_required());
        assert_eq!(
            clock.observe(950_000_000),
            Err(PolicyError::ClockRecoveryRequired)
        );
        assert_eq!(
            clock.recover_with_trusted_utc(950_000_000),
            Err(PolicyError::ClockRollback)
        );
        assert_eq!(
            clock.recover_with_trusted_utc(1_000_000_000),
            Ok(1_000_000_000)
        );
        assert_eq!(clock.observe(950_000_000), Ok(1_000_000_000));
        assert_eq!(clock.observe(1_100_000_000), Ok(1_100_000_000));
        // Exactly 60 seconds is tolerated; more than 60 seconds latches protection.
        assert_eq!(clock.observe(1_040_000_000), Ok(1_100_000_000));
        assert_eq!(
            clock.observe(1_039_999_999),
            Err(PolicyError::ClockRollback)
        );
        assert_eq!(
            clock.observe(1_100_000_000),
            Err(PolicyError::ClockRecoveryRequired)
        );
    }
}
