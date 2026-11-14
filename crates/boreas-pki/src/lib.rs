//! Pure Boreas PKI policy checks. This crate deliberately performs no encoding,
//! certificate parsing, signing, or cryptographic verification.

#![forbid(unsafe_code)]

use core::fmt;

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

/// IPv4 identity mapping is fixed at 10.20.0.0/16.
pub fn expected_vip(
    home_core_id: u8,
    vip_octet: u8,
    role: NodeRole,
) -> Result<[u8; 4], PolicyError> {
    node_id(home_core_id, vip_octet, role)?;
    Ok([10, 20, home_core_id, vip_octet])
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
        let octet = self.vip[3];
        let id = node_id(self.home_core_id, octet, self.role)?;
        if self.node_id != id {
            return Err(PolicyError::NodeIdMismatch);
        }
        if self.vip != expected_vip(self.home_core_id, octet, self.role)? {
            return Err(PolicyError::VipMismatch);
        }
        match (self.vip6, ula48_base) {
            (Some(v6), Some(base))
                if v6 == expected_vip6(base, self.home_core_id, octet, self.role)? =>
            {
                ()
            }
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
