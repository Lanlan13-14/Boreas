//! Pure routing-policy primitives for Boreas.
//!
//! This crate does not authenticate signatures, certificates, revocations, leases,
//! or object IDs. Callers MUST supply inputs already validated by the appropriate
//! trust layer. Nothing here implements a production packet data plane or TLS;
//! it does not relax the Phase 0 TLS requirements.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A canonical IP network prefix. Construction rejects host bits; it never masks.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Prefix {
    address: IpAddr,
    length: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixError {
    PrefixLengthOutOfRange,
    NonCanonicalHostBits,
}

impl Prefix {
    pub fn new(address: IpAddr, length: u8) -> Result<Self, PrefixError> {
        let p = Self { address, length };
        if !p.length_valid() {
            return Err(PrefixError::PrefixLengthOutOfRange);
        }
        if p.start() != p.address_value() {
            return Err(PrefixError::NonCanonicalHostBits);
        }
        Ok(p)
    }
    pub const fn address(self) -> IpAddr {
        self.address
    }
    pub const fn length(self) -> u8 {
        self.length
    }
    pub const fn is_ipv4(self) -> bool {
        matches!(self.address, IpAddr::V4(_))
    }
    const fn length_valid(self) -> bool {
        if self.is_ipv4() {
            self.length <= 32
        } else {
            self.length <= 128
        }
    }
    fn address_value(self) -> u128 {
        match self.address {
            IpAddr::V4(a) => u32::from(a) as u128,
            IpAddr::V6(a) => u128::from(a),
        }
    }
    fn width(self) -> u8 {
        if self.is_ipv4() { 32 } else { 128 }
    }
    fn start(self) -> u128 {
        self.address_value() & mask(self.width(), self.length)
    }
    fn end(self) -> u128 {
        self.start() | (!mask(self.width(), self.length) & width_mask(self.width()))
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.is_ipv4() == other.is_ipv4()
            && self.start() <= other.end()
            && other.start() <= self.end()
    }
    /// Whether all addresses in `self` are contained in `other`.
    pub fn is_within(self, other: Self) -> bool {
        self.is_ipv4() == other.is_ipv4()
            && self.start() >= other.start()
            && self.end() <= other.end()
    }
}

fn mask(width: u8, len: u8) -> u128 {
    if len == 0 {
        0
    } else if width == 128 {
        u128::MAX << (128 - len)
    } else {
        (u32::MAX << (32 - len)) as u128
    }
}
fn width_mask(width: u8) -> u128 {
    if width == 128 {
        u128::MAX
    } else {
        u32::MAX as u128
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpRange {
    pub first: IpAddr,
    pub last: IpAddr,
}
impl IpRange {
    fn prefix(self) -> Option<Prefix> {
        let (a, b, width) = match (self.first, self.last) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128, 32u8),
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128u8),
            _ => return None,
        };
        if a > b {
            return None;
        }
        // Reserved ranges must be exactly CIDR ranges; validate by bounded bit search.
        (0..=width).find_map(|len| {
            let candidate = Prefix {
                address: self.first,
                length: len,
            };
            (candidate.start() == a && candidate.end() == b).then_some(candidate)
        })
    }
}

/// Exactly the two network-owned ranges from trusted genesis configuration.
/// No default route is represented or inserted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedSet {
    ipv4_network: Prefix,
    ipv6_ula48: Prefix,
}
impl ProtectedSet {
    pub fn from_genesis(ipv4_network: Prefix, ipv6_ula48: Prefix) -> Result<Self, PrefixError> {
        if ipv4_network != Prefix::new(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 0)), 16)?
            || ipv6_ula48.is_ipv4()
            || ipv6_ula48.length != 48
            || !matches!(ipv6_ula48.address, IpAddr::V6(a) if (u128::from(a) >> 120) == 0xfd && ipv6_ula48.start() == u128::from(a))
        {
            return Err(PrefixError::NonCanonicalHostBits);
        }
        Ok(Self {
            ipv4_network,
            ipv6_ula48,
        })
    }
    pub fn from_ula48(address: Ipv6Addr) -> Result<Self, PrefixError> {
        let v4 = Prefix::new(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 0)), 16)?;
        let v6 = Prefix::new(IpAddr::V6(address), 48)?;
        Self::from_genesis(v4, v6)
    }
    pub const fn ipv4_network(self) -> Prefix {
        self.ipv4_network
    }
    pub const fn ipv6_ula48(self) -> Prefix {
        self.ipv6_ula48
    }
}

/// RouteAuthority authorization scope is an explicit list of allowed CIDR pools.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteScope {
    pub allowed_pools: Vec<Prefix>,
}
/// Locally configured physical/management/outer endpoint routes that must not be covered.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ManagementRoutes {
    pub protected: Vec<Prefix>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenyReason {
    PrefixLengthOutOfRange,
    NonCanonicalHostBits,
    TooBroad,
    ReservedRange,
    ProtectedOverlay,
    NotPrivateOrUla,
    OutsideAuthorityScope,
    ManagementRouteOverlap,
    InvalidContext,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixClass {
    PrivateV4,
    UniqueLocalV6,
}

/// Classification context. Genesis network values cannot be conflated with default routes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifyContext {
    pub protected: ProtectedSet,
    pub authority_scope: RouteScope,
    pub management_routes: ManagementRoutes,
}

/// Strict five-step prefix classifier (syntax, width floor, special ranges, overlay,
/// then private/scope/local route policy). Pure: no system calls or mutable state.
pub fn classify_prefix(prefix: Prefix, ctx: &ClassifyContext) -> Result<PrefixClass, DenyReason> {
    // Step 1: recheck even though Prefix is normally constructed canonically.
    if !prefix.length_valid() {
        return Err(DenyReason::PrefixLengthOutOfRange);
    }
    if prefix.start() != prefix.address_value() {
        return Err(DenyReason::NonCanonicalHostBits);
    }
    // Step 2: reject default and overly broad prefixes, separately by family.
    if (prefix.is_ipv4() && prefix.length < 8) || (!prefix.is_ipv4() && prefix.length < 48) {
        return Err(DenyReason::TooBroad);
    }
    // Step 3: reject any overlap with special-use ranges (including unspecified).
    for range in special_ranges() {
        if let Some(reserved) = range.prefix() {
            if prefix.overlaps(reserved) {
                return Err(DenyReason::ReservedRange);
            }
        }
    }
    // Step 4: only the genesis overlay ranges are protected.
    if prefix.overlaps(ctx.protected.ipv4_network) || prefix.overlaps(ctx.protected.ipv6_ula48) {
        return Err(DenyReason::ProtectedOverlay);
    }
    // Step 5: private/ULA containment, issuer scope, then local management safety.
    let class = if prefix.is_ipv4() {
        let private = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
        if !private
            .iter()
            .filter_map(|s| parse_static(s))
            .any(|p| prefix.is_within(p))
        {
            return Err(DenyReason::NotPrivateOrUla);
        }
        PrefixClass::PrivateV4
    } else {
        let ula = Prefix::new(IpAddr::V6("fc00::".parse().expect("literal")), 7).expect("literal");
        if !prefix.is_within(ula) {
            return Err(DenyReason::NotPrivateOrUla);
        }
        PrefixClass::UniqueLocalV6
    };
    if !ctx
        .authority_scope
        .allowed_pools
        .iter()
        .any(|pool| prefix.is_within(*pool))
    {
        return Err(DenyReason::OutsideAuthorityScope);
    }
    if ctx
        .management_routes
        .protected
        .iter()
        .any(|route| prefix.overlaps(*route))
    {
        return Err(DenyReason::ManagementRouteOverlap);
    }
    Ok(class)
}
fn parse_static(s: &str) -> Option<Prefix> {
    let (a, l) = s.split_once('/')?;
    Prefix::new(a.parse().ok()?, l.parse().ok()?).ok()
}
fn special_ranges() -> [IpRange; 12] {
    [
        range4([0, 0, 0, 0], [0, 0, 0, 0]),
        range4([127, 0, 0, 0], [127, 255, 255, 255]),
        range4([169, 254, 0, 0], [169, 254, 255, 255]),
        range4([224, 0, 0, 0], [239, 255, 255, 255]),
        range4([192, 0, 2, 0], [192, 0, 2, 255]),
        range4([198, 51, 100, 0], [198, 51, 100, 255]),
        range4([203, 0, 113, 0], [203, 0, 113, 255]),
        range6("::", "::"),
        range6("::1", "::1"),
        range6("fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        range6("ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        range6("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
    ]
}
fn range4(a: [u8; 4], b: [u8; 4]) -> IpRange {
    IpRange {
        first: IpAddr::V4(Ipv4Addr::from(a)),
        last: IpAddr::V4(Ipv4Addr::from(b)),
    }
}
fn range6(a: &str, b: &str) -> IpRange {
    IpRange {
        first: IpAddr::V6(a.parse().expect("literal")),
        last: IpAddr::V6(b.parse().expect("literal")),
    }
}

/// Caller-verified route record. `object_id` is treated as a deterministic opaque digest;
/// this crate neither hashes raw bytes nor validates signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCandidate {
    pub issuer_id: String,
    pub subject_id: u16,
    pub prefix: Prefix,
    pub seq: u64,
    pub metric: u32,
    pub object_id: [u8; 32],
    pub ha_group: Option<String>,
    pub healthy_lease: bool,
    pub valid: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDisposition {
    Accepted,
    Standby,
    SuppressedBy([u8; 32]),
    RejectedEquivocation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    pub object_id: [u8; 32],
    pub disposition: RouteDisposition,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArbitrationError {
    InvalidHaGroupSize,
}

/// Deterministic route selection over caller-authenticated, already time/revocation-filtered
/// objects. Highest sequence compresses `(issuer, subject, prefix)` slots first; same-sequence
/// distinct payloads equivocate and are rejected. Exact-prefix HA groups have max two subjects.
pub fn arbitrate_routes(input: &[RouteCandidate]) -> Result<Vec<RouteDecision>, ArbitrationError> {
    // Group first, so equivocation handling is independent of delivery order. A poisoned
    // highest-seq slot is never resurrected by an additional competing object.
    let mut slot_keys: Vec<(String, u16, Prefix)> = input
        .iter()
        .filter(|c| c.valid)
        .map(|c| (c.issuer_id.clone(), c.subject_id, c.prefix))
        .collect();
    slot_keys.sort();
    slot_keys.dedup();
    let mut slots = Vec::new();
    let mut results = Vec::new();
    for (issuer, subject, prefix) in slot_keys {
        let candidates: Vec<&RouteCandidate> = input
            .iter()
            .filter(|c| {
                c.valid && c.issuer_id == issuer && c.subject_id == subject && c.prefix == prefix
            })
            .collect();
        let max_seq = candidates.iter().map(|c| c.seq).max().unwrap_or(0);
        let top: Vec<&RouteCandidate> = candidates
            .into_iter()
            .filter(|c| c.seq == max_seq)
            .collect();
        let ids: Vec<[u8; 32]> = top.iter().map(|c| c.object_id).collect();
        let unique_ids: Vec<[u8; 32]> = ids.iter().copied().fold(Vec::new(), |mut v, id| {
            if !v.contains(&id) {
                v.push(id)
            }
            v
        });
        if unique_ids.len() > 1 {
            for id in unique_ids {
                results.push(RouteDecision {
                    object_id: id,
                    disposition: RouteDisposition::RejectedEquivocation,
                });
            }
        } else if let Some(c) = top.first() {
            slots.push((*c).clone());
        }
    }
    // A group name is bound to exact prefix and issuer; inconsistent prefix assignment
    // for one explicit group is rejected rather than treated as independent HA groups.
    let mut group_names: Vec<(String, String, Vec<Prefix>, Vec<u16>)> = Vec::new();
    for c in &slots {
        if let Some(g) = &c.ha_group {
            if let Some(ix) = group_names
                .iter()
                .position(|x| x.0 == c.issuer_id && x.1 == *g)
            {
                if !group_names[ix].2.contains(&c.prefix) {
                    group_names[ix].2.push(c.prefix);
                }
                if !group_names[ix].3.contains(&c.subject_id) {
                    group_names[ix].3.push(c.subject_id);
                }
            } else {
                group_names.push((
                    c.issuer_id.clone(),
                    g.clone(),
                    vec![c.prefix],
                    vec![c.subject_id],
                ));
            }
        }
    }
    if group_names.iter().any(|g| g.2.len() > 1 || g.3.len() > 2) {
        return Err(ArbitrationError::InvalidHaGroupSize);
    }
    let mut standby_ids = Vec::new();
    let mut group_keys: Vec<(String, String, Prefix)> = slots
        .iter()
        .filter_map(|c| {
            c.ha_group
                .as_ref()
                .map(|g| (c.issuer_id.clone(), g.clone(), c.prefix))
        })
        .collect();
    group_keys.sort();
    group_keys.dedup();
    for (issuer, group, prefix) in group_keys {
        let mut healthy: Vec<&RouteCandidate> = slots
            .iter()
            .filter(|c| {
                c.issuer_id == issuer
                    && c.ha_group.as_ref() == Some(&group)
                    && c.prefix == prefix
                    && c.healthy_lease
            })
            .collect();
        healthy.sort_by_key(|c| (c.metric, c.subject_id, c.object_id));
        for c in healthy.iter().skip(1) {
            standby_ids.push(c.object_id);
        }
    }
    let mut eligible: Vec<RouteCandidate> = slots
        .into_iter()
        .filter(|c| c.healthy_lease && !standby_ids.contains(&c.object_id))
        .collect();
    eligible.sort_by_key(|c| (c.metric, c.issuer_id.clone(), c.subject_id, c.object_id));
    let mut accepted: Vec<(Prefix, [u8; 32])> = Vec::new();
    for c in eligible {
        if let Some((_, winner)) = accepted.iter().find(|(p, _)| p.overlaps(c.prefix)) {
            results.push(RouteDecision {
                object_id: c.object_id,
                disposition: RouteDisposition::SuppressedBy(*winner),
            });
        } else {
            accepted.push((c.prefix, c.object_id));
            results.push(RouteDecision {
                object_id: c.object_id,
                disposition: RouteDisposition::Accepted,
            });
        }
    }
    for id in standby_ids {
        results.push(RouteDecision {
            object_id: id,
            disposition: RouteDisposition::Standby,
        });
    }
    results.sort_by_key(|d| d.object_id);
    Ok(results)
}

/// Checked connection count arithmetic for §8.1. `H` is a global unauthenticated
/// count, supplied once; callers must not multiply it by listener count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionBudget {
    pub p: u64,
    pub a: u64,
    pub b: u64,
    pub d: u64,
    pub k: u64,
    pub m: u64,
    pub u: u64,
    pub h: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    InvalidRange,
    Overflow,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionCounts {
    pub steady: u64,
    pub peak: u64,
}
impl ConnectionBudget {
    pub fn calculate(self) -> Result<ConnectionCounts, BudgetError> {
        if self.k == 0 || self.k > 16 || self.d > 1 || self.a == 0 || self.m == 0 {
            return Err(BudgetError::InvalidRange);
        }
        let steady = self
            .p
            .checked_mul(self.a.checked_add(self.d).ok_or(BudgetError::Overflow)?)
            .and_then(|x| x.checked_add(self.b))
            .and_then(|x| {
                self.k
                    .checked_sub(1)
                    .and_then(|n| n.checked_mul(self.m))
                    .and_then(|v| x.checked_add(v))
            })
            .ok_or(BudgetError::Overflow)?;
        let peak = steady
            .checked_add(self.u)
            .and_then(|x| x.checked_add(self.h))
            .ok_or(BudgetError::Overflow)?;
        Ok(ConnectionCounts { steady, peak })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(s: &str) -> Prefix {
        let (a, l) = s.split_once('/').unwrap();
        Prefix::new(a.parse().unwrap(), l.parse().unwrap()).unwrap()
    }
    fn ctx(scope: Vec<Prefix>) -> ClassifyContext {
        ClassifyContext {
            protected: ProtectedSet::from_ula48("fd12:3456:789a::".parse().unwrap()).unwrap(),
            authority_scope: RouteScope {
                allowed_pools: scope,
            },
            management_routes: ManagementRoutes::default(),
        }
    }
    #[test]
    fn canonical_host_bits_and_boundaries() {
        assert_eq!(
            Prefix::new("192.168.1.5".parse().unwrap(), 24),
            Err(PrefixError::NonCanonicalHostBits)
        );
        assert_eq!(
            Prefix::new("0.0.0.0".parse().unwrap(), 33),
            Err(PrefixError::PrefixLengthOutOfRange)
        );
        assert_eq!(
            Prefix::new("::".parse().unwrap(), 129),
            Err(PrefixError::PrefixLengthOutOfRange)
        );
        assert_eq!(
            Prefix::new("::".parse().unwrap(), 0).unwrap().end(),
            u128::MAX
        );
    }
    #[test]
    fn classifier_five_steps_and_overlap_both_directions() {
        let c = ctx(vec![
            p("10.0.0.0/8"),
            p("172.16.0.0/12"),
            p("192.168.0.0/16"),
            p("fc00::/7"),
        ]);
        assert_eq!(
            classify_prefix(p("192.168.1.0/24"), &c),
            Ok(PrefixClass::PrivateV4)
        );
        assert_eq!(
            classify_prefix(p("10.20.3.0/24"), &c),
            Err(DenyReason::ProtectedOverlay)
        );
        assert_eq!(
            classify_prefix(p("10.16.0.0/12"), &c),
            Err(DenyReason::ProtectedOverlay)
        );
        assert_eq!(
            classify_prefix(p("10.0.0.0/7"), &c),
            Err(DenyReason::TooBroad)
        );
        assert_eq!(
            classify_prefix(p("0.0.0.0/0"), &c),
            Err(DenyReason::TooBroad)
        );
        assert_eq!(
            classify_prefix(p("169.254.0.0/16"), &c),
            Err(DenyReason::ReservedRange)
        );
        assert_eq!(
            classify_prefix(p("172.16.0.0/12"), &c),
            Ok(PrefixClass::PrivateV4)
        );
        assert_eq!(
            classify_prefix(p("fd12:3456:789a::/48"), &c),
            Err(DenyReason::ProtectedOverlay)
        );
        assert_eq!(
            classify_prefix(p("fc00::/8"), &c),
            Err(DenyReason::TooBroad)
        );
        assert_eq!(
            classify_prefix(p("fc00:1::/48"), &c),
            Ok(PrefixClass::UniqueLocalV6)
        );
    }
    #[test]
    fn special_boundaries_and_mgmt_overlap() {
        let mut c = ctx(vec![p("192.168.0.0/16")]);
        for s in [
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "127.0.0.0/8",
            "224.0.0.0/4",
            "::/128",
            "::1/128",
            "fe80::/10",
        ] {
            assert_eq!(classify_prefix(p(s), &c), Err(DenyReason::ReservedRange));
        }
        assert_eq!(
            classify_prefix(p("2001:db8::/32"), &c),
            Err(DenyReason::TooBroad)
        );
        assert_eq!(
            classify_prefix(p("2001:db8:1::/48"), &c),
            Err(DenyReason::ReservedRange)
        );
        c.management_routes.protected.push(p("192.168.1.0/24"));
        assert_eq!(
            classify_prefix(p("192.168.0.0/16"), &c),
            Err(DenyReason::ManagementRouteOverlap)
        );
        assert_eq!(
            classify_prefix(p("192.168.2.0/24"), &c),
            Ok(PrefixClass::PrivateV4)
        );
    }
    fn candidate(id: u8, sub: u16, net: &str, metric: u32) -> RouteCandidate {
        RouteCandidate {
            issuer_id: "ra".into(),
            subject_id: sub,
            prefix: p(net),
            seq: 1,
            metric,
            object_id: [id; 32],
            ha_group: None,
            healthy_lease: true,
            valid: true,
        }
    }
    #[test]
    fn greedy_chain_keeps_c_after_b_suppressed() {
        let a = candidate(1, 1, "10.0.0.0/24", 1);
        let b = candidate(2, 2, "10.0.0.0/23", 2);
        let c = candidate(3, 3, "10.0.1.0/24", 3);
        let d = arbitrate_routes(&[a, b, c]).unwrap();
        assert!(d.contains(&RouteDecision {
            object_id: [1; 32],
            disposition: RouteDisposition::Accepted
        }));
        assert!(d.contains(&RouteDecision {
            object_id: [2; 32],
            disposition: RouteDisposition::SuppressedBy([1; 32])
        }));
        assert!(d.contains(&RouteDecision {
            object_id: [3; 32],
            disposition: RouteDisposition::Accepted
        }));
    }
    #[test]
    fn sequence_ha_and_order_converge() {
        let mut old = candidate(1, 1, "10.1.0.0/24", 9);
        old.seq = 1;
        let mut new = candidate(2, 1, "10.1.0.0/24", 5);
        new.seq = 2;
        let mut ha = candidate(3, 2, "10.1.0.0/24", 1);
        ha.ha_group = Some("g".into());
        ha.metric = 4;
        new.ha_group = Some("g".into());
        new.metric = 3;
        let x = arbitrate_routes(&[old.clone(), new.clone(), ha.clone()]).unwrap();
        let y = arbitrate_routes(&[ha, new, old]).unwrap();
        assert_eq!(x, y);
        assert!(
            x.iter()
                .any(|r| r.object_id == [3; 32] && r.disposition == RouteDisposition::Standby)
        );
    }
    #[test]
    fn same_seq_equivocation_and_ha_limit() {
        let a = candidate(1, 1, "10.2.0.0/24", 1);
        let mut b = a.clone();
        b.object_id = [2; 32];
        let d = arbitrate_routes(&[a, b]).unwrap();
        assert!(
            d.iter()
                .all(|r| r.disposition == RouteDisposition::RejectedEquivocation)
        );
        let mut v = vec![];
        for (id, s) in [(1, 1), (2, 2), (3, 3)] {
            let mut c = candidate(id, s, "10.3.0.0/24", 1);
            c.ha_group = Some("ha".into());
            v.push(c)
        }
        assert_eq!(
            arbitrate_routes(&v),
            Err(ArbitrationError::InvalidHaGroupSize)
        );
    }
    #[test]
    fn budgets_checked_and_example() {
        let b = ConnectionBudget {
            p: 16,
            a: 8,
            d: 1,
            b: 16,
            k: 8,
            m: 5,
            u: 0,
            h: 0,
        };
        assert_eq!(
            b.calculate(),
            Ok(ConnectionCounts {
                steady: 195,
                peak: 195
            })
        );
        assert_eq!(
            ConnectionBudget {
                p: u64::MAX,
                a: 2,
                d: 0,
                b: 0,
                k: 1,
                m: 1,
                u: 0,
                h: 0
            }
            .calculate(),
            Err(BudgetError::Overflow)
        );
        assert_eq!(
            ConnectionBudget {
                p: 0,
                a: 0,
                d: 2,
                b: 0,
                k: 1,
                m: 0,
                u: 0,
                h: 0
            }
            .calculate(),
            Err(BudgetError::InvalidRange)
        );
    }
    #[test]
    fn exhaustive_small_masks_no_overflow() {
        for len in 0..=32 {
            let addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            let net = Prefix::new(addr, len).unwrap();
            assert!(net.start() <= net.end());
        }
        for len in 0..=128 {
            let net = Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), len).unwrap();
            assert!(net.start() <= net.end());
        }
    }
}
