//! Route-install self-check for §9.3 (subnet gateway, host protection).
//!
//! Classifies a caller-supplied snapshot. This module does not run `iptables`,
//! `nft`, `sysctl -w`, or `ip route`, and it does not emit those commands.
//! [`AuditOk`] is an observation only. This slice does not implement `G-PREFIX`
//! (public prefixes, scope, property tests) or `G-TUN`.

use std::net::{IpAddr, Ipv4Addr};

/// Management plane reserved by the plan: `10.20.0.0/16`.
const MANAGEMENT_V4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 0);
const MANAGEMENT_V4_LEN: u8 = 16;

/// `rp_filter` observed on the tunnel interface. `Loose` and `Off` are reported
/// on success; `Strict` is a refusal when a requested prefix is present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpFilter {
    Off,
    Strict,
    Loose,
}

/// One route from the caller's table snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub dev: String,
    pub gateway_present: bool,
}

/// A prefix the node would install. The caller claims it was already validated;
/// this audit re-checks host bits and prefix length anyway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestedPrefix {
    pub destination: IpAddr,
    pub prefix_len: u8,
}

/// Immutable view of host routing state. The audit never writes through it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSnapshot {
    pub ip_forward_v4: bool,
    pub ip_forward_v6: bool,
    pub rp_filter: RpFilter,
    pub routes: Vec<RouteEntry>,
    pub tun_dev: String,
    pub requested_prefixes: Vec<RequestedPrefix>,
    pub accept_routes: bool,
    pub enable_subnet: bool,
}

/// First failure, in the §9.3 decision order. Not a list of every problem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefuseReason {
    /// `enable_subnet` or `accept_routes` is off. Routes are not consulted.
    Disabled,
    /// `0.0.0.0/0`, `::/0`, or any `prefix_len == 0`.
    DefaultRoute,
    /// Requested prefix contains, is contained by, or equals `10.20.0.0/16`.
    ManagementOverlap,
    /// Host bits are set, or `prefix_len` is outside the family range.
    HostBits,
    /// Forwarding is off for the address family of a requested prefix.
    ForwardingOff,
    /// Strict reverse-path filtering while a requested prefix is present.
    StrictRpFilter,
    /// No route whose destination equals the prefix and whose `dev` is `tun_dev`.
    /// A default route does not cover it.
    MissingReturnRoute,
}

/// Accept result. Deliberately has no command list and no install plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditOk {
    /// Observed `rp_filter`. `Loose` and `Off` are reported, not failed.
    pub rp_filter: RpFilter,
}

/// Fail-closed classification of `snapshot`. Does not mutate the snapshot.
pub fn audit_route_install(snapshot: &RouteSnapshot) -> Result<AuditOk, RefuseReason> {
    if !snapshot.enable_subnet || !snapshot.accept_routes {
        return Err(RefuseReason::Disabled);
    }
    // Category order is global, not per-prefix: an earlier reason on any prefix
    // beats a later reason on another prefix.
    if snapshot.requested_prefixes.iter().any(is_default) {
        return Err(RefuseReason::DefaultRoute);
    }
    if snapshot.requested_prefixes.iter().any(overlaps_management) {
        return Err(RefuseReason::ManagementOverlap);
    }
    if snapshot
        .requested_prefixes
        .iter()
        .any(|prefix| !canonical(prefix))
    {
        return Err(RefuseReason::HostBits);
    }
    if snapshot
        .requested_prefixes
        .iter()
        .any(|prefix| forwarding_off(snapshot, prefix.destination))
    {
        return Err(RefuseReason::ForwardingOff);
    }
    if !snapshot.requested_prefixes.is_empty() && snapshot.rp_filter == RpFilter::Strict {
        return Err(RefuseReason::StrictRpFilter);
    }
    if snapshot
        .requested_prefixes
        .iter()
        .any(|prefix| !has_return_route(snapshot, prefix))
    {
        return Err(RefuseReason::MissingReturnRoute);
    }
    Ok(AuditOk {
        rp_filter: snapshot.rp_filter,
    })
}

/// `0.0.0.0/0`, `::/0`, and any other `prefix_len == 0`.
fn is_default(prefix: &RequestedPrefix) -> bool {
    prefix.prefix_len == 0
}

fn overlaps_management(prefix: &RequestedPrefix) -> bool {
    let IpAddr::V4(addr) = prefix.destination else {
        return false;
    };
    if prefix.prefix_len > 32 {
        return false;
    }
    let shorter = prefix.prefix_len.min(MANAGEMENT_V4_LEN);
    same_prefix_bits(u32::from(addr), u32::from(MANAGEMENT_V4), shorter)
}

fn canonical(prefix: &RequestedPrefix) -> bool {
    match prefix.destination {
        IpAddr::V4(addr) => host_bits_clear_v4(u32::from(addr), prefix.prefix_len),
        IpAddr::V6(addr) => host_bits_clear_v6(u128::from(addr), prefix.prefix_len),
    }
}

fn host_bits_clear_v4(addr: u32, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    let host = host_mask_v4(prefix_len);
    addr & host == 0
}

fn host_bits_clear_v6(addr: u128, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    let host = host_mask_v6(prefix_len);
    addr & host == 0
}

fn host_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len >= 32 {
        0
    } else {
        u32::MAX >> prefix_len
    }
}

fn host_mask_v6(prefix_len: u8) -> u128 {
    if prefix_len >= 128 {
        0
    } else {
        u128::MAX >> prefix_len
    }
}

/// First `len` bits equal. `len == 0` is containment by a default prefix.
fn same_prefix_bits(left: u32, right: u32, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    if len >= 32 {
        return left == right;
    }
    let shift = 32 - u32::from(len);
    (left >> shift) == (right >> shift)
}

fn forwarding_off(snapshot: &RouteSnapshot, destination: IpAddr) -> bool {
    match destination {
        IpAddr::V4(_) => !snapshot.ip_forward_v4,
        IpAddr::V6(_) => !snapshot.ip_forward_v6,
    }
}

fn has_return_route(snapshot: &RouteSnapshot, prefix: &RequestedPrefix) -> bool {
    snapshot.routes.iter().any(|route| {
        route.destination == prefix.destination
            && route.prefix_len == prefix.prefix_len
            && route.dev == snapshot.tun_dev
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AuditOk, RefuseReason, RequestedPrefix, RouteEntry, RouteSnapshot, RpFilter,
        audit_route_install,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn prefix(destination: IpAddr, prefix_len: u8) -> RequestedPrefix {
        RequestedPrefix {
            destination,
            prefix_len,
        }
    }

    fn route(destination: IpAddr, prefix_len: u8, dev: &str) -> RouteEntry {
        RouteEntry {
            destination,
            prefix_len,
            dev: dev.to_owned(),
            gateway_present: false,
        }
    }

    fn snapshot(prefixes: Vec<RequestedPrefix>, routes: Vec<RouteEntry>) -> RouteSnapshot {
        RouteSnapshot {
            ip_forward_v4: true,
            ip_forward_v6: true,
            rp_filter: RpFilter::Loose,
            routes,
            tun_dev: "tun0".to_owned(),
            requested_prefixes: prefixes,
            accept_routes: true,
            enable_subnet: true,
        }
    }

    fn lan() -> RequestedPrefix {
        prefix(v4(192, 168, 10, 0), 24)
    }

    #[test]
    fn accept_v4_24_on_tun0() {
        let snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "tun0")]);
        assert_eq!(
            audit_route_install(&snap),
            Ok(AuditOk {
                rp_filter: RpFilter::Loose,
            })
        );
    }

    #[test]
    fn accept_reports_rp_filter_off() {
        let mut snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "tun0")]);
        snap.rp_filter = RpFilter::Off;
        assert_eq!(
            audit_route_install(&snap),
            Ok(AuditOk {
                rp_filter: RpFilter::Off,
            })
        );
    }

    #[test]
    fn accept_v6_when_only_v6_forwarding_is_required() {
        let dest = IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 0));
        let mut snap = snapshot(vec![prefix(dest, 64)], vec![route(dest, 64, "tun0")]);
        snap.ip_forward_v4 = false;
        assert_eq!(
            audit_route_install(&snap),
            Ok(AuditOk {
                rp_filter: RpFilter::Loose,
            })
        );
    }

    #[test]
    fn disabled_when_subnet_off() {
        let mut snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "tun0")]);
        snap.enable_subnet = false;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::Disabled));
    }

    #[test]
    fn disabled_when_accept_routes_off() {
        let mut snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "tun0")]);
        snap.accept_routes = false;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::Disabled));
    }

    #[test]
    fn disabled_beats_forwarding_off_and_default_prefix() {
        let mut snap = snapshot(
            vec![prefix(v4(0, 0, 0, 0), 0)],
            vec![route(v4(0, 0, 0, 0), 0, "eth0")],
        );
        snap.enable_subnet = false;
        snap.accept_routes = false;
        snap.ip_forward_v4 = false;
        snap.ip_forward_v6 = false;
        snap.rp_filter = RpFilter::Strict;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::Disabled));
    }

    #[test]
    fn refuse_ipv4_default() {
        let snap = snapshot(vec![prefix(v4(0, 0, 0, 0), 0)], vec![]);
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::DefaultRoute));
    }

    #[test]
    fn refuse_ipv6_default() {
        let snap = snapshot(vec![prefix(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)], vec![]);
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::DefaultRoute));
    }

    #[test]
    fn refuse_prefix_len_zero_even_if_address_is_not_unspecified() {
        let snap = snapshot(vec![prefix(v4(192, 168, 10, 0), 0)], vec![]);
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::DefaultRoute));
    }

    #[test]
    fn default_beats_later_problems() {
        let snap = snapshot(vec![lan(), prefix(v4(0, 0, 0, 0), 0)], vec![]);
        let mut snap = snap;
        snap.ip_forward_v4 = false;
        snap.rp_filter = RpFilter::Strict;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::DefaultRoute));
    }

    #[test]
    fn refuse_management_equal() {
        let snap = snapshot(vec![prefix(v4(10, 20, 0, 0), 16)], vec![]);
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::ManagementOverlap)
        );
    }

    #[test]
    fn refuse_management_subnet() {
        let snap = snapshot(vec![prefix(v4(10, 20, 1, 0), 24)], vec![]);
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::ManagementOverlap)
        );
    }

    #[test]
    fn refuse_management_superset() {
        let snap = snapshot(vec![prefix(v4(10, 0, 0, 0), 8)], vec![]);
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::ManagementOverlap)
        );
    }

    #[test]
    fn management_overlap_beats_host_bits() {
        let snap = snapshot(vec![prefix(v4(10, 20, 0, 1), 24)], vec![]);
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::ManagementOverlap)
        );
    }

    #[test]
    fn ipv6_does_not_overlap_ipv4_management() {
        let dest = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x20, 0, 0, 0, 0, 0, 0));
        let snap = snapshot(vec![prefix(dest, 48)], vec![route(dest, 48, "tun0")]);
        assert!(audit_route_install(&snap).is_ok());
    }

    #[test]
    fn refuse_host_bits() {
        let snap = snapshot(vec![prefix(v4(192, 168, 1, 1), 24)], vec![]);
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::HostBits));
    }

    #[test]
    fn refuse_prefix_len_out_of_range() {
        let snap = snapshot(vec![prefix(v4(192, 168, 10, 0), 33)], vec![]);
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::HostBits));
        let dest = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let snap = snapshot(vec![prefix(dest, 129)], vec![]);
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::HostBits));
    }

    #[test]
    fn host_bits_beat_forwarding_and_return_route() {
        let mut snap = snapshot(vec![prefix(v4(192, 168, 1, 1), 24)], vec![]);
        snap.ip_forward_v4 = false;
        snap.rp_filter = RpFilter::Strict;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::HostBits));
    }

    #[test]
    fn refuse_v4_forwarding_off() {
        let mut snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "tun0")]);
        snap.ip_forward_v4 = false;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::ForwardingOff));
    }

    #[test]
    fn refuse_v6_forwarding_off() {
        let dest = IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 0));
        let mut snap = snapshot(vec![prefix(dest, 64)], vec![route(dest, 64, "tun0")]);
        snap.ip_forward_v6 = false;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::ForwardingOff));
    }

    #[test]
    fn forwarding_off_beats_strict_rp_filter() {
        let mut snap = snapshot(vec![lan()], vec![]);
        snap.ip_forward_v4 = false;
        snap.rp_filter = RpFilter::Strict;
        assert_eq!(audit_route_install(&snap), Err(RefuseReason::ForwardingOff));
    }

    #[test]
    fn refuse_strict_rp_filter() {
        let mut snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "tun0")]);
        snap.rp_filter = RpFilter::Strict;
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::StrictRpFilter)
        );
    }

    #[test]
    fn strict_without_requested_prefixes_is_reported() {
        let mut snap = snapshot(vec![], vec![]);
        snap.rp_filter = RpFilter::Strict;
        assert_eq!(
            audit_route_install(&snap),
            Ok(AuditOk {
                rp_filter: RpFilter::Strict,
            })
        );
    }

    #[test]
    fn refuse_return_route_on_other_dev() {
        let snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "eth0")]);
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::MissingReturnRoute)
        );
    }

    #[test]
    fn default_route_does_not_satisfy_return_route() {
        let snap = snapshot(vec![lan()], vec![route(v4(0, 0, 0, 0), 0, "tun0")]);
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::MissingReturnRoute)
        );
    }

    #[test]
    fn longer_or_shorter_prefix_on_tun_is_not_the_return_route() {
        let snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 16, "tun0")]);
        assert_eq!(
            audit_route_install(&snap),
            Err(RefuseReason::MissingReturnRoute)
        );
    }

    #[test]
    fn gateway_on_matching_tun_route_still_counts() {
        let mut entry = route(v4(192, 168, 10, 0), 24, "tun0");
        entry.gateway_present = true;
        let snap = snapshot(vec![lan()], vec![entry]);
        assert!(audit_route_install(&snap).is_ok());
    }

    #[test]
    fn snapshot_is_not_mutated() {
        let snap = snapshot(vec![lan()], vec![route(v4(192, 168, 10, 0), 24, "eth0")]);
        let before = snap.clone();
        let _ = audit_route_install(&snap);
        assert_eq!(snap, before);
    }
}
