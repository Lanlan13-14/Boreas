//! Outer bootstrap-resolver admission, before the overlay is up.
//!
//! Master plan §9.4 allows only a static address, DNS-over-TCP, DNS-over-TLS,
//! or DNS-over-HTTPS-over-TCP for the outer name bootstrap. This module does
//! not resolve names, open sockets, or send queries. The caller supplies a
//! literal resolver address it already holds. UDP is refused, and so is any
//! transport that would consult the overlay this path is trying to start.
//! There is no fallback transport: a rejected configuration is not retried as
//! UDP or as anything else.

use std::fmt;
use std::net::IpAddr;

/// How an outer bootstrap resolver would be reached.
///
/// Only the first four variants may be used before the overlay is up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapTransport {
    /// A literal address already known to the caller. No lookup is performed.
    StaticIp,
    /// Classic DNS carried on TCP, addressed by a literal IP.
    DnsOverTcp,
    /// DNS-over-TLS, addressed by a literal IP with a separate certificate name.
    DnsOverTls,
    /// DNS-over-HTTPS carried on TCP, likewise addressed by a literal IP.
    DnsOverHttpsOverTcp,
    /// UDP DNS. The outer bootstrap is TCP-based or a static address, so this
    /// is never an allowed bootstrap transport.
    Udp,
    /// A resolver that would be reached through the overlay. Using it before
    /// the overlay is up is a dependency cycle.
    Overlay,
}

/// Why a bootstrap configuration must not be used before the overlay is up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootError {
    /// UDP, or any other transport outside the four plan-allowed kinds.
    TransportNotAllowed,
    /// The address is unspecified (`0.0.0.0` / `::`) or multicast, so it is
    /// not a literal unicast resolver the caller already resolved.
    ResolverAddressRejected,
    /// DoT or DoH-over-TCP was configured without a certificate name.
    CertificateNameEmpty,
    /// The certificate name is the IP's own display form. The plan requires
    /// the bootstrap IP and the certificate name to be configured separately.
    CertificateNameEqualsIp,
    /// The caller did not assert that the certificate name is distinct from
    /// the resolver IP.
    NameNotDistinctFromIp,
    /// The transport is the overlay itself. Rejected even when every other
    /// field would otherwise be acceptable.
    DependsOnOverlay,
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TransportNotAllowed => "bootstrap transport is not allowed before overlay is up",
            Self::ResolverAddressRejected => {
                "bootstrap resolver address is unspecified or multicast"
            }
            Self::CertificateNameEmpty => "bootstrap certificate name is empty",
            Self::CertificateNameEqualsIp => {
                "bootstrap certificate name must not equal the resolver IP"
            }
            Self::NameNotDistinctFromIp => {
                "bootstrap certificate name is not marked distinct from the resolver IP"
            }
            Self::DependsOnOverlay => "bootstrap resolver depends on the overlay it would start",
        })
    }
}

impl std::error::Error for BootError {}

/// A caller-supplied outer bootstrap resolver.
///
/// `resolver_ip` is a literal address. Nothing in this module accepts a
/// hostname or resolves one. `certificate_name` is the TLS name for DoT and
/// DoH-over-TCP and is kept separate from that address. `StaticIp` and
/// `DnsOverTcp` may leave it empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapConfig {
    pub transport: BootstrapTransport,
    pub resolver_ip: IpAddr,
    pub certificate_name: String,
    pub name_is_distinct_from_ip: bool,
}

/// True only for the four transports the outer bootstrap may use.
pub fn transport_allowed(transport: BootstrapTransport) -> bool {
    matches!(
        transport,
        BootstrapTransport::StaticIp
            | BootstrapTransport::DnsOverTcp
            | BootstrapTransport::DnsOverTls
            | BootstrapTransport::DnsOverHttpsOverTcp
    )
}

/// Admit a configuration for use before the overlay is up.
///
/// Overlay is rejected first, as [`BootError::DependsOnOverlay`], even when
/// the address and certificate fields would otherwise pass. No other transport
/// is substituted when this returns an error.
pub fn validate(cfg: &BootstrapConfig) -> Result<(), BootError> {
    if cfg.transport == BootstrapTransport::Overlay {
        return Err(BootError::DependsOnOverlay);
    }
    if !transport_allowed(cfg.transport) {
        return Err(BootError::TransportNotAllowed);
    }
    if !literal_unicast(cfg.resolver_ip) {
        return Err(BootError::ResolverAddressRejected);
    }
    if needs_certificate_name(cfg.transport) {
        if cfg.certificate_name.is_empty() {
            return Err(BootError::CertificateNameEmpty);
        }
        if cfg.certificate_name == cfg.resolver_ip.to_string() {
            return Err(BootError::CertificateNameEqualsIp);
        }
        if !cfg.name_is_distinct_from_ip {
            return Err(BootError::NameNotDistinctFromIp);
        }
    }
    Ok(())
}

/// Whether this configuration may be queried before the overlay is up.
///
/// Equivalent to `validate(cfg).is_ok()`. A failure is not permission to try
/// UDP, and this function does not select a fallback transport.
pub fn may_query_before_overlay_up(cfg: &BootstrapConfig) -> bool {
    validate(cfg).is_ok()
}

fn needs_certificate_name(transport: BootstrapTransport) -> bool {
    matches!(
        transport,
        BootstrapTransport::DnsOverTls | BootstrapTransport::DnsOverHttpsOverTcp
    )
}

fn literal_unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{
        BootError, BootstrapConfig, BootstrapTransport, may_query_before_overlay_up,
        transport_allowed, validate,
    };

    fn unicast_v4() -> std::net::IpAddr {
        std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))
    }

    fn unicast_v6() -> std::net::IpAddr {
        std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53))
    }

    fn cfg(
        transport: BootstrapTransport,
        ip: std::net::IpAddr,
        name: &str,
        distinct: bool,
    ) -> BootstrapConfig {
        BootstrapConfig {
            transport,
            resolver_ip: ip,
            certificate_name: name.to_string(),
            name_is_distinct_from_ip: distinct,
        }
    }

    #[test]
    fn allowed_transports_with_unicast_ip_pass() {
        let cases = [
            (BootstrapTransport::StaticIp, unicast_v4(), "", false),
            (BootstrapTransport::DnsOverTcp, unicast_v6(), "", false),
            (
                BootstrapTransport::DnsOverTls,
                unicast_v4(),
                "dns.example",
                true,
            ),
            (
                BootstrapTransport::DnsOverHttpsOverTcp,
                unicast_v6(),
                "doh.example",
                true,
            ),
        ];
        for (transport, ip, name, distinct) in cases {
            assert!(transport_allowed(transport));
            let config = cfg(transport, ip, name, distinct);
            assert_eq!(validate(&config), Ok(()));
        }
    }

    #[test]
    fn udp_and_overlay_are_rejected() {
        assert!(!transport_allowed(BootstrapTransport::Udp));
        assert!(!transport_allowed(BootstrapTransport::Overlay));
        let udp = cfg(BootstrapTransport::Udp, unicast_v4(), "", false);
        assert_eq!(validate(&udp), Err(BootError::TransportNotAllowed));
        let overlay = cfg(
            BootstrapTransport::Overlay,
            unicast_v4(),
            "dns.example",
            true,
        );
        assert_eq!(validate(&overlay), Err(BootError::DependsOnOverlay));
    }

    #[test]
    fn unspecified_and_multicast_addresses_are_rejected() {
        let bad = [
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            std::net::IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            std::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
        ];
        for ip in bad {
            let config = cfg(BootstrapTransport::DnsOverTcp, ip, "", false);
            assert_eq!(validate(&config), Err(BootError::ResolverAddressRejected));
        }
    }

    #[test]
    fn dot_rejects_empty_name_and_name_equal_to_ip_text() {
        let empty = cfg(BootstrapTransport::DnsOverTls, unicast_v4(), "", true);
        assert_eq!(validate(&empty), Err(BootError::CertificateNameEmpty));
        let ip = unicast_v4();
        let same = cfg(
            BootstrapTransport::DnsOverTls,
            ip,
            &ip.to_string(),
            true,
        );
        assert_eq!(validate(&same), Err(BootError::CertificateNameEqualsIp));
    }

    #[test]
    fn may_query_before_overlay_up_follows_validate() {
        let rejects = [
            cfg(BootstrapTransport::Udp, unicast_v4(), "", false),
            cfg(
                BootstrapTransport::Overlay,
                unicast_v4(),
                "dns.example",
                true,
            ),
            cfg(
                BootstrapTransport::DnsOverTcp,
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                "",
                false,
            ),
            cfg(
                BootstrapTransport::DnsOverTcp,
                std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                "",
                false,
            ),
            cfg(
                BootstrapTransport::StaticIp,
                std::net::IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                "",
                false,
            ),
            cfg(
                BootstrapTransport::StaticIp,
                std::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
                "",
                false,
            ),
            cfg(BootstrapTransport::DnsOverTls, unicast_v4(), "", true),
            cfg(
                BootstrapTransport::DnsOverTls,
                unicast_v4(),
                &unicast_v4().to_string(),
                true,
            ),
        ];
        for config in &rejects {
            assert!(!may_query_before_overlay_up(config));
            assert!(validate(config).is_err());
        }
        let ok = cfg(
            BootstrapTransport::DnsOverTls,
            unicast_v4(),
            "dns.example",
            true,
        );
        assert!(may_query_before_overlay_up(&ok));
    }
}
