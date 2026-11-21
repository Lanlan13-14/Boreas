//! Bounded authoritative UDP DNS responder over one [`PacketIo`] endpoint.
//!
//! # What this slice is
//!
//! A packet-level bridge for one dedicated endpoint: it reads complete
//! IPv4/UDP/DNS datagrams from a [`PacketIo`] queue, validates them, asks
//! [`boreas_dns::AuthoritativeDns`] for an authoritative answer built from a
//! *verified* signed zone, constructs the reply datagram (IPv4 header checksum
//! and UDP checksum are computed), and writes it back to the same endpoint.
//! Nothing is synthesized from a socket and no operating-system UDP socket
//! exists.
//!
//! # What this is not
//!
//! * **Not a daemon and not a complete DNS service.** No process owns this
//!   type, no port is bound, and no CLI/daemon path constructs it. It is one
//!   in-process responder behind an existing packet endpoint, not a system DNS
//!   server.
//! * **Not TCP DNS.** `TCP:53` to the DNS VIP is classified and refused without
//!   any response. Real DNS-over-TCP must be driven by
//!   `boreas_dns::tcp::TcpDnsServer` over a real `smoltcp::iface::Interface` and
//!   `Device` that owns the DNS VIP; no such device/interface is wired here, so
//!   the daemon capability `dns_tcp` stays `false`. This module never fabricates
//!   TCP segments.
//! * **Not IPv6.** IPv6 packets (including the reserved `dns_vip6`) are ignored.
//!   The verified policy has an IPv4 overlay prefix and no ULA, so no IPv6 VIP or
//!   `AAAA` record can be authorized. IPv6 is therefore off by default and has no
//!   enable switch here: `AAAA` queries for an existing owner get NODATA, never
//!   an unverified address.
//! * **Not a recursive/forwarding resolver.** No recursion, forwarding, EDNS
//!   padding, negative SOA, DNSSEC validation or cache is implemented.
//! * **Not durable authorization.** No anti-replay watermark, revocation feed,
//!   generation change or trusted-clock service is implemented. `now` is supplied
//!   by the caller on every operation and is not rollback-protected.
//!
//! # Where the authority and the source come from
//!
//! [`DnsUdpRuntime::try_new`] accepts only:
//!
//! * a [`VerifiedDnsAuthority`] — private fields, produced by
//!   `boreas-pki` only after a NetworkRoot-authorized DNS signer's Ed25519 **and**
//!   ML-DSA-65 signatures verified over the exact zone/VIP/record TBS, bound to
//!   one exact `NetworkPolicy` digest;
//! * the authenticated local [`PeerIdentity`] of the hop session — its policy
//!   context must carry the same digest; its permanent VIP is re-derived with the
//!   packet path's slot rule.
//!
//! The query source is not taken from the packet: an inbound datagram is answered
//! only when its IPv4 source equals the local endpoint's derived permanent VIP.
//! A packet claiming another source is counted and dropped. No caller-supplied
//! "authorized" boolean, address list or policy digest can enter this type.
//! No private key is passed to, stored in or copied by this runtime; the verified
//! token contains public authorization data only.
//!
//! # Time and bounded work
//!
//! Two clocks are explicit and separate:
//!
//! * **Freshness**: `poll_once` and `handle_packet` take the caller's UTC
//!   `now` and refuse to answer or write when the token's freshness window
//!   (authority ∩ signer grant ∩ policy) has ended; `poll_once` also refuses to
//!   read. This is a static interval check, not a trusted-clock service: UTC can
//!   roll back, no durable watermark is consulted, and the caller is responsible
//!   for its clock source.
//! * **Rate limiting**: the same operations take a monotonic [`Instant`] used
//!   only for the fixed-window query budget. It is never derived from UTC, so a
//!   UTC adjustment cannot refill the budget. The caller must supply a value from
//!   a monotonic clock belonging to the same process.
//!
//! The freshness window is re-checked per operation; it is not a one-time bind
//! check. Work is bounded per packet: one datagram in, at most one datagram out,
//! at most the negotiated MTU. Answers are additionally capped by a
//! fixed-capacity, fixed-state per-window budget (no map, no unbounded queue, no
//! allocation for limiter state). One endpoint is read per call and non-DNS
//! packets are consumed, not forwarded; the endpoint must be a DNS-dedicated
//! queue or the owner must demultiplex before calling this type.
//!
//! * The source rule is the *local* permanent VIP. LAN clients behind a node do
//!   not match it and receive no answer; authorizing them needs a separately
//!   authenticated source mapping, which does not exist in this slice.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use boreas_crypto::NodeRole;
use boreas_dns::{
    AuthoritativeDns, DnsError, MAX_QUERY_BYTES, MAX_RESPONSE_BYTES, SourceAuthorization, Zone,
};
use boreas_pki::dns_authority::VerifiedDnsAuthority;
use boreas_tun::{Error as TunError, IpVersion, PacketIo, inspect_packet};

use crate::packet_path::{MAX_MTU, MIN_MTU};
use crate::tls::PeerIdentity;

/// Authoritative DNS port. The reserved VIP is `overlay.0.53`.
pub const DNS_PORT: u16 = 53;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const DATAGRAM_OVERHEAD: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN;
const UDP_PROTOCOL: u8 = 17;
const TCP_PROTOCOL: u8 = 6;
/// 12-byte IPv4/UDP pseudo header plus the largest UDP payload this link can
/// carry. Used for one bounded stack buffer per packet.
const MAX_PSEUDO_SUM_LEN: usize = 12 + MAX_MTU;
const ZERO_CHECKSUM: u16 = 0;
/// Fixed query budget per one-second window. This is a coarse local abuse bound,
/// not a traffic-shaping or per-client policy: the only accepted source is the
/// authenticated local VIP, and limiter state is one `Option<Instant>` plus one
/// `u32`.
const RATE_LIMIT_MAX_PER_WINDOW: u32 = 128;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);

/// Why a runtime could not be bound to an authority and identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The local identity came from the legacy/non-policy session path.
    UnboundIdentity,
    /// The local identity lacks a network, node id or generation.
    InvalidIdentity,
    /// The identity's `(node_id, role)` is not a canonical permanent slot.
    InvalidPermanentSlot,
    /// The authority, the policy context and the identity do not share one
    /// network and one exact policy digest.
    AuthorityMismatch,
    /// The verified authority cannot be expressed as a bounded zone.
    InvalidAuthority,
    /// The authority carries an IPv6 VIP or `AAAA` record, but the verified
    /// policy has no ULA to bind it to. IPv6 is disabled by default.
    UnsupportedIpv6,
    /// The link MTU is outside `MIN_MTU..=MAX_MTU`.
    MtuOutOfRange,
    /// The caller-supplied UTC time is outside the policy validity window.
    ExpiredPolicy,
    /// The caller-supplied UTC time is outside the authority's freshness window
    /// (authority ∩ DNS signer grant ∩ policy).
    ExpiredAuthority,
    Io(TunError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Outcome of one packet. Stable, packet-safe: no payload or address is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Handled {
    /// An authorized query was answered; the response datagram was written.
    Answered { response_bytes: usize },
    /// The answer did not fit the datagram budget, so a TC-only response was
    /// written (still built from the real query, never a shortened RRset).
    AnsweredTruncated { response_bytes: usize },
    /// Not addressed to the DNS VIP, or not IPv4; nothing was written.
    Ignored,
    /// Addressed to the DNS VIP from a source other than the verified local VIP.
    SourceRefused,
    /// The caller-supplied UTC `now` is outside the verified freshness window.
    /// No response was produced; `poll_once` also leaves the queue unread.
    Expired,
    /// The fixed per-window query budget is exhausted. Nothing was written.
    RateLimited,
    /// TCP to the DNS VIP: refused locally, nothing was written. DNS-over-TCP is
    /// not implemented in this slice.
    TcpRefused,
    /// Structurally invalid IPv4/UDP/DNS input; nothing was written.
    Malformed,
    /// The resolver produced no response (malformed query, or the question
    /// cannot even fit in the datagram budget).
    NoResponse,
    /// The response could not be enqueued on the `PacketIo` endpoint.
    ResponseRejected(TunError),
}

/// Bounded counters for one service instance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsUdpStats {
    pub seen: u64,
    pub answered: u64,
    pub truncated: u64,
    pub ignored: u64,
    pub source_refused: u64,
    pub expired: u64,
    pub rate_limited: u64,
    pub tcp_refused: u64,
    pub malformed: u64,
    pub no_response: u64,
    pub response_rejected: u64,
}

/// Fixed-size fixed-window counter over a monotonic [`Instant`]. No allocation
/// and no per-client map: this service accepts exactly one authenticated source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RateLimit {
    window_start: Option<Instant>,
    used: u32,
}

impl RateLimit {
    /// Consume one unit if the current window has budget left. An out-of-order
    /// sample must not reset an exhausted budget. This clock is independent of
    /// the UTC value used for freshness.
    fn permit(&mut self, now: Instant) -> bool {
        let reset = match self.window_start {
            Some(start) if now < start => return false,
            Some(start) => now.duration_since(start) >= RATE_LIMIT_WINDOW,
            None => true,
        };
        if reset {
            self.window_start = Some(now);
            self.used = 0;
        }
        if self.used >= RATE_LIMIT_MAX_PER_WINDOW {
            return false;
        }
        self.used += 1;
        true
    }
}

/// One authoritative UDP DNS responder instance bound to one verified authority
/// and one authenticated local identity. It is not a daemon or a full server.
pub struct DnsUdpRuntime<'a, P: PacketIo + ?Sized> {
    io: &'a P,
    resolver: AuthoritativeDns,
    local_vip: Ipv4Addr,
    dns_vip: Ipv4Addr,
    net_id: [u8; 16],
    policy_digest: [u8; 32],
    authority_sequence: u64,
    fresh_from: u64,
    fresh_until: u64,
    zone: String,
    mtu: usize,
    max_response_bytes: usize,
    next_id: u16,
    rate_limit: RateLimit,
    stats: DnsUdpStats,
}

impl<P: PacketIo + ?Sized> fmt::Debug for DnsUdpRuntime<'_, P> {
    /// Redacts the endpoint and resolver interior: only stable binding facts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsUdpRuntime")
            .field("local_vip", &self.local_vip)
            .field("dns_vip", &self.dns_vip)
            .field("net_id", &self.net_id)
            .field("zone", &self.zone)
            .field("mtu", &self.mtu)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl<'a, P: PacketIo + ?Sized> DnsUdpRuntime<'a, P> {
    /// Bind a verified authority to an authenticated local endpoint.
    ///
    /// `now` is the caller's UTC time; it must be inside the signed policy window
    /// and the token's freshness window (authority ∩ signer grant ∩ policy).
    /// Binding is not a lifetime grant: `poll_once` and `handle_packet` re-check
    /// their own UTC `now` before answering or writing, and take a separate
    /// monotonic `Instant` for rate limiting. UTC is not trusted against
    /// rollback; the caller owns the clock source.
    pub fn try_new(
        io: &'a P,
        authority: &VerifiedDnsAuthority,
        local: PeerIdentity,
        mtu: usize,
        now: u64,
    ) -> Result<Self, Error> {
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err(Error::MtuOutOfRange);
        }
        if local.net_id == [0; 16] || local.node_id == 0 || local.identity_generation == 0 {
            return Err(Error::InvalidIdentity);
        }
        let policy = local.policy().ok_or(Error::UnboundIdentity)?;
        if policy.net_id() != local.net_id
            || policy.net_id() != authority.net_id()
            || policy.policy_digest() != authority.policy_digest()
        {
            return Err(Error::AuthorityMismatch);
        }
        let (policy_not_before, policy_expires) = policy.validity();
        if now < policy_not_before || now >= policy_expires {
            return Err(Error::ExpiredPolicy);
        }
        if !authority.is_fresh_at(now) {
            return Err(Error::ExpiredAuthority);
        }
        let (fresh_from, fresh_until) = authority.freshness();
        let local_vip = permanent_vip_in(policy.overlay_base(), local.node_id, local.role)
            .ok_or(Error::InvalidPermanentSlot)?;
        let base = policy.overlay_base();
        let dns_octet = u8::try_from(DNS_PORT).map_err(|_| Error::InvalidAuthority)?;
        let dns_vip = Ipv4Addr::new(base[0], base[1], 0, dns_octet);

        let max_response_bytes = (mtu - DATAGRAM_OVERHEAD).min(MAX_RESPONSE_BYTES);
        let resolver = verified_ipv4_resolver(authority, local_vip, max_response_bytes)?;
        Ok(Self {
            io,
            resolver,
            local_vip,
            dns_vip,
            net_id: policy.net_id(),
            policy_digest: policy.policy_digest(),
            authority_sequence: authority.sequence(),
            fresh_from,
            fresh_until,
            zone: authority.zone().to_owned(),
            mtu,
            max_response_bytes,
            next_id: 0,
            rate_limit: RateLimit::default(),
            stats: DnsUdpStats::default(),
        })
    }

    /// The authenticated local permanent VIP queries must come from.
    pub fn local_vip(&self) -> Ipv4Addr {
        self.local_vip
    }

    /// The reserved DNS VIP derived from the verified policy prefix.
    pub fn dns_vip(&self) -> Ipv4Addr {
        self.dns_vip
    }

    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn authority_sequence(&self) -> u64 {
        self.authority_sequence
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Largest DNS message the service will emit, so a reply never exceeds the MTU.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Whether the token's full freshness window (authority ∩ signer grant ∩
    /// policy) contains `now`. The caller must stop this service when this
    /// returns `false`; every packet operation re-checks its own `now` anyway.
    /// This is a UTC interval check, not rollback protection.
    pub fn is_fresh_at(&self, now: u64) -> bool {
        now >= self.fresh_from && now < self.fresh_until
    }

    pub fn stats(&self) -> DnsUdpStats {
        self.stats
    }

    /// Read one packet from the endpoint and handle it at the caller's UTC
    /// `now`, with `monotonic` used only for the rate limiter. `monotonic` must
    /// be sampled from a monotonic clock for this operation, not cached across
    /// calls.
    ///
    /// `Ok(None)` means the queue was empty. When `now` is outside the freshness
    /// window the packet is not read: this returns `Some(Handled::Expired)` so
    /// the caller can stop the service without consuming queued traffic. A
    /// non-DNS packet is consumed and reported as [`Handled::Ignored`]; this
    /// endpoint must not also carry traffic that another path is expected to
    /// forward.
    pub fn poll_once(&mut self, now: u64, monotonic: Instant) -> Result<Option<Handled>, Error> {
        if !self.is_fresh_at(now) {
            self.stats.expired = self.stats.expired.saturating_add(1);
            return Ok(Some(Handled::Expired));
        }
        match self.io.read_packet() {
            Ok(Some(packet)) => Ok(Some(self.handle_packet(&packet, now, monotonic))),
            Ok(None) => Ok(None),
            Err(error) => Err(Error::Io(error)),
        }
    }

    /// Handle one complete IPv4 packet read elsewhere at the caller's UTC `now`,
    /// with `monotonic` used only for the rate limiter. `monotonic` must be
    /// sampled from a monotonic clock for this operation, not cached across
    /// calls. Exactly one bounded response datagram may be written. An expired
    /// token is checked before parsing and produces no response.
    pub fn handle_packet(&mut self, packet: &[u8], now: u64, monotonic: Instant) -> Handled {
        self.stats.seen = self.stats.seen.saturating_add(1);
        if !self.is_fresh_at(now) {
            self.stats.expired = self.stats.expired.saturating_add(1);
            return Handled::Expired;
        }
        if packet.len() > self.mtu {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return Handled::Malformed;
        }
        let info = match inspect_packet(packet) {
            Ok(info) => info,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return Handled::Malformed;
            }
        };
        if info.version != IpVersion::V4 {
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return Handled::Ignored;
        }
        if info.destination != IpAddr::V4(self.dns_vip) {
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return Handled::Ignored;
        }
        // TCP is never answered here. There is no fabricated SYN/ACK or payload:
        // a real DNS-over-TCP endpoint needs the smoltcp interface that this
        // slice does not own.
        if info.protocol == TCP_PROTOCOL {
            if tcp_destination_port(packet, info.header_len) == Some(DNS_PORT) {
                self.stats.tcp_refused = self.stats.tcp_refused.saturating_add(1);
                return Handled::TcpRefused;
            }
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return Handled::Ignored;
        }
        if info.protocol != UDP_PROTOCOL {
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return Handled::Ignored;
        }
        if info.fragment.is_some() {
            // No reassembly here; a single datagram must be whole.
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return Handled::Malformed;
        }
        // The packet source is not authentication. It must equal the VIP derived
        // from the authenticated local identity.
        if info.source != IpAddr::V4(self.local_vip) {
            self.stats.source_refused = self.stats.source_refused.saturating_add(1);
            return Handled::SourceRefused;
        }
        let udp = &packet[info.header_len..];
        if udp.len() < UDP_HEADER_LEN {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return Handled::Malformed;
        }
        let source_port = u16::from_be_bytes([udp[0], udp[1]]);
        let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
        if destination_port != DNS_PORT {
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return Handled::Ignored;
        }
        let declared = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if source_port == 0 || declared < UDP_HEADER_LEN || declared != udp.len() {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return Handled::Malformed;
        }
        let checksum = u16::from_be_bytes([udp[6], udp[7]]);
        // IPv4 permits a zero UDP checksum ("not computed"). A non-zero value
        // must be exactly right; a valid checksum sums to zero.
        if checksum != ZERO_CHECKSUM && udp_checksum(self.local_vip, self.dns_vip, udp) != 0 {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return Handled::Malformed;
        }
        let payload = &udp[UDP_HEADER_LEN..];
        if payload.is_empty() || payload.len() > MAX_QUERY_BYTES {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return Handled::Malformed;
        }
        // Fixed-state abuse bound applied only to structurally accepted queries
        // from the authenticated local VIP. It is checked before any DNS work and
        // uses the monotonic clock, never the UTC freshness value.
        if !self.rate_limit.permit(monotonic) {
            self.stats.rate_limited = self.stats.rate_limited.saturating_add(1);
            return Handled::RateLimited;
        }
        let source = IpAddr::V4(self.local_vip);
        match self.resolver.respond_udp(source, payload) {
            Ok(Some(response)) => self.write_response(source_port, &response, false),
            Ok(None) => {
                // The resolver allowlist is the same verified VIP, so this is a
                // defence-in-depth mismatch rather than a normal path.
                self.stats.source_refused = self.stats.source_refused.saturating_add(1);
                Handled::SourceRefused
            }
            Err(DnsError::TruncatedWouldExceed) => {
                // Honest truncation: header + question with TC, no partial RRset.
                match self.resolver.udp_truncate(payload, self.max_response_bytes) {
                    Ok(response) => self.write_response(source_port, &response, true),
                    Err(_) => {
                        self.stats.no_response = self.stats.no_response.saturating_add(1);
                        Handled::NoResponse
                    }
                }
            }
            Err(_) => {
                self.stats.no_response = self.stats.no_response.saturating_add(1);
                Handled::NoResponse
            }
        }
    }

    fn write_response(
        &mut self,
        destination_port: u16,
        payload: &[u8],
        truncated: bool,
    ) -> Handled {
        let total = DATAGRAM_OVERHEAD + payload.len();
        if total > self.mtu || payload.len() > usize::from(u16::MAX) - UDP_HEADER_LEN {
            self.stats.no_response = self.stats.no_response.saturating_add(1);
            return Handled::NoResponse;
        }
        let Ok(total_u16) = u16::try_from(total) else {
            self.stats.no_response = self.stats.no_response.saturating_add(1);
            return Handled::NoResponse;
        };
        let Ok(udp_len) = u16::try_from(UDP_HEADER_LEN + payload.len()) else {
            self.stats.no_response = self.stats.no_response.saturating_add(1);
            return Handled::NoResponse;
        };
        let mut datagram = vec![0u8; total];
        datagram[0] = 0x45; // IPv4, 5-word header
        datagram[2..4].copy_from_slice(&total_u16.to_be_bytes());
        datagram[4..6].copy_from_slice(&self.next_id.to_be_bytes());
        self.next_id = self.next_id.wrapping_add(1);
        datagram[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        datagram[8] = 64;
        datagram[9] = UDP_PROTOCOL;
        datagram[12..16].copy_from_slice(&self.dns_vip.octets());
        datagram[16..20].copy_from_slice(&self.local_vip.octets());
        let header = ones_complement_sum(&datagram[..IPV4_HEADER_LEN]);
        datagram[10..12].copy_from_slice(&header.to_be_bytes());
        datagram[20..22].copy_from_slice(&DNS_PORT.to_be_bytes());
        datagram[22..24].copy_from_slice(&destination_port.to_be_bytes());
        datagram[24..26].copy_from_slice(&udp_len.to_be_bytes());
        datagram[28..].copy_from_slice(payload);
        let mut checksum = udp_checksum(self.dns_vip, self.local_vip, &datagram[IPV4_HEADER_LEN..]);
        if checksum == 0 {
            checksum = 0xffff;
        }
        datagram[26..28].copy_from_slice(&checksum.to_be_bytes());
        match self.io.write_packet(&datagram) {
            Ok(()) => {
                if truncated {
                    self.stats.truncated = self.stats.truncated.saturating_add(1);
                    Handled::AnsweredTruncated {
                        response_bytes: total,
                    }
                } else {
                    self.stats.answered = self.stats.answered.saturating_add(1);
                    Handled::Answered {
                        response_bytes: total,
                    }
                }
            }
            Err(error) => {
                self.stats.response_rejected = self.stats.response_rejected.saturating_add(1);
                Handled::ResponseRejected(error)
            }
        }
    }
}

fn tcp_destination_port(packet: &[u8], ip_header_len: usize) -> Option<u16> {
    let tcp = packet.get(ip_header_len..)?;
    if tcp.len() < 4 {
        return None;
    }
    Some(u16::from_be_bytes([tcp[2], tcp[3]]))
}

/// Materialize only records covered by the already-verified signed token.
/// The caller must bind the exact policy and source before using the resolver.
pub(super) fn verified_ipv4_resolver(
    authority: &VerifiedDnsAuthority,
    source: Ipv4Addr,
    max_response_bytes: usize,
) -> Result<AuthoritativeDns, Error> {
    // The profile has no policy ULA. Refuse IPv6 claims/records rather than
    // putting an address into the zone that the policy never authorized.
    if authority.vips().iter().any(|claim| claim.ipv6.is_some()) {
        return Err(Error::UnsupportedIpv6);
    }

    // The zone is rebuilt from the verified token, never from caller bytes.
    // Only A records are accepted; an AAAA record would need a policy ULA.
    let mut zone = Zone::new(authority.zone()).map_err(|_| Error::InvalidAuthority)?;
    for record in authority.records() {
        let address = match record.record_type {
            1 => {
                let octets: [u8; 4] = record
                    .address
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidAuthority)?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            28 => return Err(Error::UnsupportedIpv6),
            _ => return Err(Error::InvalidAuthority),
        };
        zone.add_address(&record.owner, address)
            .map_err(|_| Error::InvalidAuthority)?;
    }

    let sources = SourceAuthorization::new([IpAddr::V4(source)]);
    AuthoritativeDns::new(zone, sources, max_response_bytes).map_err(|_| Error::InvalidAuthority)
}

/// Permanent IPv4 slot for `(node_id, role)` inside a verified prefix.
///
/// This is the same rule `packet_path` applies to its authenticated endpoints,
/// parameterized by the signed policy's base. It is kept private here so this
/// slice does not modify the packet-path file; the per-node `(node_id, VIP)`
/// binding is also re-checked inside `boreas-pki` for every signed claim.
pub(super) fn permanent_vip_in(base: [u8; 4], node_id: u16, role: NodeRole) -> Option<Ipv4Addr> {
    let home_core = u8::try_from(node_id >> 8).ok()?.checked_add(1)?;
    let vip_octet = u8::try_from(node_id & 0xff).ok()?;
    if home_core > 16 {
        return None;
    }
    let octet_valid = match role {
        NodeRole::Core => vip_octet == 1,
        NodeRole::Edge => (2..=251).contains(&vip_octet),
        NodeRole::EnrollmentService => false,
    };
    if !octet_valid {
        return None;
    }
    Some(Ipv4Addr::new(base[0], base[1], home_core, vip_octet))
}

/// One's-complement sum check over `source || destination || 0 || 17 || len ||
/// udp`. Used both to verify an incoming non-zero checksum (a valid datagram
/// sums to zero) and to compute the outgoing one (call with a zero field).
fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    if udp.len() > MAX_MTU {
        return 0xffff;
    }
    let mut buffer = [0u8; MAX_PSEUDO_SUM_LEN];
    let len = 12 + udp.len();
    buffer[0..4].copy_from_slice(&source.octets());
    buffer[4..8].copy_from_slice(&destination.octets());
    buffer[8] = 0;
    buffer[9] = UDP_PROTOCOL;
    let Ok(udp_len) = u16::try_from(udp.len()) else {
        return 0xffff;
    };
    buffer[10..12].copy_from_slice(&udp_len.to_be_bytes());
    buffer[12..len].copy_from_slice(udp);
    ones_complement_sum(&buffer[..len])
}

fn ones_complement_sum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for &[hi, lo] in chunks {
        sum += u32::from(u16::from_be_bytes([hi, lo]));
    }
    if let Some(&byte) = remainder.first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use boreas_pki::dns_authority::DnsSignerPin;
    use boreas_pki::{NetworkRootPin, verify_network_policy};
    use boreas_proto::{
        dns_authority::{
            DnsAuthority, DnsRecordEntry, DnsSignerGrant, DnsVipClaim, MLDSA_PARAMETER_SET_65,
            TYPE_A, TYPE_AAAA,
        },
        network_policy::NetworkPolicyCandidate,
        objects::MldsaParameterSet,
    };
    use boreas_tun::VirtualTun;
    use openssl::{
        pkey::{KeyType, PKey, Private},
        sign::Signer,
    };
    use std::time::{Duration, Instant};

    const NET: [u8; 16] = [7; 16];
    const LOCAL: [u8; 4] = [10, 20, 1, 1];

    pub(crate) fn sign(
        ed: &PKey<Private>,
        pq: &PKey<Private>,
        message: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut signer = Signer::new_without_digest(ed).unwrap();
        let ed_signature = signer.sign_oneshot_to_vec(message).unwrap();
        let mut signer = Signer::new_without_digest(pq).unwrap();
        (ed_signature, signer.sign_oneshot_to_vec(message).unwrap())
    }

    fn keys(seed: u8) -> (PKey<Private>, PKey<Private>) {
        (
            PKey::generate_ed25519().unwrap(),
            PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap(),
        )
    }

    pub(crate) struct Fixture {
        pub(crate) authority: VerifiedDnsAuthority,
        pub(crate) local: PeerIdentity,
        pub(crate) network: boreas_pki::VerifiedNetworkPolicy,
        pub(crate) root: NetworkRootPin,
        pub(crate) root_ed: PKey<Private>,
        pub(crate) root_pq: PKey<Private>,
    }

    fn fixture() -> (VerifiedDnsAuthority, PeerIdentity) {
        let f = fixture_at(1);
        (f.authority, f.local)
    }

    /// A complete real trust chain: root pin -> signed policy -> root-signed DNS
    /// signer grant -> signer-signed zone authority -> policy-bound local identity.
    pub(crate) fn fixture_at(unit: u64) -> Fixture {
        let (root_ed, root_pq) = keys(41);
        let root = NetworkRootPin::provisioned(
            NET,
            root_ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            root_pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        let candidate = NetworkPolicyCandidate {
            net_id: NET,
            root_key_fingerprint: root.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 1,
            issued_at: 1_000 * unit,
            expires: 2_000 * unit,
        };
        let raw = candidate.encode_tbs().unwrap();
        let message = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        let (ed, pq) = sign(&root_ed, &root_pq, &message);
        let network = verify_network_policy(&raw, &ed, &pq, &root, NET, 1_500 * unit).unwrap();
        let policy = network.require_default_runtime().unwrap();

        let (signer_ed, signer_pq) = keys(42);
        let grant = DnsSignerGrant {
            net_id: NET,
            policy_digest: policy.policy_digest(),
            signer_generation: 1,
            sequence: 1,
            not_before: 1_000 * unit,
            expires: 2_000 * unit,
            ed25519_public_key_der: signer_ed.public_key_to_der().unwrap(),
            mldsa_parameter_set: MLDSA_PARAMETER_SET_65,
            mldsa_public_key_der: signer_pq.public_key_to_der().unwrap(),
        };
        let grant_raw = grant.encode_tbs().unwrap();
        let message = DnsSignerGrant::signature_input(&grant_raw).unwrap();
        let (grant_ed, grant_pq) = sign(&root_ed, &root_pq, &message);
        let signer = DnsSignerPin::verify_grant(
            &grant_raw,
            &grant_ed,
            &grant_pq,
            &root,
            &policy,
            1_500 * unit,
        )
        .unwrap();

        let authority = DnsAuthority {
            net_id: NET,
            policy_digest: policy.policy_digest(),
            sequence: 2,
            issued_at: 1_000 * unit,
            expires: 1_900 * unit,
            zone: b"b.example".to_vec(),
            vips: vec![DnsVipClaim {
                node_id: 0x0001,
                ipv4: LOCAL,
                ipv6: [0; 16],
            }],
            records: vec![DnsRecordEntry {
                owner: b"host.b.example".to_vec(),
                record_type: TYPE_A,
                address: LOCAL.to_vec(),
            }],
        };
        let raw = authority.encode_tbs().unwrap();
        let message = DnsAuthority::signature_input(&raw).unwrap();
        let (ed, pq) = sign(&signer_ed, &signer_pq, &message);
        let authority =
            VerifiedDnsAuthority::verify(&raw, &ed, &pq, &signer, &policy, 1_500 * unit).unwrap();
        let local = PeerIdentity::policy_bound(NET, 0x0001, 1, NodeRole::Core, policy).unwrap();
        Fixture {
            authority,
            local,
            network,
            root,
            root_ed,
            root_pq,
        }
    }

    pub(crate) fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(u8::try_from(label.len()).unwrap());
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    pub(crate) fn udp_datagram(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
        with_checksum: bool,
    ) -> Vec<u8> {
        let total = DATAGRAM_OVERHEAD + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = UDP_PROTOCOL;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(
            &u16::try_from(UDP_HEADER_LEN + payload.len())
                .unwrap()
                .to_be_bytes(),
        );
        packet[28..].copy_from_slice(payload);
        let header = ones_complement_sum(&packet[..IPV4_HEADER_LEN]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        if with_checksum {
            let mut value = udp_checksum(
                Ipv4Addr::from(source),
                Ipv4Addr::from(destination),
                &packet[20..],
            );
            if value == 0 {
                value = 0xffff;
            }
            packet[26..28].copy_from_slice(&value.to_be_bytes());
        }
        packet
    }

    fn tcp_segment(source: [u8; 4], destination: [u8; 4], destination_port: u16) -> Vec<u8> {
        let total = IPV4_HEADER_LEN + 20;
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        packet[8] = 64;
        packet[9] = TCP_PROTOCOL;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&40_000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50; // data offset: 5 words
        packet[20 + 13] = 0x02; // SYN
        let header = ones_complement_sum(&packet[..IPV4_HEADER_LEN]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet
    }

    pub(crate) fn dns_payload(packet: &[u8]) -> &[u8] {
        let info = inspect_packet(packet).expect("structurally valid response");
        &packet[info.header_len + UDP_HEADER_LEN..]
    }

    fn exchange(
        runtime: &mut DnsUdpRuntime<'_, VirtualTun>,
        device: &VirtualTun,
        host: &VirtualTun,
        source: [u8; 4],
        destination: [u8; 4],
        query: &[u8],
        time: (u64, Instant),
    ) -> (Handled, Option<Vec<u8>>) {
        let packet = udp_datagram(source, destination, 40_000, DNS_PORT, query, true);
        device.inject(&packet).unwrap();
        let handled = runtime
            .poll_once(time.0, time.1)
            .unwrap()
            .expect("one packet");
        (handled, host.read_packet().unwrap())
    }

    #[test]
    fn permanent_slot_rule_matches_the_packet_path() {
        assert_eq!(
            permanent_vip_in([10, 20, 0, 0], 0x0001, NodeRole::Core),
            Some(Ipv4Addr::new(10, 20, 1, 1))
        );
        assert_eq!(
            permanent_vip_in([10, 20, 0, 0], 0x0102, NodeRole::Edge),
            Some(Ipv4Addr::new(10, 20, 2, 2))
        );
        assert_eq!(
            permanent_vip_in([10, 20, 0, 0], 0x0101, NodeRole::Core),
            Some(Ipv4Addr::new(10, 20, 2, 1))
        );
        assert_eq!(
            permanent_vip_in([10, 20, 0, 0], 0x0001, NodeRole::Edge),
            None
        );
        assert_eq!(
            permanent_vip_in([10, 20, 0, 0], 0x0002, NodeRole::EnrollmentService),
            None
        );
        assert_eq!(
            permanent_vip_in([10, 20, 0, 0], 0x1001, NodeRole::Core),
            None
        );
        // The rule is parameterized by the signed policy prefix, not hardcoded.
        assert_eq!(
            permanent_vip_in([172, 19, 0, 0], 0x0001, NodeRole::Core),
            Some(Ipv4Addr::new(172, 19, 1, 1))
        );
    }

    #[test]
    fn real_udp_query_is_answered_over_packet_io() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();
        assert_eq!(runtime.local_vip(), Ipv4Addr::new(10, 20, 1, 1));
        assert_eq!(runtime.dns_vip(), Ipv4Addr::new(10, 20, 0, 53));
        assert_eq!(runtime.net_id(), NET);
        assert_eq!(runtime.zone(), "b.example");
        assert_eq!(runtime.authority_sequence(), 2);
        assert!(runtime.is_fresh_at(1_500));
        assert!(!runtime.is_fresh_at(1_900));

        let query = dns_query("host.b.example", TYPE_A);
        let (handled, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 0, 53],
            &query,
            (1_500, Instant::now()),
        );
        assert!(
            matches!(handled, Handled::Answered { .. }),
            "expected an answer, got {handled:?}"
        );
        let response = response.expect("one response datagram");
        let info = inspect_packet(&response).unwrap();
        assert_eq!(info.source, IpAddr::V4(Ipv4Addr::new(10, 20, 0, 53)));
        assert_eq!(info.destination, IpAddr::V4(Ipv4Addr::new(10, 20, 1, 1)));
        assert_eq!(info.protocol, UDP_PROTOCOL);
        let udp = &response[info.header_len..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), DNS_PORT);
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 40_000);
        assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
        assert_eq!(
            udp_checksum(
                Ipv4Addr::new(10, 20, 0, 53),
                Ipv4Addr::new(10, 20, 1, 1),
                udp
            ),
            0,
            "the response UDP checksum must verify"
        );
        let dns = dns_payload(&response);
        assert_eq!(u16::from_be_bytes([dns[0], dns[1]]), 0x1234);
        assert_ne!(dns[2] & 0x80, 0, "QR");
        assert_ne!(dns[2] & 0x04, 0, "AA");
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1, "ANCOUNT");
        assert_eq!(&dns[dns.len() - 4..], &LOCAL);
        assert_eq!(host.read_packet().unwrap(), None, "one query, one response");
        let stats = runtime.stats();
        assert_eq!(stats.seen, 1);
        assert_eq!(stats.answered, 1);
    }

    #[test]
    fn aaaa_is_nodata_because_ipv6_is_disabled_by_default() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();
        let (handled, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 0, 53],
            &dns_query("host.b.example", TYPE_AAAA),
            (1_500, Instant::now()),
        );
        assert!(matches!(handled, Handled::Answered { .. }));
        let response = response.expect("NODATA response");
        let dns = dns_payload(&response);
        assert_eq!(dns[3] & 0x0f, 0, "NOERROR, not NXDOMAIN");
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 0, "ANCOUNT");
        assert_ne!(dns[2] & 0x04, 0, "AA");
    }

    #[test]
    fn expired_token_is_refused_per_operation_without_reading_or_writing() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();
        let query = dns_query("host.b.example", TYPE_A);
        let packet = udp_datagram(LOCAL, [10, 20, 0, 53], 40_000, DNS_PORT, &query, true);
        device.inject(&packet).unwrap();

        // The authority expires at 1_900. The guard runs before the endpoint is
        // read, so the queued packet is untouched.
        assert_eq!(
            runtime.poll_once(1_900, Instant::now()).unwrap(),
            Some(Handled::Expired)
        );
        assert_eq!(host.read_packet().unwrap(), None);
        assert_eq!(
            device.read_packet().unwrap(),
            Some(packet.clone()),
            "an expired poll must not consume the packet"
        );
        assert_eq!(
            runtime.handle_packet(&packet, 2_000, Instant::now()),
            Handled::Expired
        );
        assert_eq!(host.read_packet().unwrap(), None);
        let stats = runtime.stats();
        assert_eq!(stats.expired, 2);
        assert_eq!(stats.answered, 0);
        assert_eq!(stats.truncated, 0);
    }

    #[test]
    fn rate_limit_refuses_out_of_order_monotonic_samples() {
        let start = Instant::now() + Duration::from_secs(1);
        let mut limiter = RateLimit {
            window_start: Some(start),
            used: RATE_LIMIT_MAX_PER_WINDOW,
        };
        assert!(!limiter.permit(start - Duration::from_millis(1)));
        assert_eq!(limiter.used, RATE_LIMIT_MAX_PER_WINDOW);
        assert_eq!(limiter.window_start, Some(start));
        assert!(limiter.permit(start + RATE_LIMIT_WINDOW));
        assert_eq!(limiter.used, 1);
    }

    #[test]
    fn fixed_rate_limit_bounds_answers_and_recovers_next_window() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();
        let query = dns_query("host.b.example", TYPE_A);
        let base = Instant::now();
        runtime.rate_limit = RateLimit {
            window_start: Some(base),
            used: RATE_LIMIT_MAX_PER_WINDOW,
        };

        let (handled, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 0, 53],
            &query,
            (1_500, base),
        );
        assert_eq!(handled, Handled::RateLimited);
        assert_eq!(response, None);
        assert_eq!(runtime.stats().rate_limited, 1);
        assert_eq!(runtime.stats().answered, 0);

        // Advancing UTC does not refill the budget: the limiter only sees the
        // monotonic Instant. The UTC value is still inside the freshness window.
        let (handled, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 0, 53],
            &query,
            (1_700, base),
        );
        assert_eq!(handled, Handled::RateLimited);
        assert_eq!(response, None);
        assert_eq!(runtime.stats().rate_limited, 2);
        assert_eq!(runtime.stats().answered, 0);

        // A new one-second monotonic window restores exactly the fixed budget.
        let (handled, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 0, 53],
            &query,
            (1_700, base + Duration::from_secs(1)),
        );
        assert!(matches!(handled, Handled::Answered { .. }));
        assert!(response.is_some());
        assert_eq!(runtime.stats().answered, 1);
    }

    #[test]
    fn nxdomain_and_out_of_zone_refused_have_correct_rcodes() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();

        let (_, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 0, 53],
            &dns_query("missing.b.example", TYPE_A),
            (1_500, Instant::now()),
        );
        let response = response.expect("NXDOMAIN response");
        let dns = dns_payload(&response);
        assert_eq!(dns[3] & 0x0f, 3);
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 0);

        let (_, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 0, 53],
            &dns_query("other.example", TYPE_A),
            (1_500, Instant::now()),
        );
        let response = response.expect("REFUSED response");
        let dns = dns_payload(&response);
        assert_eq!(dns[3] & 0x0f, 5);
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 0);
    }

    #[test]
    fn spoofed_source_and_wrong_destination_get_no_response() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();
        let query = dns_query("host.b.example", TYPE_A);

        let (handled, response) = exchange(
            &mut runtime,
            &device,
            &host,
            [10, 20, 9, 9],
            [10, 20, 0, 53],
            &query,
            (1_500, Instant::now()),
        );
        assert_eq!(handled, Handled::SourceRefused);
        assert_eq!(response, None);
        assert_eq!(runtime.stats().source_refused, 1);

        let (handled, response) = exchange(
            &mut runtime,
            &device,
            &host,
            LOCAL,
            [10, 20, 1, 1],
            &query,
            (1_500, Instant::now()),
        );
        assert_eq!(handled, Handled::Ignored);
        assert_eq!(response, None);
        assert_eq!(runtime.stats().answered, 0);
    }

    #[test]
    fn tcp_is_refused_without_synthesizing_any_segment() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();
        let segment = tcp_segment(LOCAL, [10, 20, 0, 53], DNS_PORT);
        assert_eq!(
            runtime.handle_packet(&segment, 1_500, Instant::now()),
            Handled::TcpRefused
        );
        assert_eq!(host.read_packet().unwrap(), None);
        let stats = runtime.stats();
        assert_eq!(stats.tcp_refused, 1);
        assert_eq!(stats.answered, 0);
        assert_eq!(stats.truncated, 0);
    }

    #[test]
    fn malformed_and_fragmented_datagrams_fail_closed() {
        let (authority, local) = fixture();
        let (device, host) = VirtualTun::try_pair(8, 8, MAX_MTU).unwrap();
        let mut runtime = DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_500).unwrap();
        let query = dns_query("host.b.example", TYPE_A);

        // A bad non-zero UDP checksum is refused, not repaired.
        let mut bad = udp_datagram(LOCAL, [10, 20, 0, 53], 40_000, DNS_PORT, &query, true);
        bad[27] ^= 0xff;
        assert_eq!(
            runtime.handle_packet(&bad, 1_500, Instant::now()),
            Handled::Malformed
        );
        assert_eq!(host.read_packet().unwrap(), None);

        // A zero UDP checksum is legal for IPv4 and is accepted.
        let zero = udp_datagram(LOCAL, [10, 20, 0, 53], 40_000, DNS_PORT, &query, false);
        assert!(matches!(
            runtime.handle_packet(&zero, 1_500, Instant::now()),
            Handled::Answered { .. }
        ));
        assert!(host.read_packet().unwrap().is_some());

        // A fragment is not reassembled here.
        let mut fragmented = udp_datagram(LOCAL, [10, 20, 0, 53], 40_000, DNS_PORT, &[], false);
        fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF
        fragmented[10..12].fill(0);
        let header = ones_complement_sum(&fragmented[..IPV4_HEADER_LEN]);
        fragmented[10..12].copy_from_slice(&header.to_be_bytes());
        assert_eq!(
            runtime.handle_packet(&fragmented, 1_500, Instant::now()),
            Handled::Malformed
        );

        // IPv6 is ignored (the packet path negotiates IPv4 only).
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[6] = 59; // no next header
        assert_eq!(
            runtime.handle_packet(&v6, 1_500, Instant::now()),
            Handled::Ignored
        );
    }

    #[test]
    fn binding_rejects_unverified_or_expired_material() {
        let (authority, local) = fixture();
        let (device, _host) = VirtualTun::try_pair(2, 2, MAX_MTU).unwrap();

        assert_eq!(
            DnsUdpRuntime::try_new(&device, &authority, local, 1500, 2_000).unwrap_err(),
            Error::ExpiredPolicy
        );
        assert_eq!(
            DnsUdpRuntime::try_new(&device, &authority, local, 1500, 1_900).unwrap_err(),
            Error::ExpiredAuthority
        );
        assert_eq!(
            DnsUdpRuntime::try_new(&device, &authority, local, 100, 1_500).unwrap_err(),
            Error::MtuOutOfRange
        );

        // A legacy identity has no verified policy context at all.
        let legacy = PeerIdentity::legacy_default(NET, 0x0001, 1, NodeRole::Core);
        assert_eq!(
            DnsUdpRuntime::try_new(&device, &authority, legacy, 1500, 1_500).unwrap_err(),
            Error::UnboundIdentity
        );
    }
}
