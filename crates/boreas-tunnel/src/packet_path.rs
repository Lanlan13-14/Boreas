//! Bounded L3 packet encapsulation between a real [`boreas_tun::PacketIo`]
//! endpoint and an established [`E2eCircuit`] byte stream.
//!
//! # What this module is
//!
//! A single-owner adapter. One direction reads exactly one IP packet from the
//! host-side `PacketIo` endpoint (the host stack sent it), checks it against the
//! signed permanent VIP pair, and writes it as exactly one length-prefixed frame
//! into the already authenticated and encrypted E2E circuit stream. The other
//! direction reads exactly one frame from the stream, repeats the address check
//! for its own direction, and hands exactly one packet to the host-side
//! [`PacketIo::write_inspected_packet`]. Ordinary traffic has no queued retry
//! or second FIFO: `boreas_tun::VirtualTun` or a native `PacketIo` queue is the
//! only packet queue, and the circuit stream is the only wire. Opt-in private
//! DNS terminates matching requests instead of handing them to the host.
//!
//! # Where the endpoints come from
//!
//! The two endpoints are taken from the circuit itself: [`E2eCircuit::info`]
//! reports the peer that the E2E handshake compared for exact equality against
//! the verified TLS peer, and [`E2eCircuit::local`] reports the authenticated
//! local hop identity captured when the circuit was established. Their permanent
//! IPv4 addresses are derived from the verified node id and role, then checked to
//! be a canonical permanent slot. There is no caller-supplied "authenticated"
//! boolean, no caller-declared local endpoint and no address table that a caller
//! can substitute. A plaintext or hop-only session cannot reach the public
//! constructor at all, because it needs an `E2eCircuit`, and `E2eCircuit` can only
//! be produced by the E2E TLS handshake plus the encrypted application
//! confirmation.
//!
//! # Deliberate limits of this slice (not production acceptance)
//!
//! * Point-to-point only: the two exact permanent VIP addresses. No subnet
//!   route, no default route, no third party and no IPv6. IPv6 is not negotiated
//!   here, so every IPv6 packet is refused rather than forwarded. The optional
//!   Core DNS constructor additionally terminates UDP/53 at the reserved service
//!   VIP locally; it grants neither host access to that address nor a new route.
//! * **Ordinary forwarding does not revalidate durable status.** The daemon
//!   owner must gate business traffic on a real verified status capability.
//!   The opt-in DNS branch separately enforces signed validity windows, trusted
//!   UTC and its circuit owner's liveness gate through reply delivery. Neither
//!   is `G-REVOKE`, `G-E2E`, `G-DATA` or 1 GiB production evidence on its own.
//! * No retry buffer, no scheduler, no cancellation token and no worker thread.
//!   The blocking owner loop, its poll/wakeup policy and shutdown ordering stay
//!   with the runtime owner. One `read`/`write` step is bounded: consecutive
//!   `Interrupted` results fail closed instead of being retried without limit.
//!   A malformed packet, an unauthorized address or a wire/circuit error poisons
//!   the path: it fails closed, refuses every later step, and the caller must
//!   tear the circuit down. No failure path converts to hop-only delivery.
//! * Not a router or a forwarder. This adapter terminates one point-to-point
//!   link: it does not decrement TTL/hop limit, does not generate ICMP errors,
//!   does not reassemble fragments and does not route. `path_hops` may be greater
//!   than one — a multi-hop encrypted circuit still ends here — but this adapter
//!   only ever sees its own two endpoints, never the intermediate hops. Those
//!   forwarding slices carry their own evidence.
//! * The 2-byte big-endian length framing is a **candidate** encoding, not a
//!   frozen protocol and not a registered L3 capability. See
//!   `docs/protocol/e2e-packet-candidate-v1.md`.
//! * Only link MTUs in `MIN_MTU..=MAX_MTU` (576..=1500) are accepted, and never
//!   above the circuit's negotiated `mtu_cap`. Jumbo frames, GSO and virtio
//!   offload belong to separate slices.

use std::{
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr},
};

use boreas_crypto::NodeRole;
use boreas_tun::{Error as TunError, InspectedPacket, IpVersion, PacketInfo, PacketIo, PacketRead};

#[cfg(feature = "openssl-inner-tls")]
use crate::dns_packet_service::{self, DnsPacketService};
#[cfg(feature = "openssl-inner-tls")]
use std::time::Instant;

use crate::e2e::E2eCircuit;
use crate::error::TunnelError;
use crate::relay::MAX_RELAY_HOPS;
use crate::tls::PeerIdentity;
use crate::ws::WsError;

/// Width of the length prefix inside the E2E stream, in bytes.
pub const FRAME_PREFIX_LEN: usize = 2;
/// Smallest MTU this adapter accepts. This is a validation floor taken from the
/// IPv4 minimum reassembly buffer (RFC 791); it is **not** a negotiated default
/// link MTU. The runtime owner chooses the actual link MTU (`DEFAULT_MTU` is the
/// 1500-byte Ethernet value).
pub const MIN_MTU: usize = 576;
/// Largest accepted link MTU for this slice.
pub const MAX_MTU: usize = 1500;
/// Default link MTU.
pub const DEFAULT_MTU: usize = 1500;
/// Largest encoded frame: prefix plus one full-MTU packet.
pub const MAX_FRAME_BYTES: usize = FRAME_PREFIX_LEN + MAX_MTU;

// The daemon already targets a single 16,288-byte plaintext record. Keep
// initialized space for one full guarded read after the byte threshold; the
// threshold is checked BEFORE reading, just like the original batch path.
const INLINE_BATCH_THRESHOLD: usize = 16_288;
const INLINE_BATCH_STORAGE: usize = INLINE_BATCH_THRESHOLD + MAX_FRAME_BYTES + 1;

/// Bounded retries for `ErrorKind::Interrupted` reads before the path gives up.
/// A stream that never makes progress must not spin forever.
const MAX_INTERRUPT_RETRIES: u8 = 8;

/// Why one L3 packet was refused.
///
/// These are structural and policy decisions over the packet bytes, not
/// authentication results. Stable, peer-safe codes only: nothing here echoes
/// packet contents, addresses or backend text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDeny {
    /// The packet slice was empty.
    EmptyPacket,
    /// The header or the declared length was cut off.
    Truncated,
    /// The version nibble was neither 4 nor 6.
    UnknownVersion,
    /// IPv6 is not negotiated in this slice, so it is refused, never forwarded.
    Ipv6NotNegotiated,
    /// A structurally invalid IP header.
    BadHeader,
    /// The declared total length disagrees with the slice or the header length.
    BadLength,
    /// The IPv4 header checksum did not verify.
    BadChecksum,
    /// An IPv6 extension chain this slice does not carry.
    UnsupportedExtension,
    /// A malformed fragment description.
    MalformedFragment,
    /// Larger than the negotiated link MTU.
    MtuExceeded,
    /// Outbound packet source is not the local permanent VIP.
    SourceNotLocal,
    /// Outbound packet destination is not the peer permanent VIP.
    DestinationNotPeer,
    /// Inbound packet source is not the peer permanent VIP.
    SourceNotPeer,
    /// Inbound packet destination is not the local permanent VIP.
    DestinationNotLocal,
    /// An ordinary IP packet on a dedicated private DNS circuit.
    NotDnsTraffic,
}

impl fmt::Display for PacketDeny {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyPacket => "packet-empty",
            Self::Truncated => "packet-truncated",
            Self::UnknownVersion => "ip-version-unknown",
            Self::Ipv6NotNegotiated => "ipv6-not-negotiated",
            Self::BadHeader => "ip-header-invalid",
            Self::BadLength => "ip-length-invalid",
            Self::BadChecksum => "ip-checksum-invalid",
            Self::UnsupportedExtension => "ip-extension-unsupported",
            Self::MalformedFragment => "ip-fragment-malformed",
            Self::MtuExceeded => "mtu-exceeded",
            Self::SourceNotLocal => "source-not-local-vip",
            Self::DestinationNotPeer => "destination-not-peer-vip",
            Self::SourceNotPeer => "source-not-peer-vip",
            Self::DestinationNotLocal => "destination-not-local-vip",
            Self::NotDnsTraffic => "not-private-dns-traffic",
        })
    }
}

impl PacketDeny {
    /// A structurally valid packet produced by the local host that is not part
    /// of this point-to-point flow. It is discarded without reaching the peer
    /// and without failing the circuit. Malformed packets are not included.
    pub const fn is_local_discard(self) -> bool {
        matches!(
            self,
            Self::Ipv6NotNegotiated | Self::SourceNotLocal | Self::DestinationNotPeer | Self::NotDnsTraffic
        )
    }
}

impl std::error::Error for PacketDeny {}

impl From<TunError> for PacketDeny {
    fn from(error: TunError) -> Self {
        match error {
            TunError::EmptyPacket => Self::EmptyPacket,
            TunError::Truncated => Self::Truncated,
            TunError::InvalidVersion => Self::UnknownVersion,
            TunError::InvalidHeader => Self::BadHeader,
            TunError::InvalidLength => Self::BadLength,
            TunError::InvalidChecksum => Self::BadChecksum,
            TunError::UnsupportedExtension | TunError::TooManyExtensions => {
                Self::UnsupportedExtension
            }
            TunError::FragmentMalformed
            | TunError::FragmentOverlap
            | TunError::FragmentLimit
            | TunError::FragmentTimeout => Self::MalformedFragment,
            TunError::PacketTooLarge { .. } => Self::MtuExceeded,
            TunError::TtlExpired
            | TunError::QueueFull
            | TunError::QueueClosed
            | TunError::InvalidConfiguration
            | TunError::VirtioHeaderTruncated
            | TunError::VirtioUnsupportedGso
            | TunError::VirtioUnsupportedOffload
            | TunError::VirtioInvalid => Self::BadHeader,
        }
    }
}

/// Failure of the packet path itself, as opposed to one refused packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketPathError {
    /// One packet was refused by the L3 policy.
    Denied(PacketDeny),
    /// A frame carried no packet.
    EmptyFrame,
    /// A frame declared more bytes than the negotiated MTU allows.
    FrameTooLarge,
    /// The declared frame length and the bytes actually present disagree.
    FrameLengthMismatch,
    /// The stream ended inside a frame.
    TruncatedFrame,
    /// The circuit stream reported an I/O error.
    CircuitIo(io::ErrorKind),
    /// The wrapped TLS, WebSocket or circuit rejected the byte stream.
    CircuitProtocol,
    /// The host-side packet queue is full. This slice has no retry buffer, so it
    /// fails closed instead of dropping the packet silently.
    HostQueueFull,
    /// The host-side packet endpoint was closed.
    HostQueueClosed,
    /// The host-side `PacketIo` rejected a packet this path already validated.
    HostRejected(TunError),
    /// The link MTU is outside `MIN_MTU..=MAX_MTU`.
    MtuOutOfRange,
    /// The requested link MTU is above the hop session's negotiated cap.
    MtuAboveCircuitCap,
    /// An identity is not a usable Boreas node identity.
    InvalidIdentity,
    /// The identity is not bound to the same verified network policy as its peer.
    PolicyMismatch,
    /// The node id and role do not describe a permanent VIP slot.
    InvalidPermanentSlot,
    /// A permanent VIP is not in the network overlay or not canonical.
    InvalidEndpointVip,
    /// Both endpoints resolved to the same identity or address.
    SelfPair,
    /// The circuit id, hop count or peer facts do not match the established
    /// circuit.
    CircuitMismatch,
    /// The local and peer identities are not two nodes of one network.
    IdentityMismatch,
    /// The path was closed or poisoned by an earlier failure.
    Closed,
    /// The path was poisoned by an earlier failure and refuses all work.
    Poisoned,
    /// The selected DNS grants, authority, or link binding were rejected.
    #[cfg(feature = "openssl-inner-tls")]
    DnsBind(dns_packet_service::Error),
    /// DNS authorization is no longer current.
    #[cfg(feature = "openssl-inner-tls")]
    DnsAuthorizationLost,
}

impl fmt::Display for PacketPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(deny) => write!(f, "packet-denied({deny})"),
            Self::EmptyFrame => f.write_str("frame-empty"),
            Self::FrameTooLarge => f.write_str("frame-too-large"),
            Self::FrameLengthMismatch => f.write_str("frame-length-mismatch"),
            Self::TruncatedFrame => f.write_str("frame-truncated"),
            Self::CircuitIo(kind) => write!(f, "circuit-io({kind:?})"),
            Self::CircuitProtocol => f.write_str("circuit-protocol"),
            Self::HostQueueFull => f.write_str("host-queue-full"),
            Self::HostQueueClosed => f.write_str("host-queue-closed"),
            Self::HostRejected(error) => write!(f, "host-rejected({error})"),
            Self::MtuOutOfRange => f.write_str("mtu-out-of-range"),
            Self::MtuAboveCircuitCap => f.write_str("mtu-above-circuit-cap"),
            Self::InvalidIdentity => f.write_str("identity-invalid"),
            Self::PolicyMismatch => f.write_str("policy-mismatch"),
            Self::InvalidPermanentSlot => f.write_str("permanent-slot-invalid"),
            Self::InvalidEndpointVip => f.write_str("endpoint-vip-invalid"),
            Self::SelfPair => f.write_str("endpoint-pair-self"),
            Self::CircuitMismatch => f.write_str("circuit-mismatch"),
            Self::IdentityMismatch => f.write_str("identity-mismatch"),
            Self::Closed => f.write_str("path-closed"),
            Self::Poisoned => f.write_str("path-poisoned"),
            #[cfg(feature = "openssl-inner-tls")]
            Self::DnsBind(error) => write!(f, "dns-bind({error})"),
            #[cfg(feature = "openssl-inner-tls")]
            Self::DnsAuthorizationLost => f.write_str("dns-authorization-lost"),
        }
    }
}

impl std::error::Error for PacketPathError {}

/// Read-only facts about one authenticated endpoint of the circuit.
///
/// The fields are private and there is no public constructor: this value is only
/// produced from an [`E2eCircuit`]'s verified identities, so code outside this
/// crate cannot present its own endpoint declaration as one of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointFacts {
    net_id: [u8; 16],
    node_id: u16,
    identity_generation: u64,
    role: NodeRole,
    vip: Ipv4Addr,
    #[cfg(feature = "openssl-inner-tls")]
    policy_digest: [u8; 32],
}

impl EndpointFacts {
    pub fn net_id(&self) -> [u8; 16] {
        self.net_id
    }

    pub fn node_id(&self) -> u16 {
        self.node_id
    }

    pub fn identity_generation(&self) -> u64 {
        self.identity_generation
    }

    pub fn role(&self) -> NodeRole {
        self.role
    }

    /// The permanent IPv4 address derived from this verified identity.
    pub fn vip(&self) -> Ipv4Addr {
        self.vip
    }

    /// Derive the endpoint from authenticated identity facts.
    ///
    /// The VIP is a deterministic function of the verified signed policy base,
    /// `(node_id, role)`: `<base>.<home_core>.<vip_octet>`, with
    /// `node_id = ((home_core - 1) << 8) | vip_octet`, Core `vip_octet = 1` and
    /// Edge `vip_octet` in `2..=251`. This reproduces `boreas-pki`'s permanent
    /// slot rule so the L3 binding can be checked in a build without the PKI
    /// dependency; it is not a substitute for verifying the signed
    /// `NodeIdentity` that carries the same value. Enrollment-service nodes have
    /// no VIP and are refused.
    fn from_verified_identity(identity: PeerIdentity) -> Result<Self, PacketPathError> {
        if identity.net_id == [0; 16] || identity.node_id == 0 || identity.identity_generation == 0
        {
            return Err(PacketPathError::InvalidIdentity);
        }
        let base = identity
            .policy_base()
            .ok_or(PacketPathError::PolicyMismatch)?;
        #[cfg(feature = "openssl-inner-tls")]
        if identity
            .policy()
            .is_none_or(|policy| policy.net_id() != identity.net_id)
        {
            return Err(PacketPathError::PolicyMismatch);
        }
        let vip = permanent_vip(base, identity.node_id, identity.role)
            .ok_or(PacketPathError::InvalidPermanentSlot)?;
        Ok(Self {
            net_id: identity.net_id,
            node_id: identity.node_id,
            identity_generation: identity.identity_generation,
            role: identity.role,
            vip,
            #[cfg(feature = "openssl-inner-tls")]
            policy_digest: identity
                .policy()
                .ok_or(PacketPathError::PolicyMismatch)?
                .policy_digest(),
        })
    }
}

/// The permanent IPv4 slot for a verified `(node_id, role)`, or `None` when the
/// pair is not a canonical permanent slot.
fn permanent_vip(base: [u8; 4], node_id: u16, role: NodeRole) -> Option<Ipv4Addr> {
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

/// Derive a common private /16 from two policy-model endpoints. This pure
/// helper grants no authentication; the business path obtains both addresses
/// from the circuit's verified identities before calling it.
fn base_from_endpoints(local: Ipv4Addr, peer: Ipv4Addr) -> Result<[u8; 4], PacketPathError> {
    if !is_permanent_vip(local) || !is_permanent_vip(peer) {
        return Err(PacketPathError::InvalidEndpointVip);
    }
    let local = local.octets();
    let peer = peer.octets();
    if local[..2] != peer[..2] {
        return Err(PacketPathError::InvalidEndpointVip);
    }
    Ok([local[0], local[1], 0, 0])
}

/// Whether the address is a canonical private overlay node slot, independent
/// of one deployment's network prefix. The circuit binds the actual base.
fn is_permanent_vip(address: Ipv4Addr) -> bool {
    let [first, second, home_core, vip_octet] = address.octets();
    let private = first == 10
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168);
    private && (1..=16).contains(&home_core) && (1..=251).contains(&vip_octet)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    /// Host stack to remote peer.
    HostToPeer,
    /// Remote peer to host stack.
    PeerToHost,
}

/// Pure L3 policy model for one signed permanent VIP pair.
///
/// This type performs no I/O, holds no capability and authorizes no traffic by
/// itself. [`PacketPath`] builds it only from an established circuit's verified
/// identities; it is public so the address rules can be reviewed and tested
/// against real packets without a TLS session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointToPoint {
    local: Ipv4Addr,
    peer: Ipv4Addr,
    mtu: usize,
}

impl PointToPoint {
    /// Build the policy for one exact permanent VIP pair and link MTU.
    ///
    /// Both addresses must be canonical permanent overlay VIPs and must differ:
    /// there is no way to express a subnet, a default route or a third address.
    pub fn try_new(local: Ipv4Addr, peer: Ipv4Addr, mtu: usize) -> Result<Self, PacketPathError> {
        Self::try_new_in(base_from_endpoints(local, peer)?, local, peer, mtu)
    }

    #[cfg(all(feature = "openssl-inner-tls", target_os = "linux"))]
    pub(crate) fn from_mesh_circuit(
        circuit: &E2eCircuit<'_>,
        mtu: usize,
    ) -> Result<Self, PacketPathError> {
        let endpoints = AuthorizedEndpoints::from_e2e_circuit(circuit)?;
        if mtu > usize::from(endpoints.mtu_cap) {
            return Err(PacketPathError::MtuOutOfRange);
        }
        Self::try_new(endpoints.local.vip, endpoints.peer.vip, mtu)
    }

    fn try_new_in(
        base: [u8; 4],
        local: Ipv4Addr,
        peer: Ipv4Addr,
        mtu: usize,
    ) -> Result<Self, PacketPathError> {
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err(PacketPathError::MtuOutOfRange);
        }
        if !is_permanent_vip(local) || !is_permanent_vip(peer) {
            return Err(PacketPathError::InvalidEndpointVip);
        }
        if local.octets()[..2] != base[..2] || peer.octets()[..2] != base[..2] {
            return Err(PacketPathError::InvalidEndpointVip);
        }
        if local == peer {
            return Err(PacketPathError::SelfPair);
        }
        Ok(Self { local, peer, mtu })
    }

    pub fn local_vip(&self) -> Ipv4Addr {
        self.local
    }

    pub fn peer_vip(&self) -> Ipv4Addr {
        self.peer
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Largest frame this policy can encode or accept.
    pub fn max_frame(&self) -> usize {
        FRAME_PREFIX_LEN + self.mtu
    }

    /// Validate and authorize one packet the host stack handed to the tunnel.
    ///
    /// The source must be the local permanent VIP and the destination the peer
    /// permanent VIP. Nothing else is authorized, in either address position.
    pub fn authorize_outbound(&self, packet: &[u8]) -> Result<PacketInfo, PacketDeny> {
        self.authorize_bytes(packet, Direction::HostToPeer)
            .map(InspectedPacket::info)
    }

    /// Validate and authorize one packet the peer delivered for the host stack.
    ///
    /// The source must be the peer permanent VIP and the destination the local
    /// permanent VIP.
    pub fn authorize_inbound(&self, packet: &[u8]) -> Result<PacketInfo, PacketDeny> {
        self.authorize_bytes(packet, Direction::PeerToHost)
            .map(InspectedPacket::info)
    }

    fn authorize_bytes<'packet>(
        &self,
        packet: &'packet [u8],
        direction: Direction,
    ) -> Result<InspectedPacket<'packet>, PacketDeny> {
        self.authorize_inspected(self.inspect_bytes(packet)?, direction)
    }

    fn inspect_bytes<'packet>(
        &self,
        packet: &'packet [u8],
    ) -> Result<InspectedPacket<'packet>, PacketDeny> {
        self.check_packet_envelope(packet)?;
        InspectedPacket::new(packet).map_err(PacketDeny::from)
    }

    fn authorize_host_read(&self, packet: &PacketRead<'_>) -> Result<PacketInfo, PacketDeny> {
        match packet {
            PacketRead::Bytes(bytes) => self.authorize_outbound(bytes),
            PacketRead::Inspected(packet) => {
                self.check_packet_envelope(packet.bytes())?;
                self.authorize_inspected(*packet, Direction::HostToPeer)
                    .map(InspectedPacket::info)
            }
        }
    }

    fn check_packet_envelope(&self, packet: &[u8]) -> Result<(), PacketDeny> {
        if packet.len() > self.mtu {
            return Err(PacketDeny::MtuExceeded);
        }
        let Some(&first) = packet.first() else {
            return Err(PacketDeny::EmptyPacket);
        };
        match first >> 4 {
            4 => Ok(()),
            6 => Err(PacketDeny::Ipv6NotNegotiated),
            _ => Err(PacketDeny::UnknownVersion),
        }
    }

    fn authorize_inspected<'packet>(
        &self,
        packet: InspectedPacket<'packet>,
        direction: Direction,
    ) -> Result<InspectedPacket<'packet>, PacketDeny> {
        let info = packet.info();
        if info.version != IpVersion::V4 {
            return Err(PacketDeny::Ipv6NotNegotiated);
        }
        match direction {
            Direction::HostToPeer => {
                if info.source != IpAddr::V4(self.local) {
                    return Err(PacketDeny::SourceNotLocal);
                }
                if info.destination != IpAddr::V4(self.peer) {
                    return Err(PacketDeny::DestinationNotPeer);
                }
            }
            Direction::PeerToHost => {
                if info.source != IpAddr::V4(self.peer) {
                    return Err(PacketDeny::SourceNotPeer);
                }
                if info.destination != IpAddr::V4(self.local) {
                    return Err(PacketDeny::DestinationNotLocal);
                }
            }
        }
        Ok(packet)
    }
}

/// Endpoints bound to one established E2E circuit.
///
/// Private fields and no public constructor. The only entrance is
/// [`AuthorizedEndpoints::from_e2e_circuit`], which reads the circuit's own
/// authenticated identities; an `E2eCircuit` can only be produced by the E2E
/// handshake plus the encrypted application confirmation.
///
/// The verified token a circuit carries has no facts of its own, so no separate
/// "token facts" check is claimed here: the identities are the circuit's.
#[derive(Debug)]
pub(crate) struct AuthorizedEndpoints {
    local: EndpointFacts,
    peer: EndpointFacts,
    circuit_id: [u8; 16],
    path_hops: u8,
    mtu_cap: u16,
}

impl AuthorizedEndpoints {
    /// Bind the circuit's own authenticated identities to their permanent VIPs.
    fn from_e2e_circuit(circuit: &E2eCircuit<'_>) -> Result<Self, PacketPathError> {
        let info = circuit.info();
        Self::bind(
            info.circuit_id,
            info.path_hops,
            info.peer,
            circuit.local(),
            circuit.mtu_cap(),
        )
    }

    /// Check the same signed endpoint binding before L3 capability confirmation.
    #[cfg(feature = "openssl-inner-tls")]
    pub(crate) fn confirmation_policy_digest(
        circuit_id: [u8; 16],
        path_hops: u8,
        peer: PeerIdentity,
        local: PeerIdentity,
        mtu_cap: u16,
    ) -> Result<[u8; 32], PacketPathError> {
        let endpoints = Self::bind(circuit_id, path_hops, peer, local, mtu_cap)?;
        Ok(endpoints.local.policy_digest)
    }

    fn bind(
        circuit_id: [u8; 16],
        path_hops: u8,
        peer: PeerIdentity,
        local: PeerIdentity,
        mtu_cap: u16,
    ) -> Result<Self, PacketPathError> {
        if circuit_id == [0; 16] || path_hops == 0 || path_hops > MAX_RELAY_HOPS {
            return Err(PacketPathError::CircuitMismatch);
        }
        // Slot validity is a property of one identity, not of the pair. A Core
        // that claims an Edge octet is `InvalidPermanentSlot` even when the
        // other endpoint happens to carry the same node id.
        let local = EndpointFacts::from_verified_identity(local)?;
        let peer = EndpointFacts::from_verified_identity(peer)?;
        if local.net_id != peer.net_id || local.node_id == peer.node_id {
            return Err(PacketPathError::IdentityMismatch);
        }
        #[cfg(feature = "openssl-inner-tls")]
        if local.policy_digest != peer.policy_digest {
            return Err(PacketPathError::PolicyMismatch);
        }
        if local.vip == peer.vip {
            return Err(PacketPathError::SelfPair);
        }
        Ok(Self {
            local,
            peer,
            circuit_id,
            path_hops,
            mtu_cap,
        })
    }
}

/// Encode one packet as one length-prefixed frame.
///
/// Candidate encoding: a big-endian `u16` packet length followed by exactly that
/// many bytes, nothing else. One frame carries exactly one packet.
pub fn encode_packet_frame(packet: &[u8], mtu: usize) -> Result<Vec<u8>, PacketPathError> {
    let prefix = packet_frame_prefix(packet, mtu)?;
    let mut frame = Vec::with_capacity(FRAME_PREFIX_LEN + packet.len());
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(packet);
    Ok(frame)
}

fn packet_frame_prefix(
    packet: &[u8],
    mtu: usize,
) -> Result<[u8; FRAME_PREFIX_LEN], PacketPathError> {
    if packet.is_empty() {
        return Err(PacketPathError::Denied(PacketDeny::EmptyPacket));
    }
    if packet.len() > mtu || packet.len() > MAX_MTU {
        return Err(PacketPathError::Denied(PacketDeny::MtuExceeded));
    }
    let length = u16::try_from(packet.len())
        .map_err(|_| PacketPathError::Denied(PacketDeny::MtuExceeded))?;
    Ok(length.to_be_bytes())
}

/// Encode one packet into caller-provided storage and return its exact frame size.
fn encode_packet_frame_into(
    packet: &[u8],
    mtu: usize,
    frame: &mut [u8],
) -> Result<usize, PacketPathError> {
    let prefix = packet_frame_prefix(packet, mtu)?;
    let frame_len = FRAME_PREFIX_LEN + packet.len();
    if frame.len() < frame_len {
        return Err(PacketPathError::Denied(PacketDeny::MtuExceeded));
    }
    frame[..FRAME_PREFIX_LEN].copy_from_slice(&prefix);
    frame[FRAME_PREFIX_LEN..frame_len].copy_from_slice(packet);
    Ok(frame_len)
}

/// Decode exactly one length-prefixed frame back to its single packet.
///
/// Rejects an empty frame, a frame that declares more than the MTU, and any
/// trailing or missing bytes, so a frame can never be reinterpreted as a packet
/// boundary shift.
pub fn decode_packet_frame(frame: &[u8], mtu: usize) -> Result<&[u8], PacketPathError> {
    if frame.len() < FRAME_PREFIX_LEN {
        return Err(PacketPathError::TruncatedFrame);
    }
    let length = usize::from(u16::from_be_bytes([frame[0], frame[1]]));
    if length == 0 {
        return Err(PacketPathError::EmptyFrame);
    }
    if length > mtu {
        return Err(PacketPathError::FrameTooLarge);
    }
    let body = &frame[FRAME_PREFIX_LEN..];
    if body.len() != length {
        return Err(PacketPathError::FrameLengthMismatch);
    }
    Ok(body)
}

fn circuit_io(error: io::Error) -> PacketPathError {
    // Nested stream adapters can carry a typed protocol rejection inside
    // InvalidData. Unwrap the verified type before deciding whether fallback
    // is allowed; never promote on an unknown TLS alert or framing error.
    match TunnelError::from(error) {
        TunnelError::Io(kind) | TunnelError::Ws(WsError::Io(kind)) => {
            PacketPathError::CircuitIo(kind)
        }
        TunnelError::Timeout | TunnelError::Ws(WsError::Timeout) => {
            PacketPathError::CircuitIo(io::ErrorKind::TimedOut)
        }
        TunnelError::Closed | TunnelError::Ws(WsError::Closed) => {
            PacketPathError::CircuitIo(io::ErrorKind::UnexpectedEof)
        }
        _ => PacketPathError::CircuitProtocol,
    }
}

/// Read one frame's 2-byte prefix.
///
/// `Ok(false)` means the stream ended cleanly before a frame started. A stream
/// that ends after one prefix byte is a truncated frame, not a clean close.
fn read_prefix<C: Read + ?Sized>(
    circuit: &mut C,
    prefix: &mut [u8; FRAME_PREFIX_LEN],
) -> Result<bool, PacketPathError> {
    let mut filled = 0;
    let mut interrupts = 0u8;
    while filled < FRAME_PREFIX_LEN {
        let target = &mut prefix[filled..FRAME_PREFIX_LEN];
        match circuit.read(target) {
            Ok(0) => {
                return if filled == 0 {
                    Ok(false)
                } else {
                    Err(PacketPathError::TruncatedFrame)
                };
            }
            Ok(read) => {
                filled += read;
                interrupts = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupts = interrupts.saturating_add(1);
                if interrupts >= MAX_INTERRUPT_RETRIES {
                    return Err(PacketPathError::CircuitIo(io::ErrorKind::Interrupted));
                }
            }
            Err(error) => return Err(circuit_io(error)),
        }
    }
    Ok(true)
}

/// Distinguish a complete or immediately rejectable frame from a prefix
/// which would need another blocking read.
fn prefetched_frame_ready(bytes: &[u8], mtu: usize) -> bool {
    let [hi, lo, rest @ ..] = bytes else { return false; };
    let len = usize::from(u16::from_be_bytes([*hi, *lo]));
    // An invalid length is immediately actionable; never defer its rejection.
    len == 0 || len > mtu || rest.len() >= len
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundClass { Host, CoreDns, EdgeDns }

/// One rule for copied and borrowed ingress. Classification is not authority:
/// DNS leases/transactions are still checked by the original dispatchers.
fn classify_inbound(
    policy: &PointToPoint,
    packet: InspectedPacket<'_>,
    core_dns: Option<Ipv4Addr>,
    edge_dns: Option<Ipv4Addr>,
    replica_only: bool,
) -> Result<InboundClass, PacketPathError> {
    let info = packet.info();
    if core_dns.is_some_and(|vip| info.destination == IpAddr::V4(vip)) {
        if info.source != IpAddr::V4(policy.peer_vip()) {
            return Err(PacketPathError::Denied(PacketDeny::SourceNotPeer));
        }
        return Ok(InboundClass::CoreDns);
    }
    if edge_dns.is_some_and(|vip| info.source == IpAddr::V4(vip)) {
        if info.destination != IpAddr::V4(policy.local_vip()) {
            return Err(PacketPathError::Denied(PacketDeny::DestinationNotLocal));
        }
        return Ok(InboundClass::EdgeDns);
    }
    if replica_only {
        return Err(PacketPathError::Denied(PacketDeny::NotDnsTraffic));
    }
    Ok(InboundClass::Host)
}

/// None means a refill or the original DNS dispatcher is required. In either
/// case the plaintext cursor has not moved. Errors never consume bytes.
fn deliver_prefetched_classified<P: PacketIo + ?Sized>(
    io: &P,
    policy: &PointToPoint,
    bytes: &[u8],
    core_dns: Option<Ipv4Addr>,
    edge_dns: Option<Ipv4Addr>,
    replica_only: bool,
) -> Option<Result<(usize, usize), PacketPathError>> {
    let [hi, lo, rest @ ..] = bytes else {
        return None;
    };
    let length = usize::from(u16::from_be_bytes([*hi, *lo]));
    if length == 0 {
        return Some(Err(PacketPathError::EmptyFrame));
    }
    if length > policy.mtu() {
        return Some(Err(PacketPathError::FrameTooLarge));
    }
    if rest.len() < length {
        return None;
    }
    let packet = match policy.inspect_bytes(&rest[..length]).map_err(PacketPathError::Denied) {
        Ok(packet) => packet,
        Err(error) => return Some(Err(error)),
    };
    match classify_inbound(policy, packet, core_dns, edge_dns, replica_only) {
        Err(error) => Some(Err(error)),
        Ok(InboundClass::CoreDns | InboundClass::EdgeDns) => None,
        Ok(InboundClass::Host) => Some(
            deliver_inspected_host_packet(io, policy, packet)
                .map(|length| (FRAME_PREFIX_LEN + length, length)),
        ),
    }
}

#[cfg(test)]
fn deliver_prefetched<P: PacketIo + ?Sized>(
    io: &P, policy: &PointToPoint, bytes: &[u8],
) -> Option<Result<(usize, usize), PacketPathError>> {
    deliver_prefetched_classified(io, policy, bytes, None, None, false)
}

fn deliver_inspected_host_packet<P: PacketIo + ?Sized>(
    io: &P,
    policy: &PointToPoint,
    packet: InspectedPacket<'_>,
) -> Result<usize, PacketPathError> {
    let packet = policy
        .authorize_inspected(packet, Direction::PeerToHost)
        .map_err(PacketPathError::Denied)?;
    io.write_inspected_packet(packet)
        .map_err(PacketPathError::from_host_error)?;
    Ok(packet.info().packet_len)
}

/// Read one whole frame into caller-provided storage and return whether a
/// frame was present (`Ok(false)` on clean EOF at a frame boundary).
fn read_packet_frame_into<C: Read + ?Sized>(
    circuit: &mut C,
    mtu: usize,
    packet: &mut Vec<u8>,
) -> Result<bool, PacketPathError> {
    let mut prefix = [0u8; FRAME_PREFIX_LEN];
    if !read_prefix(circuit, &mut prefix)? {
        return Ok(false);
    }
    let length = usize::from(u16::from_be_bytes(prefix));
    if length == 0 {
        return Err(PacketPathError::EmptyFrame);
    }
    if length > mtu {
        return Err(PacketPathError::FrameTooLarge);
    }
    // The allocation is bounded by the negotiated MTU and happens only after the
    // declared length has been checked.
    packet.resize(length, 0);
    read_exact_bounded(circuit, packet)?;
    Ok(true)
}

/// A single-owner adapter between one host-side packet endpoint and one
/// established E2E circuit.
///
/// The public constructor [`PacketPath::try_new_over_e2e`] owns the circuit, so
/// dropping the path drops the circuit (and its stream). Every failure and every
/// clean peer close additionally drops the circuit **immediately**, inside the
/// step that observed it: the path holds it in an `Option` and clears it, so a
/// caller that forgets to drop the path cannot leave an authenticated E2E stream
/// usable. After the first failure or close, no step succeeds in either
/// direction, and no failure is retried, reclassed or delivered on another path.
///
/// This type is real and usable, but it is **not** wired to status freshness and
/// must not be enabled for production business traffic in this slice.
pub struct PacketPath<'a, C, P: ?Sized> {
    io: &'a P,
    /// `None` once the path is closed or poisoned. The circuit stream is dropped
    /// at that moment, so a closed or failed adapter cannot keep an authenticated
    /// E2E connection (and its TLS/buffer resources) alive.
    circuit: Option<C>,
    endpoints: AuthorizedEndpoints,
    policy: PointToPoint,
    state: PathState,
    stats: PacketStats,
    outbound_batch: Vec<u8>,
    // One initialized high-water allocation; only `used` bytes may be sent.
    outbound_inline: Vec<u8>,
    // Linux TUN may truncate to the supplied read length; reserve a guard byte.
    outbound_scratch: [u8; MAX_MTU + 1],
    inbound_scratch: Vec<u8>,
    #[cfg(feature = "openssl-inner-tls")]
    private_dns: Option<PrivateDns<'a>>,
    #[cfg(feature = "openssl-inner-tls")]
    edge_dns: Option<EdgeDns<'a>>,
    #[cfg(feature = "openssl-inner-tls")]
    dns_replica_only: bool,
}

#[cfg(feature = "openssl-inner-tls")]
type DnsLiveness<'a> = Box<dyn Fn() -> bool + Send + Sync + 'a>;

/// Explicit opt-in for the single Core's private IPv4 DNS responder.
/// These inputs must be selected and pinned by the E2E owner, not the peer.
#[cfg(feature = "openssl-inner-tls")]
pub struct PrivateDnsProvision<'a> {
    pub material: dns_packet_service::Material<'a>,
    pub tcp: bool,
    pub public: Option<dns_packet_service::PublicForward>,
    /// Fresh UTC Unix microseconds, or `None` on clock failure.
    pub utc: Box<dyn Fn() -> Option<u64> + Send + Sync + 'a>,
    /// Nonblocking gate for this circuit, both identities, and the exact
    /// selected policy/signer/authority versions, including revocation and
    /// rollback protection. Must include the owner's business deadline.
    pub is_current: Box<dyn Fn() -> bool + Send + Sync + 'a>,
}

/// Explicit Edge route context, owned by the one admitted circuit. The caller
/// pins the signed zone and supplies its current status/revocation/lease gate.
#[cfg(feature = "openssl-inner-tls")]
struct EdgeDns<'a> {
    vip: Ipv4Addr,
    zone: &'a str,
    public: bool,
    current: DnsLiveness<'a>,
    pending: std::collections::VecDeque<EdgeQuery>,
    tcp: Option<EdgeTcpFlows>,
}

#[cfg(feature = "openssl-inner-tls")]
struct EdgeQuery {
    sent: Instant,
    port: u16,
    question: boreas_dns::PrivateQuestion,
}

#[cfg(feature = "openssl-inner-tls")]
impl EdgeDns<'_> {
    const MAX_PENDING: usize = 64;
    const REPLY_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);

    fn remember(&mut self, port: u16, question: boreas_dns::PrivateQuestion) {
        let pending = &mut self.pending;
        pending.retain(|p| {
            p.sent.elapsed() < Self::REPLY_WINDOW && (p.port != port || p.question != question)
        });
        if pending.len() == Self::MAX_PENDING {
            pending.pop_front();
        }
        pending.push_back(EdgeQuery {
            sent: Instant::now(),
            port,
            question,
        });
    }

    fn take_reply(&mut self, port: u16, question: &boreas_dns::PrivateQuestion) -> bool {
        let pending = &mut self.pending;
        pending.retain(|p| p.sent.elapsed() < Self::REPLY_WINDOW);
        let index = pending
            .iter()
            .position(|p| p.port == port && &p.question == question);
        index.and_then(|i| pending.remove(i)).is_some()
    }

    fn check(&self) -> Result<(), PacketPathError> {
        if (self.current)() {
            Ok(())
        } else {
            Err(PacketPathError::DnsAuthorizationLost)
        }
    }
}

// Match an Edge-originated TCP tuple, not individual packets to DNS messages.
// Linux and smoltcp own TCP sequence/ACK validation and stream reassembly.
// This table only limits which ports on the authenticated Edge are reachable
// from the authenticated DNS VIP. No state is created by inbound packets.
#[cfg(feature = "openssl-inner-tls")]
#[derive(Default)]
struct EdgeTcpFlows(std::collections::VecDeque<(u16, Instant)>);

#[cfg(feature = "openssl-inner-tls")]
impl EdgeTcpFlows {
    const CAPACITY: usize = 64;
    const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(75);

    fn expire(&mut self) {
        self.0.retain(|(_, opened)| opened.elapsed() < Self::MAX_AGE);
    }

    fn outbound(&mut self, client: u16, flags: u8) -> bool {
        self.expire();
        let position = self.0.iter().position(|&(port, _)| port == client);
        if flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN) == TCP_SYN {
            if let Some(index) = position {
                self.0.remove(index);
            } else if self.0.len() == Self::CAPACITY {
                self.0.pop_front();
            }
            self.0.push_back((client, Instant::now()));
            return true;
        }
        if let Some(index) = position {
            if flags & TCP_RST != 0 {
                self.0.remove(index);
            }
            return true;
        }
        false
    }

    fn inbound(&mut self, client: u16, flags: u8) -> bool {
        self.expire();
        // Do not deliver an unsolicited server-side open, even on a known port.
        if flags & (TCP_SYN | TCP_ACK) == TCP_SYN {
            return false;
        }
        self.0.iter().any(|&(port, _)| port == client)
    }
}

#[cfg(feature = "openssl-inner-tls")]
const TCP_FIN: u8 = 0x01;
#[cfg(feature = "openssl-inner-tls")]
const TCP_SYN: u8 = 0x02;
#[cfg(feature = "openssl-inner-tls")]
const TCP_RST: u8 = 0x04;
#[cfg(feature = "openssl-inner-tls")]
const TCP_ACK: u8 = 0x10;

#[cfg(feature = "openssl-inner-tls")]
struct PrivateDns<'a> {
    service: DnsPacketService<DnsLiveness<'a>>,
    tcp: bool,
    deferred: bool,
    utc: Box<dyn Fn() -> Option<u64> + Send + Sync + 'a>,
}

#[cfg(feature = "openssl-inner-tls")]
impl PrivateDns<'_> {
    fn live_utc(&mut self) -> Result<u64, PacketPathError> {
        (self.utc)()
            .filter(|&now| self.service.check_live(now))
            .ok_or(PacketPathError::DnsAuthorizationLost)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathState {
    Open,
    /// The peer closed the circuit cleanly (or the owner closed the path): normal
    /// termination, not a failure.
    Closed,
    Poisoned(PacketPathError),
}

/// Counters for one path. Whole numbers of packets and bytes only: no payload.
///
/// `failures` counts steps that failed closed (per-packet policy denials and I/O
/// failures alike); a clean close is not counted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketStats {
    pub outbound_packets: u64,
    pub outbound_bytes: u64,
    pub inbound_packets: u64,
    pub inbound_bytes: u64,
    pub failures: u64,
    /// Host packets that were structurally readable but not authorized for the
    /// peer. They are discarded locally; they do not cross the circuit and do
    /// not close it.
    pub dropped_outbound: u64,
}

impl<'a, P: PacketIo + ?Sized> PacketPath<'a, E2eCircuit<'a>, P> {
    /// Bind an established E2E circuit to the host-side packet endpoint.
    ///
    /// This is the business constructor with DNS disabled. It consumes the circuit by value
    /// and derives both endpoints from the circuit's own authenticated identities
    /// (`E2eCircuit::local` and `E2eCircuit::info`). A hop-only or plaintext
    /// session cannot satisfy the parameter type.
    ///
    /// `mtu` is the link MTU chosen by the runtime owner; it must be in
    /// `MIN_MTU..=MAX_MTU` and must not exceed the circuit's negotiated MTU cap.
    /// Status freshness is not integrated into this adapter: it holds the
    /// borrowed `PacketIo` and the owned `E2eCircuit`, exchanges packets one at a
    /// time, and consults no durable status, revocation or clock state. The
    /// daemon owner must gate this construction on a real verified status
    /// capability before any business traffic is enabled.
    pub fn try_new_over_e2e(
        io: &'a P,
        circuit: E2eCircuit<'a>,
        mtu: usize,
    ) -> Result<Self, PacketPathError> {
        let endpoints = AuthorizedEndpoints::from_e2e_circuit(&circuit)?;
        #[cfg(feature = "openssl-inner-tls")]
        let only_dns = circuit.is_private_dns_only();
        let path = Self::try_new(io, circuit, endpoints, mtu)?;
        #[cfg(feature = "openssl-inner-tls")]
        let path = Self { dns_replica_only: only_dns, ..path };
        Ok(path)
    }

    /// Bind private DNS to this exact authenticated Core–Edge circuit, using
    /// the chosen path MTU rather than the hop's ceiling. The ordinary
    /// constructor never enables DNS, and this constructor fails on bad grants.
    #[cfg(feature = "openssl-inner-tls")]
    pub fn try_new_over_e2e_with_private_dns(
        io: &'a P,
        circuit: E2eCircuit<'a>,
        mtu: usize,
        provision: PrivateDnsProvision<'a>,
    ) -> Result<Self, PacketPathError> {
        let mut path = Self::try_new_over_e2e(io, circuit, mtu)?;
        let started = Instant::now();
        let now = (provision.utc)().ok_or(PacketPathError::DnsAuthorizationLost)?;
        let deferred = provision.tcp || provision.public.is_some();
        let service = DnsPacketService::try_new_for_path(
            dns_packet_service::Config { enabled: true, tcp: provision.tcp },
            path.circuit.as_ref().ok_or(PacketPathError::Closed)?,
            mtu,
            provision.material,
            started,
            now,
            provision.public,
            provision.is_current,
        )
        .map_err(PacketPathError::DnsBind)?
        .ok_or(PacketPathError::DnsAuthorizationLost)?;
        path.private_dns = Some(PrivateDns {
            service,
            tcp: provision.tcp,
            deferred,
            utc: provision.utc,
        });
        Ok(path)
    }

    /// Opt one Edge–Core E2E path into private DNS. Nothing changes in
    /// the normal permanent VIP pair, and there is no peer discovery/failover.
    #[cfg(feature = "openssl-inner-tls")]
    pub fn try_new_over_e2e_with_edge_dns(
        io: &'a P,
        circuit: E2eCircuit<'a>,
        mtu: usize,
        authority: &'a boreas_pki::dns_authority::VerifiedDnsAuthority,
        tcp: bool,
        public: bool,
        is_current: Box<dyn Fn() -> bool + Send + Sync + 'a>,
    ) -> Result<Self, PacketPathError> {
        let context = circuit
            .local()
            .policy()
            .ok_or(PacketPathError::PolicyMismatch)?;
        if circuit.local().role != NodeRole::Edge
            || circuit.info().peer.role != NodeRole::Core
            || context.net_id() != authority.net_id()
            || context.policy_digest() != authority.policy_digest()
        {
            return Err(PacketPathError::PolicyMismatch);
        }
        let [a, b, _, _] = context.overlay_base();
        let dns = EdgeDns {
            vip: Ipv4Addr::new(a, b, 0, 53),
            zone: authority.zone(),
            public,
            current: is_current,
            pending: Default::default(),
            tcp: tcp.then(EdgeTcpFlows::default),
        };
        dns.check()?;
        let mut path = Self::try_new_over_e2e(io, circuit, mtu)?;
        path.edge_dns = Some(dns);
        Ok(path)
    }

    /// Enable only after role, DNS lease and replica binding are final. This
    /// is also the assembly entry used by daemon regression tests.
    pub fn configure_direct_read_ahead(
        &mut self, real_tun: bool, replica_epoch: bool, admission: &crate::resource::Admission,
    ) -> bool {
        #[cfg(feature = "openssl-inner-tls")]
        if self.dns_replica_only { return false; }
        self.circuit.as_mut().is_some_and(|circuit| {
            circuit.direct_read_ahead_eligible(real_tun, replica_epoch)
                && circuit.enable_direct_read_ahead_admitted(admission)
        })
    }

    /// Whether inbound bytes are buffered above the raw outer TCP socket.
    /// The daemon combines this with socket readiness before entering a
    /// blocking frame read, avoiding both arbitrary sleeps and missed TLS data.
    pub fn has_buffered_input(&self) -> bool {
        self.circuit
            .as_ref()
            .is_some_and(E2eCircuit::has_buffered_input)
    }

    /// Whether the next packet can be handled without refilling E2E plaintext.
    /// `None` means this circuit does not use the optional direct prefetcher.
    pub fn prefetched_frame_ready(&self) -> Option<bool> {
        self.circuit
            .as_ref()?
            .prefetched_plaintext()
            .map(|bytes| prefetched_frame_ready(bytes, self.policy.mtu()))
    }

    /// Deliver one already-complete ordinary packet directly from the E2E
    /// plaintext buffer. DNS and partial frames keep the original path. The
    /// caller's per-packet stop/revocation checks remain outside this call.
    pub fn step_inbound_prefetched(&mut self) -> Result<Option<usize>, PacketPathError> {
        self.check_open()?;
        // Dedicated replica streams retain authenticated-EOF reads unchanged.
        #[cfg(feature = "openssl-inner-tls")]
        if self.dns_replica_only {
            return self.step_inbound();
        }
        #[cfg(feature = "openssl-inner-tls")]
        let (core_dns, edge_dns) = (
            self.private_dns.as_ref().map(|dns| dns.service.dns_vip()),
            self.edge_dns.as_ref().map(|dns| dns.vip),
        );
        #[cfg(not(feature = "openssl-inner-tls"))]
        let (core_dns, edge_dns) = (None, None);
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        let mut interrupts = 0;
        loop {
            match circuit.fill_prefetched_plaintext() {
                crate::e2e::PrefetchFill::Disabled => return self.step_inbound(),
                crate::e2e::PrefetchFill::CleanEof => {
                    self.close();
                    return Ok(None);
                }
                crate::e2e::PrefetchFill::Error(error)
                    if error.kind() == io::ErrorKind::Interrupted => {
                        interrupts += 1;
                        if interrupts == MAX_INTERRUPT_RETRIES {
                            return Err(self.fail(circuit_io(error)));
                        }
                    }
                crate::e2e::PrefetchFill::Error(error) => {
                    return Err(self.fail(circuit_io(error)));
                }
                crate::e2e::PrefetchFill::HasBytes => break,
            }
        }
        let result = circuit
            .prefetched_plaintext()
            .and_then(|bytes| deliver_prefetched_classified(
                self.io, &self.policy, bytes, core_dns, edge_dns, false,
            ));
        match result {
            None => self.step_inbound(),
            Some(Err(error)) => Err(self.fail(error)),
            Some(Ok((used, length))) => {
                if !circuit.consume_prefetched_plaintext(used) {
                    return Err(self.fail(PacketPathError::Poisoned));
                }
                self.stats.inbound_packets = self.stats.inbound_packets.saturating_add(1);
                self.stats.inbound_bytes = self.stats.inbound_bytes.saturating_add(length as u64);
                Ok(Some(length))
            }
        }
    }

    /// Close the path after telling the peer: TLS `close_notify`, then the
    /// circuit's own `CircuitClose`, then the stream is dropped.
    ///
    /// A planned stop (a time or packet budget running out) must use this
    /// rather than [`Self::close`]. Dropping the TLS record layer without
    /// `close_notify` makes the peer read a truncated record and fail closed,
    /// which is the right outcome for an error and the wrong one for a stop the
    /// owner chose. Best-effort: a peer that is already gone does not turn the
    /// local stop into a failure.
    pub fn close_gracefully(&mut self) {
        if matches!(self.state, PathState::Open) {
            self.state = PathState::Closed;
        }
        if let Some(circuit) = self.circuit.as_mut() {
            circuit.close_gracefully();
        }
        self.circuit = None;
        #[cfg(feature = "openssl-inner-tls")]
        {
            self.private_dns = None;
            self.edge_dns = None;
        }
    }
}

impl<'a, C: Read + Write, P: PacketIo + ?Sized> PacketPath<'a, C, P> {
    /// Inner constructor used after the capability binding succeeded.
    pub(crate) fn try_new(
        io: &'a P,
        circuit: C,
        endpoints: AuthorizedEndpoints,
        mtu: usize,
    ) -> Result<Self, PacketPathError> {
        if mtu > usize::from(endpoints.mtu_cap) {
            return Err(PacketPathError::MtuAboveCircuitCap);
        }
        let policy = PointToPoint::try_new_in(
            base_from_endpoints(endpoints.local.vip, endpoints.peer.vip)?,
            endpoints.local.vip,
            endpoints.peer.vip,
            mtu,
        )?;
        Ok(Self {
            io,
            circuit: Some(circuit),
            endpoints,
            policy,
            state: PathState::Open,
            stats: PacketStats::default(),
            outbound_batch: Vec::new(),
            outbound_inline: Vec::new(),
            // Keep this independent of the path MTU: the host adapter must read
            // at its own MTU, then policy checks the complete packet below.
            outbound_scratch: [0; MAX_MTU + 1],
            inbound_scratch: Vec::new(),
            #[cfg(feature = "openssl-inner-tls")]
            private_dns: None,
            #[cfg(feature = "openssl-inner-tls")]
            edge_dns: None,
            #[cfg(feature = "openssl-inner-tls")]
            dns_replica_only: false,
        })
    }

    /// The authenticated local endpoint of this circuit.
    pub fn local_endpoint(&self) -> EndpointFacts {
        self.endpoints.local
    }

    /// The authenticated peer endpoint of this circuit.
    pub fn peer_endpoint(&self) -> EndpointFacts {
        self.endpoints.peer
    }

    /// The circuit id this path is bound to.
    pub fn circuit_id(&self) -> [u8; 16] {
        self.endpoints.circuit_id
    }

    /// The declared circuit length in hop links.
    pub fn path_hops(&self) -> u8 {
        self.endpoints.path_hops
    }

    /// The link MTU this path enforces.
    pub fn mtu(&self) -> usize {
        self.policy.mtu()
    }

    pub fn stats(&self) -> PacketStats {
        self.stats
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, PathState::Open)
    }

    /// The first failure that poisoned this path, if any.
    ///
    /// A cleanly closed path returns `None`: normal termination is reported
    /// through `Ok(None)` from the step that observed it and through
    /// [`PacketPath::is_open`], not as an error.
    pub fn first_error(&self) -> Option<PacketPathError> {
        match self.state {
            PathState::Open | PathState::Closed => None,
            PathState::Poisoned(reason) => Some(reason),
        }
    }

    /// The hop session's negotiated MTU ceiling this path was bound to.
    pub fn mtu_cap(&self) -> u16 {
        self.endpoints.mtu_cap
    }

    /// Close the path and release the circuit stream immediately.
    ///
    /// Idempotent, and not counted as a failure. The owned circuit is dropped
    /// here rather than left to the caller, so a closed adapter cannot keep an
    /// authenticated E2E stream alive. Dropping that stream is the existing
    /// circuit teardown (its `CircuitStream` drop sends a best-effort reset);
    /// this method does not claim to suppress it. A planned stop that must tell
    /// the peer first uses [`Self::close_gracefully`] on the E2E specialization.
    pub fn close(&mut self) {
        if matches!(self.state, PathState::Open) {
            self.state = PathState::Closed;
        }
        self.circuit = None;
        #[cfg(feature = "openssl-inner-tls")]
        {
            self.private_dns = None;
            self.edge_dns = None;
        }
    }

    /// Read one packet from the host stack and send it to the peer.
    ///
    /// `Ok(None)` means no packet was available and the path stays open. Exactly
    /// one packet is read, authorized, framed and written per call; a partial
    /// write poisons the path and drops the circuit.
    pub fn step_outbound(&mut self) -> Result<Option<usize>, PacketPathError> {
        self.check_open()?;
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        match outbound_once(
            self.io,
            circuit,
            &self.policy,
            &mut self.outbound_scratch,
            #[cfg(feature = "openssl-inner-tls")]
            self.edge_dns.as_mut(),
            #[cfg(feature = "openssl-inner-tls")]
            self.dns_replica_only,
        ) {
            Ok(Some(length)) => {
                self.stats.outbound_packets = self.stats.outbound_packets.saturating_add(1);
                self.stats.outbound_bytes = self
                    .stats
                    .outbound_bytes
                    .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
                Ok(Some(length))
            }
            Ok(None) => Ok(None),
            Err(PacketPathError::Denied(reason)) if reason.is_local_discard() => {
                // Host configuration traffic is not evidence that the
                // authenticated circuit failed. Do not frame it or close.
                self.stats.dropped_outbound = self.stats.dropped_outbound.saturating_add(1);
                Ok(None)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Drain up to `max_packets` currently-ready host packets (stopping
    /// immediately when the host read returns `None` or buffered bytes reach
    /// `max_bytes`), frame them contiguously, and emit them in a single E2E
    /// stream write + flush. Zero coalescing timer is used (§6.4).
    ///
    /// Returns the number of packets delivered to the circuit (`0` if none).
    pub fn step_outbound_batch(
        &mut self,
        max_packets: usize,
        max_bytes: usize,
    ) -> Result<usize, PacketPathError> {
        // Preserve the old unbounded-API behavior for callers above the
        // production single-record threshold; ordinary daemon batches use
        // the bounded direct-read storage below.
        if max_bytes > INLINE_BATCH_THRESHOLD {
            return self.step_outbound_batch_legacy(max_packets, max_bytes);
        }
        self.check_open()?;
        if max_packets == 0 || max_bytes == 0 {
            return Ok(0);
        }
        if self.outbound_inline.is_empty() {
            self.outbound_inline.resize(INLINE_BATCH_STORAGE, 0);
        }
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        let mut used = 0usize;
        let mut drained = 0usize;
        let mut payload_bytes = 0u64;
        let mut attempts = 0usize;
        let max_attempts = max_packets.saturating_mul(2);
        let mut failure = None;
        #[cfg(feature = "openssl-inner-tls")]
        let mut contains_dns = false;
        while drained < max_packets && used < max_bytes && attempts < max_attempts {
            attempts += 1;
            let body_start = used + FRAME_PREFIX_LEN;
            // Full adapter MTU plus guard, not just remaining frame budget.
            let target = &mut self.outbound_inline[body_start..body_start + MAX_MTU + 1];
            let target_ptr = target.as_ptr();
            let packet = match self.io.read_for_forwarding(target) {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(error) => {
                    failure = Some(PacketPathError::from_host_error(error));
                    break;
                }
            };
            let bytes = packet.as_ref();
            let authorized = authorize_outbound_read(
                &self.policy,
                &packet,
                #[cfg(feature = "openssl-inner-tls")]
                self.edge_dns.as_mut(),
                #[cfg(feature = "openssl-inner-tls")]
                self.dns_replica_only,
            );
            match authorized {
                Ok(info) => {
                    #[cfg(feature = "openssl-inner-tls")]
                    if self
                        .edge_dns
                        .as_ref()
                        .is_some_and(|dns| info.destination == IpAddr::V4(dns.vip))
                    {
                        contains_dns = true;
                    }
                    let prefix = match packet_frame_prefix(bytes, self.policy.mtu()) {
                        Ok(prefix) => prefix,
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    };
                    let packet_len = bytes.len();
                    // Borrow-capable TUNs already filled this exact region.
                    // Owned/foreign adapters retain the legacy one-copy path.
                    let fallback = if bytes.as_ptr() == target_ptr {
                        None
                    } else {
                        Some(match packet {
                            PacketRead::Bytes(std::borrow::Cow::Owned(bytes)) => bytes,
                            other => other.as_ref().to_vec(),
                        })
                    };
                    if let Some(bytes) = fallback {
                        self.outbound_inline[body_start..body_start + packet_len]
                            .copy_from_slice(&bytes);
                    }
                    self.outbound_inline[used..body_start].copy_from_slice(&prefix);
                    used = body_start + packet_len;
                    drained += 1;
                    payload_bytes = payload_bytes
                        .saturating_add(u64::try_from(info.packet_len).unwrap_or(u64::MAX));
                }
                Err(deny) if deny.is_local_discard() => {
                    self.stats.dropped_outbound = self.stats.dropped_outbound.saturating_add(1);
                }
                Err(deny) => {
                    failure = Some(PacketPathError::Denied(deny));
                    break;
                }
            }
        }
        #[cfg(any(test, feature = "record-diagnostics"))]
        {
            use crate::record_diagnostics::{BatchExit, observe_batch};
            let exit = if failure.is_some() {
                BatchExit::Fatal
            } else if drained >= max_packets {
                BatchExit::PacketBudget
            } else if used >= max_bytes {
                BatchExit::ByteBudget
            } else if attempts >= max_attempts {
                BatchExit::DiscardBudget
            } else {
                BatchExit::Empty
            };
            observe_batch(exit, drained, payload_bytes, used);
        }
        if let Some(error) = failure {
            return Err(self.fail(error));
        }
        if drained == 0 {
            return Ok(0);
        }
        let result = write_outbound(
            circuit,
            &self.outbound_inline[..used],
            #[cfg(feature = "openssl-inner-tls")]
            self.edge_dns.as_ref().filter(|_| contains_dns),
        );
        if let Err(error) = result {
            return Err(self.fail(error));
        }
        self.stats.outbound_packets = self
            .stats
            .outbound_packets
            .saturating_add(u64::try_from(drained).unwrap_or(u64::MAX));
        self.stats.outbound_bytes = self.stats.outbound_bytes.saturating_add(payload_bytes);
        Ok(drained)
    }

    fn step_outbound_batch_legacy(
        &mut self,
        max_packets: usize,
        max_bytes: usize,
    ) -> Result<usize, PacketPathError> {
        self.check_open()?;
        if max_packets == 0 || max_bytes == 0 {
            return Ok(0);
        }
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        let mut drained = 0usize;
        let mut payload_bytes = 0u64;
        let mut attempts = 0usize;
        let max_attempts = max_packets.saturating_mul(2);
        let mut failure = None;
        #[cfg(feature = "openssl-inner-tls")]
        let mut contains_dns = false;
        self.outbound_batch.clear();
        while drained < max_packets
            && self.outbound_batch.len() < max_bytes
            && attempts < max_attempts
        {
            attempts += 1;
            let packet = match self.io.read_for_forwarding(&mut self.outbound_scratch) {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(error) => {
                    failure = Some(PacketPathError::from_host_error(error));
                    break;
                }
            };
            let bytes = packet.as_ref();
            let authorized = authorize_outbound_read(
                &self.policy,
                &packet,
                #[cfg(feature = "openssl-inner-tls")]
                self.edge_dns.as_mut(),
                #[cfg(feature = "openssl-inner-tls")]
                self.dns_replica_only,
            );
            match authorized {
                Ok(info) => {
                    #[cfg(feature = "openssl-inner-tls")]
                    if self
                        .edge_dns
                        .as_ref()
                        .is_some_and(|dns| info.destination == IpAddr::V4(dns.vip))
                    {
                        contains_dns = true;
                    }
                    let prefix = match packet_frame_prefix(bytes, self.policy.mtu()) {
                        Ok(prefix) => prefix,
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    };
                    // Append the verified bytes straight into the existing batch.
                    // Preserve the same size checks and flush/poll boundaries.
                    self.outbound_batch.extend_from_slice(&prefix);
                    self.outbound_batch.extend_from_slice(bytes);
                    drained += 1;
                    payload_bytes = payload_bytes
                        .saturating_add(u64::try_from(info.packet_len).unwrap_or(u64::MAX));
                }
                Err(deny) if deny.is_local_discard() => {
                    self.stats.dropped_outbound = self.stats.dropped_outbound.saturating_add(1);
                }
                Err(deny) => {
                    failure = Some(PacketPathError::Denied(deny));
                    break;
                }
            }
        }
        if let Some(error) = failure {
            self.outbound_batch.clear();
            return Err(self.fail(error));
        }
        if drained == 0 {
            return Ok(0);
        }
        let result = write_outbound(
            circuit,
            &self.outbound_batch,
            #[cfg(feature = "openssl-inner-tls")]
            self.edge_dns.as_ref().filter(|_| contains_dns),
        );
        if let Err(error) = result {
            self.outbound_batch.clear();
            return Err(self.fail(error));
        }
        self.outbound_batch.clear();
        self.stats.outbound_packets = self
            .stats
            .outbound_packets
            .saturating_add(u64::try_from(drained).unwrap_or(u64::MAX));
        self.stats.outbound_bytes = self.stats.outbound_bytes.saturating_add(payload_bytes);
        Ok(drained)
    }

    /// Read one frame from the peer and deliver its packet to the host stack,
    /// or consume it in the explicitly provisioned private DNS responder.
    ///
    /// `Ok(None)` means the peer closed the circuit cleanly between frames. That
    /// is terminal for business traffic: the path closes and drops the circuit,
    /// so no later step (in either direction) succeeds. A frame that ends early,
    /// declares too many bytes or fails L3 authorization poisons the path, drops
    /// the circuit and is never delivered.
    pub fn step_inbound(&mut self) -> Result<Option<usize>, PacketPathError> {
        self.check_open()?;
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        match inbound_once(
            self.io,
            circuit,
            &self.policy,
            &mut self.inbound_scratch,
            #[cfg(feature = "openssl-inner-tls")]
            self.private_dns.as_mut(),
            #[cfg(feature = "openssl-inner-tls")]
            self.edge_dns.as_mut(),
            #[cfg(feature = "openssl-inner-tls")]
            self.dns_replica_only,
        ) {
            Ok(Some(InboundDelivery { length, reply_len })) => {
                if let Some(reply_len) = reply_len {
                    self.stats.outbound_packets = self.stats.outbound_packets.saturating_add(1);
                    self.stats.outbound_bytes = self
                        .stats
                        .outbound_bytes
                        .saturating_add(u64::try_from(reply_len).unwrap_or(u64::MAX));
                }
                self.stats.inbound_packets = self.stats.inbound_packets.saturating_add(1);
                self.stats.inbound_bytes = self
                    .stats
                    .inbound_bytes
                    .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
                Ok(Some(length))
            }
            Ok(None) => {
                self.close();
                Ok(None)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Advance the Core's in-process DNS TCP endpoint even without inbound
    /// frames. Flush at most `max_packets` complete IP packets on this circuit.
    /// Only the same path owner may call this and the ordinary I/O steps.
    #[cfg(feature = "openssl-inner-tls")]
    pub fn step_private_dns(&mut self, max_packets: usize) -> Result<usize, PacketPathError> {
        self.check_open()?;
        let Some(dns) = self.private_dns.as_mut().filter(|dns| dns.deferred) else {
            return Ok(0);
        };
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        let result = poll_private_dns(circuit, &self.policy, dns, max_packets, &mut self.stats);
        result.map_err(|error| self.fail(error))
    }

    fn check_open(&self) -> Result<(), PacketPathError> {
        match self.state {
            PathState::Open => Ok(()),
            PathState::Closed => Err(PacketPathError::Closed),
            PathState::Poisoned(_) => Err(PacketPathError::Poisoned),
        }
    }

    /// Record the failure, drop the circuit stream and refuse all further work.
    fn fail(&mut self, error: PacketPathError) -> PacketPathError {
        self.stats.failures = self.stats.failures.saturating_add(1);
        self.state = PathState::Poisoned(error);
        self.circuit = None;
        #[cfg(feature = "openssl-inner-tls")]
        {
            self.private_dns = None;
            self.edge_dns = None;
        }
        error
    }
}

/// One outbound step over the borrowed pieces, so the caller can drop the whole
/// circuit on failure without a self-borrow conflict.
fn outbound_once<C: Read + Write, P: PacketIo + ?Sized>(
    io: &P,
    circuit: &mut C,
    policy: &PointToPoint,
    scratch: &mut [u8],
    #[cfg(feature = "openssl-inner-tls")] mut edge_dns: Option<&mut EdgeDns<'_>>,
    #[cfg(feature = "openssl-inner-tls")] dns_replica_only: bool,
) -> Result<Option<usize>, PacketPathError> {
    let packet = match io.read_for_forwarding(scratch) {
        Ok(Some(packet)) => packet,
        Ok(None) => return Ok(None),
        Err(error) => return Err(PacketPathError::from_host_error(error)),
    };
    let bytes = packet.as_ref();
    let info = authorize_outbound_read(
        policy,
        &packet,
        #[cfg(feature = "openssl-inner-tls")]
        edge_dns.as_deref_mut(),
        #[cfg(feature = "openssl-inner-tls")]
        dns_replica_only,
    )
    .map_err(PacketPathError::Denied)?;
    // Copy the packet directly into a contiguous, bounded frame for the stream.
    let mut frame = [0u8; MAX_FRAME_BYTES];
    let frame_len = encode_packet_frame_into(bytes, policy.mtu(), &mut frame)?;
    write_outbound(
        circuit,
        &frame[..frame_len],
        #[cfg(feature = "openssl-inner-tls")]
        edge_dns
            .as_deref()
            .filter(|dns| info.destination == IpAddr::V4(dns.vip)),
    )?;
    Ok(Some(info.packet_len))
}

fn authorize_outbound_read(
    policy: &PointToPoint,
    packet: &PacketRead<'_>,
    #[cfg(feature = "openssl-inner-tls")] edge_dns: Option<&mut EdgeDns<'_>>,
    #[cfg(feature = "openssl-inner-tls")] dns_replica_only: bool,
) -> Result<PacketInfo, PacketDeny> {
    let ordinary = policy.authorize_host_read(packet);
    #[cfg(feature = "openssl-inner-tls")]
    if ordinary == Err(PacketDeny::DestinationNotPeer)
        && let Some(dns) = edge_dns
    {
        // The original check already required the local source and MTU.
        let bytes = packet.as_ref();
        let info = match packet {
            PacketRead::Inspected(packet) => packet.info(),
            PacketRead::Bytes(bytes) => policy.inspect_bytes(bytes)?.info(),
        };
        if info.destination == IpAddr::V4(dns.vip) {
            if let Ok((port, 53, message)) = edge_udp_dns(bytes, info)
                && let Some(question) = boreas_dns::PrivateQuestion::routed_query(message, dns.zone, dns.public)
            {
                dns.remember(port, question);
                return Ok(info);
            }
            if let Ok((client, 53, flags)) = dns_tcp_segment(bytes, info)
                && let Some(flows) = dns.tcp.as_mut()
                && flows.outbound(client, flags)
            {
                return Ok(info);
            }
        }
    }
    #[cfg(feature = "openssl-inner-tls")]
    if dns_replica_only && ordinary.is_ok() {
        return Err(PacketDeny::NotDnsTraffic);
    }
    ordinary
}

fn write_outbound<C: Write>(
    circuit: &mut C,
    frame: &[u8],
    #[cfg(feature = "openssl-inner-tls")] edge_dns: Option<&EdgeDns<'_>>,
) -> Result<(), PacketPathError> {
    #[cfg(feature = "openssl-inner-tls")]
    if let Some(dns) = edge_dns {
        write_all_guarded(circuit, frame, || dns.check())?;
        dns.check()?;
        circuit
            .flush()
            .map_err(circuit_io)?;
        return dns.check();
    }
    write_all_bounded(circuit, frame)?;
    circuit
        .flush()
        .map_err(circuit_io)
}

/// Write a whole frame, bounded on "no progress".
///
/// `std::io::Write::write_all` retries `Interrupted` without any limit, so a
/// stream that keeps returning `Interrupted` would spin forever. This loop
/// bounds *consecutive* interrupts and fails closed instead; each successful
/// write resets the budget.
fn write_all_bounded<C: Write + ?Sized>(
    circuit: &mut C,
    frame: &[u8],
) -> Result<(), PacketPathError> {
    write_all_guarded(circuit, frame, || Ok(()))
}

fn write_all_guarded<C: Write + ?Sized>(
    circuit: &mut C,
    frame: &[u8],
    mut authorize: impl FnMut() -> Result<(), PacketPathError>,
) -> Result<(), PacketPathError> {
    let mut written = 0;
    let mut interrupts = 0u8;
    while written < frame.len() {
        authorize()?;
        match circuit.write(&frame[written..]) {
            Ok(0) => return Err(PacketPathError::CircuitIo(io::ErrorKind::WriteZero)),
            Ok(count) => {
                written += count;
                interrupts = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupts = interrupts.saturating_add(1);
                if interrupts >= MAX_INTERRUPT_RETRIES {
                    return Err(PacketPathError::CircuitIo(io::ErrorKind::Interrupted));
                }
            }
            Err(error) => return Err(circuit_io(error)),
        }
    }
    Ok(())
}

/// Read a whole frame body, bounded on "no progress" for the same reason.
fn read_exact_bounded<C: Read + ?Sized>(
    circuit: &mut C,
    body: &mut [u8],
) -> Result<(), PacketPathError> {
    let mut filled = 0;
    let mut interrupts = 0u8;
    while filled < body.len() {
        match circuit.read(&mut body[filled..]) {
            Ok(0) => return Err(PacketPathError::TruncatedFrame),
            Ok(count) => {
                filled += count;
                interrupts = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupts = interrupts.saturating_add(1);
                if interrupts >= MAX_INTERRUPT_RETRIES {
                    return Err(PacketPathError::CircuitIo(io::ErrorKind::Interrupted));
                }
            }
            Err(error) => return Err(circuit_io(error)),
        }
    }
    Ok(())
}

struct InboundDelivery {
    length: usize,
    reply_len: Option<usize>,
}

/// One inbound step over the borrowed pieces.
fn inbound_once<C: Read + Write, P: PacketIo + ?Sized>(
    io: &P,
    circuit: &mut C,
    policy: &PointToPoint,
    packet: &mut Vec<u8>,
    #[cfg(feature = "openssl-inner-tls")] dns: Option<&mut PrivateDns<'_>>,
    #[cfg(feature = "openssl-inner-tls")] edge_dns: Option<&mut EdgeDns<'_>>,
    #[cfg(feature = "openssl-inner-tls")] dns_replica_only: bool,
) -> Result<Option<InboundDelivery>, PacketPathError> {
    if !read_packet_frame_into(circuit, policy.mtu(), packet)? {
        return Ok(None);
    }
    let packet = policy.inspect_bytes(packet).map_err(PacketPathError::Denied)?;
    #[cfg(feature = "openssl-inner-tls")]
    let info = packet.info();
    #[cfg(feature = "openssl-inner-tls")]
    let class = classify_inbound(
        policy, packet,
        dns.as_ref().map(|dns| dns.service.dns_vip()),
        edge_dns.as_ref().map(|dns| dns.vip), dns_replica_only,
    )?;
    #[cfg(feature = "openssl-inner-tls")]
    if let Some(dns) = dns.filter(|_| class == InboundClass::CoreDns) {
        // Never reclassify a DNS VIP packet as host traffic, even when
        // unanswered or authorization expired during the read.
        let reply_len = dispatch_private_dns(circuit, policy, dns, packet)?;
        return Ok(Some(InboundDelivery {
            length: info.packet_len,
            reply_len,
        }));
    }
    #[cfg(feature = "openssl-inner-tls")]
    if let Some(dns) = edge_dns.filter(|_| class == InboundClass::EdgeDns) {
        dns.check()?;
        let expected = if info.protocol == 6 {
            let (port, client, flags) = dns_tcp_segment(packet.bytes(), info)
                .map_err(PacketPathError::Denied)?;
            let Some(flows) = dns.tcp.as_mut().filter(|_| port == 53) else {
                return Err(PacketPathError::Denied(PacketDeny::BadHeader));
            };
            flows.inbound(client, flags)
        } else {
            let (port, client, message) =
                edge_udp_dns(packet.bytes(), info).map_err(PacketPathError::Denied)?;
            let Some(question) =
                boreas_dns::PrivateQuestion::routed_response(message, dns.zone, dns.public).filter(|_| port == 53)
            else {
                return Err(PacketPathError::Denied(PacketDeny::BadHeader));
            };
            dns.take_reply(client, &question)
        };
        if !expected {
            // A delayed response, an evicted query, or a wrong transaction is
            // never written to TUN. It does not tear down an otherwise live path.
            return Ok(Some(InboundDelivery {
                length: info.packet_len,
                reply_len: None,
            }));
        }
        io.write_inspected_packet(packet)
            .map_err(PacketPathError::from_host_error)?;
        dns.check()?;
        return Ok(Some(InboundDelivery {
            length: info.packet_len,
            reply_len: None,
        }));
    }
    let length = deliver_inspected_host_packet(io, policy, packet)?;
    Ok(Some(InboundDelivery {
        length,
        reply_len: None,
    }))
}

#[cfg(feature = "openssl-inner-tls")]
fn dns_udp_ports(packet: &[u8], info: PacketInfo) -> Result<(u16, u16), PacketPathError> {
    if info.version != IpVersion::V4
        || info.header_len != 20
        || info.fragment.is_some()
        || info.protocol != 17
        || packet.len() < 28
    {
        return Err(PacketPathError::Denied(PacketDeny::BadHeader));
    }
    let source = u16::from_be_bytes([packet[20], packet[21]]);
    let destination = u16::from_be_bytes([packet[22], packet[23]]);
    if source == 0 || destination == 0 {
        return Err(PacketPathError::Denied(PacketDeny::BadHeader));
    }
    Ok((source, destination))
}

#[cfg(feature = "openssl-inner-tls")]
fn edge_udp_dns(packet: &[u8], info: PacketInfo) -> Result<(u16, u16, &[u8]), PacketDeny> {
    let (source, destination) = dns_udp_ports(packet, info).map_err(|_| PacketDeny::BadHeader)?;
    let udp = &packet[20..];
    let len = u16::from_be_bytes([udp[4], udp[5]]);
    if usize::from(len) != udp.len() || len < 20 {
        return Err(PacketDeny::BadLength);
    }
    // Optional IPv4 UDP checksum. Nonzero checksums include the pseudo-header.
    if udp[6..8] != [0, 0] && !transport_checksum_valid(packet, 17, udp) {
        return Err(PacketDeny::BadChecksum);
    }
    Ok((source, destination, &udp[8..]))
}

#[cfg(feature = "openssl-inner-tls")]
fn dns_tcp_segment(packet: &[u8], info: PacketInfo) -> Result<(u16, u16, u8), PacketDeny> {
    if info.version != IpVersion::V4
        || info.header_len != 20
        || info.fragment.is_some()
        || info.protocol != 6
        || packet.len() < 40
    {
        return Err(PacketDeny::BadHeader);
    }
    let segment = &packet[20..];
    let header_len = usize::from(segment[12] >> 4) * 4;
    let source = u16::from_be_bytes([segment[0], segment[1]]);
    let destination = u16::from_be_bytes([segment[2], segment[3]]);
    if !(20..=segment.len()).contains(&header_len) || source == 0 || destination == 0 {
        return Err(PacketDeny::BadHeader);
    }
    // TCP checksum is mandatory; the Linux DNS TCP profile has no TUN offload.
    if !transport_checksum_valid(packet, 6, segment) {
        return Err(PacketDeny::BadChecksum);
    }
    Ok((source, destination, segment[13]))
}

#[cfg(feature = "openssl-inner-tls")]
fn transport_checksum_valid(packet: &[u8], protocol: u8, segment: &[u8]) -> bool {
    // Both callers already checked the whole IPv4 packet against the path MTU.
    let mut sum = segment.len() as u32 + u32::from(protocol);
    for word in packet[12..20].chunks(2).chain(segment.chunks(2)) {
        sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

#[cfg(feature = "openssl-inner-tls")]
fn dispatch_private_dns<C: Write>(
    circuit: &mut C,
    policy: &PointToPoint,
    dns: &mut PrivateDns<'_>,
    query: InspectedPacket<'_>,
) -> Result<Option<usize>, PacketPathError> {
    let info = query.info();
    let (client_port, port) = if dns.tcp && info.protocol == 6 {
        let (client, port, _) = dns_tcp_segment(query.bytes(), info)
            .map_err(PacketPathError::Denied)?;
        (client, port)
    } else {
        dns_udp_ports(query.bytes(), info)?
    };
    if port != 53 {
        return Err(PacketPathError::Denied(PacketDeny::DestinationNotLocal));
    }
    let now = dns.live_utc()?;
    if !dns.service.push_input(query.bytes(), now) {
        dns.live_utc()?;
        return Ok(None);
    }
    if dns.deferred {
        // Both transports share this bounded dispatcher. TCP may emit zero,
        // one, or multiple packets unrelated to the most recent input packet.
        return Ok(None);
    }
    let now = dns.live_utc()?;
    dns.service.poll(now).ok_or(PacketPathError::DnsAuthorizationLost)?;
    let now = dns.live_utc()?;
    let Some(reply) = dns.service.pop_output(now) else {
        dns.live_utc()?;
        return Ok(None);
    };
    write_private_dns(circuit, policy, dns, &reply, Some(client_port)).map(Some)
}

#[cfg(feature = "openssl-inner-tls")]
fn poll_private_dns<C: Write>(
    circuit: &mut C,
    policy: &PointToPoint,
    dns: &mut PrivateDns<'_>,
    max_packets: usize,
    stats: &mut PacketStats,
) -> Result<usize, PacketPathError> {
    let now = dns.live_utc()?;
    dns.service.poll(now).ok_or(PacketPathError::DnsAuthorizationLost)?;
    let mut sent = 0;
    for _ in 0..max_packets.min(16) {
        let now = dns.live_utc()?;
        let Some(reply) = dns.service.pop_output(now) else {
            dns.live_utc()?;
            break;
        };
        let length = write_private_dns(circuit, policy, dns, &reply, None)?;
        stats.outbound_packets = stats.outbound_packets.saturating_add(1);
        stats.outbound_bytes = stats.outbound_bytes.saturating_add(length as u64);
        sent += 1;
    }
    dns.live_utc()?;
    Ok(sent)
}

#[cfg(feature = "openssl-inner-tls")]
fn write_private_dns<C: Write>(
    circuit: &mut C,
    policy: &PointToPoint,
    dns: &mut PrivateDns<'_>,
    bytes: &[u8],
    udp_client: Option<u16>,
) -> Result<usize, PacketPathError> {
    let reply = policy.inspect_bytes(bytes).map_err(PacketPathError::Denied)?;
    let info = reply.info();
    let (port, client) = if dns.tcp && info.protocol == 6 {
        let (port, client, _) = dns_tcp_segment(reply.bytes(), info)
            .map_err(PacketPathError::Denied)?;
        (port, client)
    } else {
        dns_udp_ports(reply.bytes(), info)?
    };
    if info.source != IpAddr::V4(dns.service.dns_vip())
        || info.destination != IpAddr::V4(policy.peer_vip())
        || port != 53
        || udp_client.is_some_and(|expected| expected != client)
    {
        return Err(PacketPathError::Denied(PacketDeny::BadHeader));
    }
    let mut frame = [0; MAX_FRAME_BYTES];
    let frame_len = encode_packet_frame_into(reply.bytes(), policy.mtu(), &mut frame)?;
    // Guard each partial write and the flush. On loss, abandon this circuit;
    // bytes already accepted by an underlying blocking write cannot be recalled.
    write_all_guarded(circuit, &frame[..frame_len], || dns.live_utc().map(|_| ()))?;
    dns.live_utc()?;
    circuit.flush().map_err(circuit_io)?;
    dns.live_utc()?;
    Ok(info.packet_len)
}

impl PacketPathError {
    fn from_host_error(error: TunError) -> Self {
        match error {
            TunError::QueueFull => Self::HostQueueFull,
            TunError::QueueClosed => Self::HostQueueClosed,
            other => Self::HostRejected(other),
        }
    }
}

#[cfg(all(test, not(feature = "openssl-inner-tls")))]
mod unbound_default_tests {
    use super::*;

    #[cfg(not(feature = "openssl-inner-tls"))]
    #[test]
    fn packet_path_rejects_legacy_identity_without_crypto_feature() {
        let peer = PeerIdentity::legacy_default([7; 16], 0x0209, 1, NodeRole::Edge);
        assert_eq!(
            EndpointFacts::from_verified_identity(peer).unwrap_err(),
            PacketPathError::PolicyMismatch,
        );
    }
}

#[cfg(all(test, feature = "openssl-inner-tls"))]
mod tests {
    //! In-crate tests.
    //!
    //! This module is the only place that can build [`AuthorizedEndpoints`]
    //! directly, which lets the real `boreas_tun` endpoint and the real framing run
    //! without a TLS stack. The real end-to-end path (actual WSS + E2E circuit +
    //! `VirtualTun`) is covered by `tests/wss_e2e_openssl.rs` under the
    //! `openssl-inner-tls` feature. These results are development evidence only and
    //! are not a production, G-DATA or 1 GiB acceptance claim.

    use super::*;
    #[path = "optimization_tests.rs"]
    mod optimization_tests;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use boreas_tun::{VirtualTun, inspect_packet};

    const NET: [u8; 16] = [0x2a; 16];
    const GENERATION: u64 = 7;

    #[test]
    fn prefetch_readiness_preserves_partial_and_invalid_lengths() {
        assert!(!prefetched_frame_ready(&[], 1500));
        assert!(!prefetched_frame_ready(&[0], 1500));
        assert!(!prefetched_frame_ready(&[0, 3, 1, 2], 1500));
        assert!(prefetched_frame_ready(&[0, 3, 1, 2, 3], 1500));
        assert!(prefetched_frame_ready(&[0, 3, 1, 2, 3, 0], 1500));
        assert!(prefetched_frame_ready(&[0, 0], 1500));
        assert!(prefetched_frame_ready(&[0xff, 0xff], 1500));
    }

    #[test]
    fn circuit_io_preserves_transport_and_protocol_distinction() {
        use io::ErrorKind::{ConnectionReset, InvalidData, TimedOut, UnexpectedEof};
        for (wrapped, expected) in [
            (TunnelError::Io(ConnectionReset), PacketPathError::CircuitIo(ConnectionReset)),
            (TunnelError::Timeout, PacketPathError::CircuitIo(TimedOut)),
            (TunnelError::Ws(WsError::Closed), PacketPathError::CircuitIo(UnexpectedEof)),
            (TunnelError::Circuit(crate::CircuitReject::OffsetMismatch), PacketPathError::CircuitProtocol),
            (TunnelError::Ws(WsError::BadAcceptKey), PacketPathError::CircuitProtocol),
        ] {
            assert_eq!(circuit_io(io::Error::new(InvalidData, wrapped)), expected);
        }
    }

    #[test]
    fn caller_buffer_frame_matches_wire_bytes_and_preserves_tail() {
        for length in [1, MIN_MTU, MAX_MTU] {
            let packet = vec![0x5a; length];
            let mut storage = [0xa5; MAX_FRAME_BYTES];
            let used = encode_packet_frame_into(&packet, MAX_MTU, &mut storage).unwrap();
            assert_eq!(used, FRAME_PREFIX_LEN + length);
            assert_eq!(&storage[..2], &(length as u16).to_be_bytes());
            assert_eq!(&storage[2..used], packet.as_slice());
            assert!(storage[used..].iter().all(|byte| *byte == 0xa5));
            assert_eq!(
                encode_packet_frame(&packet, MAX_MTU).unwrap(),
                storage[..used]
            );
        }
        let mut storage = [0u8; MAX_FRAME_BYTES];
        assert!(encode_packet_frame_into(&[], MAX_MTU, &mut storage).is_err());
        assert!(encode_packet_frame_into(&vec![0; MAX_MTU + 1], MAX_MTU, &mut storage).is_err());
        assert!(encode_packet_frame_into(&[1, 2], MAX_MTU, &mut [0; 3]).is_err());
    }

    fn identity(node_id: u16, role: NodeRole) -> PeerIdentity {
        PeerIdentity::legacy_default(NET, node_id, GENERATION, role)
    }

    fn endpoints(local: PeerIdentity, peer: PeerIdentity) -> AuthorizedEndpoints {
        // This helper exists only in backend-enabled tests; production cannot
        // synthesize a binding and default-build tests cover rejection separately.
        let policy = test_policy_context(NET);
        let local = PeerIdentity::policy_bound(
            NET,
            local.node_id,
            local.identity_generation,
            local.role,
            policy,
        )
        .expect("verified fixture context");
        let peer = PeerIdentity::policy_bound(
            NET,
            peer.node_id,
            peer.identity_generation,
            peer.role,
            policy,
        )
        .expect("verified fixture context");
        AuthorizedEndpoints::bind([0x11; 16], 1, peer, local, DEFAULT_MTU as u16)
            .expect("canonical permanent pair")
    }

    /// One process-wide verification context per test network.
    ///
    /// Every provisioning call generates fresh root keys, so two calls produce
    /// two *different* signed policy digests. Positive cases must share exactly
    /// one context or even a re-bound pair fails closed as `PolicyMismatch`.
    /// [`fresh_test_policy_context`] remains available only for the negative
    /// test that deliberately needs two distinct digests.
    #[cfg(feature = "openssl-inner-tls")]
    fn test_policy_context(net_id: [u8; 16]) -> boreas_pki::VerifiedNetworkContext {
        static CACHED: std::sync::OnceLock<boreas_pki::VerifiedNetworkContext> =
            std::sync::OnceLock::new();
        assert_eq!(
            net_id, NET,
            "the cached context is provisioned for the fixture network only"
        );
        *CACHED.get_or_init(|| fresh_test_policy_context(net_id))
    }

    #[cfg(feature = "openssl-inner-tls")]
    fn fresh_test_policy_context(net_id: [u8; 16]) -> boreas_pki::VerifiedNetworkContext {
        use boreas_proto::network_policy::NetworkPolicyCandidate;
        use boreas_proto::objects::MldsaParameterSet;
        use openssl::{
            pkey::{KeyType, PKey},
            sign::Signer,
        };
        let ed = PKey::generate_ed25519().expect("Ed25519 test root");
        let pq = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[0x65; 32])
            .expect("ML-DSA test root");
        let pin = boreas_pki::root_authorization::NetworkRootPin::provisioned(
            net_id,
            ed.public_key_to_der().unwrap(),
            MldsaParameterSet::Mldsa65,
            pq.public_key_to_der().unwrap(),
        )
        .unwrap();
        let candidate = NetworkPolicyCandidate {
            net_id,
            root_key_fingerprint: pin.fingerprint().unwrap(),
            overlay_base: [10, 20, 0, 0],
            version: 1,
            seq: 1,
            issued_at: 1,
            expires: u64::MAX,
        };
        let raw = candidate.encode_tbs().unwrap();
        let message = NetworkPolicyCandidate::signature_input(&raw).unwrap();
        let mut signer = Signer::new_without_digest(&ed).unwrap();
        let ed_sig = signer.sign_oneshot_to_vec(&message).unwrap();
        let mut signer = Signer::new_without_digest(&pq).unwrap();
        let pq_sig = signer.sign_oneshot_to_vec(&message).unwrap();
        boreas_pki::verify_network_policy(&raw, &ed_sig, &pq_sig, &pin, net_id, 2)
            .unwrap()
            .require_default_runtime()
            .unwrap()
    }

    #[test]
    fn private_prefix_binding_and_public_address_rejection() {
        let private = PointToPoint::try_new(
            Ipv4Addr::new(172, 19, 1, 1),
            Ipv4Addr::new(172, 19, 1, 2),
            1400,
        )
        .expect("canonical private slots");
        assert_eq!(private.local_vip(), Ipv4Addr::new(172, 19, 1, 1));
        assert_eq!(
            PointToPoint::try_new(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(10, 20, 1, 2), 1400,)
                .unwrap_err(),
            PacketPathError::InvalidEndpointVip
        );
        assert_eq!(
            PointToPoint::try_new(
                Ipv4Addr::new(10, 21, 1, 1),
                Ipv4Addr::new(10, 20, 1, 2),
                1400,
            )
            .unwrap_err(),
            PacketPathError::InvalidEndpointVip
        );
    }

    fn assert_unbound_rejected(local: PeerIdentity, peer: PeerIdentity) {
        assert_eq!(
            AuthorizedEndpoints::bind([0x11; 16], 1, peer, local, DEFAULT_MTU as u16).unwrap_err(),
            PacketPathError::PolicyMismatch,
        );
    }

    #[cfg(feature = "openssl-inner-tls")]
    #[test]
    fn packet_endpoint_refuses_legacy_unbound_identity() {
        assert_unbound_rejected(
            identity(0x0201, NodeRole::Core),
            identity(0x0209, NodeRole::Edge),
        );
    }

    #[cfg(feature = "openssl-inner-tls")]
    #[test]
    fn packet_endpoint_rejects_distinct_signed_policy_digests() {
        // Two independent provisioning runs: fresh root keys, so two different
        // signed policy digests. This is the negative case that must stay
        // distinct, hence `fresh_test_policy_context` rather than the cache.
        let local = PeerIdentity::policy_bound(
            NET,
            0x0201,
            GENERATION,
            NodeRole::Core,
            fresh_test_policy_context(NET),
        )
        .unwrap();
        let peer = PeerIdentity::policy_bound(
            NET,
            0x0209,
            GENERATION,
            NodeRole::Edge,
            fresh_test_policy_context(NET),
        )
        .unwrap();
        assert_eq!(
            AuthorizedEndpoints::bind([0x11; 16], 1, peer, local, DEFAULT_MTU as u16).unwrap_err(),
            PacketPathError::PolicyMismatch,
        );
    }

    fn checksum_value(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in data.chunks(2) {
            sum += if chunk.len() == 2 {
                u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
            } else {
                u32::from(chunk[0]) << 8
            };
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&u16::try_from(total).expect("bounded").to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..].copy_from_slice(payload);
        let header = checksum_value(&packet[..20]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet
    }

    fn fnv1a_64(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// Circuit stand-in for the host-to-peer direction: records the frames.
    #[derive(Clone)]
    struct OutboundSink {
        log: Rc<RefCell<Vec<u8>>>,
    }

    impl OutboundSink {
        fn new() -> (Self, Rc<RefCell<Vec<u8>>>) {
            let log = Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    log: Rc::clone(&log),
                },
                log,
            )
        }
    }

    impl Read for OutboundSink {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for OutboundSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.log.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Circuit stand-in for the peer-to-host direction: replays recorded frames.
    struct InboundSource {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl InboundSource {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl Read for InboundSource {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.offset >= self.bytes.len() || out.is_empty() {
                return Ok(0);
            }
            let take = out.len().min(self.bytes.len() - self.offset);
            out[..take].copy_from_slice(&self.bytes[self.offset..self.offset + take]);
            self.offset += take;
            Ok(take)
        }
    }

    impl Write for InboundSource {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "openssl-inner-tls")]
    #[test]
    fn edge_dns_requires_the_verified_vips_and_matching_udp_transaction() {
        use crate::dns_runtime::tests::{dns_query, udp_datagram};

        let edge = [10, 20, 1, 2];
        let core = [10, 20, 1, 1];
        let vip = [10, 20, 0, 53];
        let policy = PointToPoint::try_new(edge.into(), core.into(), DEFAULT_MTU).unwrap();
        let mut dns = EdgeDns {
            vip: vip.into(),
            zone: "private.example",
            public: false,
            current: Box::new(|| true),
            pending: Default::default(),
            tcp: None,
        };
        let question = dns_query("host.private.example", 1);
        for (source, destination, port, body, allow) in [
            (edge, vip, 53, question.clone(), true),
            (edge, vip, 54, question.clone(), false),
            (core, vip, 53, question.clone(), false),
            (edge, [10, 20, 0, 54], 53, question.clone(), false),
            (edge, vip, 53, dns_query("notprivate.example", 1), false),
            (
                edge,
                vip,
                53,
                dns_query("private.example.invalid", 1),
                false,
            ),
        ] {
            let bytes = udp_datagram(source, destination, 40_001, port, &body, true);
            let packet = InspectedPacket::new(&bytes).unwrap();
            assert!(
                authorize_outbound_read(&policy, &PacketRead::Inspected(packet), None, false).is_err()
            );
            assert_eq!(
                authorize_outbound_read(&policy, &PacketRead::Inspected(packet), Some(&mut dns), true)
                    .is_ok(),
                allow
            );
        }
        let mut response = question;
        response[2] |= 0x84; // QR + AA, echo RD.
        // The same structurally valid ordinary L3 packet is allowed by the
        // normal point-to-point policy but must not cross a DNS-only circuit.
        let ordinary_out = udp_datagram(edge, core, 40_001, 1234, b"not DNS", true);
        let ordinary_out = PacketRead::Inspected(policy.inspect_bytes(&ordinary_out).unwrap());
        assert!(authorize_outbound_read(&policy, &ordinary_out, Some(&mut dns), false).is_ok());
        assert_eq!(authorize_outbound_read(&policy, &ordinary_out, Some(&mut dns), true),
            Err(PacketDeny::NotDnsTraffic));
        let (device, host) = VirtualTun::try_pair(4, 4, DEFAULT_MTU).unwrap();
        let mut scratch = Vec::new();
        let ordinary_in = udp_datagram(core, edge, 1234, 40_001, b"not DNS", true);
        let mut ordinary_stream = InboundSource::new(encode_packet_frame(&ordinary_in, DEFAULT_MTU).unwrap());
        assert!(matches!(inbound_once(&device, &mut ordinary_stream, &policy, &mut scratch,
            None, Some(&mut dns), true), Err(PacketPathError::Denied(PacketDeny::NotDnsTraffic))));
        assert!(host.read_packet().unwrap().is_none());
        let answer = udp_datagram(vip, edge, 53, 40_001, &response, true);
        let wrong_port = udp_datagram(vip, edge, 53, 40_002, &response, true);
        let wrong_destination = udp_datagram(vip, core, 53, 40_001, &response, true);
        for (bytes, reject, deliver) in [
            (&wrong_port, false, false),
            (&wrong_destination, true, false),
            (&answer, false, true),
            (&answer, false, false), // duplicate
        ] {
            let frame = encode_packet_frame(bytes, DEFAULT_MTU).unwrap();
            let mut stream = InboundSource::new(frame);
            assert_eq!(
                inbound_once(
                    &device,
                    &mut stream,
                    &policy,
                    &mut scratch,
                    None,
                    Some(&mut dns),
                    true,
                )
                .is_err(),
                reject
            );
            assert_eq!(
                host.read_packet().unwrap().as_deref(),
                deliver.then_some(bytes.as_slice())
            );
        }
    }

    #[cfg(feature = "openssl-inner-tls")]
    #[test]
    fn edge_tcp_dns_allows_only_opened_authenticated_tuples() {
        let edge = [10, 20, 1, 2];
        let core = [10, 20, 1, 1];
        let vip = [10, 20, 0, 53];
        let policy = PointToPoint::try_new(edge.into(), core.into(), DEFAULT_MTU).unwrap();
        let mut dns = EdgeDns {
            vip: vip.into(),
            zone: "private.example",
            public: false,
            current: Box::new(|| true),
            pending: Default::default(),
            tcp: None,
        };
        let segment = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags| {
            let mut tcp = [0; 20];
            tcp[..2].copy_from_slice(&sport.to_be_bytes());
            tcp[2..4].copy_from_slice(&dport.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = flags;
            let mut pseudo = src.to_vec();
            pseudo.extend_from_slice(&dst);
            pseudo.extend_from_slice(&[0, 6, 0, 20]);
            pseudo.extend_from_slice(&tcp);
            tcp[16..18].copy_from_slice(&checksum_value(&pseudo).to_be_bytes());
            let mut packet = ipv4(src, dst, &tcp);
            packet[9] = 6;
            packet[10..12].fill(0);
            let checksum = checksum_value(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet
        };
        let authorize = |bytes: &[u8], dns: &mut EdgeDns<'_>| {
            let packet = InspectedPacket::new(bytes).unwrap();
            authorize_outbound_read(&policy, &PacketRead::Inspected(packet), Some(dns), false).is_ok()
        };
        let syn = segment(edge, vip, 40_000, 53, TCP_SYN);
        assert!(!authorize(&syn, &mut dns));
        dns.tcp = Some(EdgeTcpFlows::default());
        assert!(!authorize(&segment(edge, vip, 40_000, 53, TCP_ACK), &mut dns));
        assert!(!authorize(&segment(edge, vip, 40_000, 54, TCP_SYN), &mut dns));
        assert!(!authorize(&segment(core, vip, 40_000, 53, TCP_SYN), &mut dns));
        let mut bad_checksum = syn.clone();
        bad_checksum[24] ^= 1;
        assert!(!authorize(&bad_checksum, &mut dns));
        assert!(authorize(&syn, &mut dns));
        let (device, host) = VirtualTun::try_pair(4, 4, DEFAULT_MTU).unwrap();
        let mut scratch = Vec::new();
        for (bytes, reject, deliver) in [
            (segment(vip, edge, 53, 40_001, TCP_SYN | TCP_ACK), false, false),
            (segment(vip, edge, 53, 40_000, TCP_SYN), false, false),
            (segment(vip, core, 53, 40_000, TCP_SYN | TCP_ACK), true, false),
            (segment(vip, edge, 54, 40_000, TCP_SYN | TCP_ACK), true, false),
            (segment(vip, edge, 53, 40_000, TCP_SYN | TCP_ACK), false, true),
        ] {
            let frame = encode_packet_frame(&bytes, DEFAULT_MTU).unwrap();
            let mut stream = InboundSource::new(frame);
            let result = inbound_once(&device, &mut stream, &policy, &mut scratch, None, Some(&mut dns), false);
            assert_eq!(result.is_err(), reject);
            assert_eq!(host.read_packet().unwrap(), deliver.then_some(bytes));
        }
        let flows = dns.tcp.as_mut().unwrap();
        let expired = Instant::now().checked_sub(EdgeTcpFlows::MAX_AGE);
        if let Some(expired) = expired {
            flows.0[0].1 = expired;
            assert!(!flows.inbound(40_000, TCP_ACK));
        }
        for port in 1..=65 {
            assert!(flows.outbound(port, TCP_SYN));
        }
        assert_eq!(flows.0.len(), EdgeTcpFlows::CAPACITY);
        assert!(!flows.inbound(1, TCP_ACK));
        assert!(flows.outbound(2, TCP_RST));
        assert!(!flows.inbound(2, TCP_ACK));
    }

    #[cfg(feature = "openssl-inner-tls")]
    #[test]
    fn private_dns_packet_path_dispatches_only_on_authorized_circuit() {
        use crate::dns_packet_service::tests::signed_packet_binding;
        use crate::dns_runtime::tests::{dns_payload, dns_query, fixture_at, udp_datagram};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum RevokeAt {
            Never,
            PartialWrite,
            FullWrite,
            Flush,
        }

        struct Duplex {
            input: InboundSource,
            output: OutboundSink,
            live: Arc<AtomicBool>,
            revoke_at: RevokeAt,
            flushes: Rc<Cell<usize>>,
        }
        impl Read for Duplex {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl Write for Duplex {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let count = if self.revoke_at == RevokeAt::PartialWrite { 1 } else { buf.len() };
                let written = self.output.write(&buf[..count])?;
                if matches!(self.revoke_at, RevokeAt::PartialWrite | RevokeAt::FullWrite) {
                    self.live.store(false, Ordering::SeqCst);
                }
                Ok(written)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes.set(self.flushes.get() + 1);
                if self.revoke_at == RevokeAt::Flush {
                    self.live.store(false, Ordering::SeqCst);
                }
                self.output.flush()
            }
        }

        const UNIT: u64 = 1_000_000;
        const NOW: u64 = 1_500 * UNIT;
        const MTU: usize = 1280;
        let fixture = fixture_at(UNIT);
        let core = [10, 20, 1, 1];
        let edge = [10, 20, 1, 2];
        let vip = [10, 20, 0, 53];
        let query = |source, name| udp_datagram(source, vip, 40_000, 53, &dns_query(name, 1), true);
        let good = query(edge, "host.b.example");
        let mut bad_ip = good.clone();
        bad_ip[10] ^= 1;
        let mut bad_udp = good.clone();
        bad_udp[28] ^= 1; // Change the DNS ID without updating UDP checksum.
        let mut no_udp_checksum = good.clone();
        no_udp_checksum[26..28].fill(0);
        let unauthorized = Some(PacketPathError::DnsAuthorizationLost);
        let wrong_destination = Some(PacketPathError::Denied(PacketDeny::DestinationNotLocal));
        for (enable, packet, utc, revoke_at, expected) in [
            (true, good.clone(), Some(NOW), RevokeAt::Never, None),
            (true, no_udp_checksum.clone(), Some(NOW), RevokeAt::Never, None),
            (true, query(edge, "outside.example"), Some(NOW), RevokeAt::Never, None),
            (true, ipv4(edge, core, &[0; MTU - 20]), Some(NOW), RevokeAt::Never, None),
            (
                true,
                udp_datagram(edge, vip, 40_000, 54, &dns_query("host.b.example", 1), true),
                Some(NOW),
                RevokeAt::Never,
                wrong_destination,
            ),
            (
                true,
                udp_datagram(edge, vip, 0, 53, &dns_query("host.b.example", 1), true),
                Some(NOW),
                RevokeAt::Never,
                Some(PacketPathError::Denied(PacketDeny::BadHeader)),
            ),
            (false, good.clone(), Some(NOW), RevokeAt::Never, wrong_destination),
            (
                true,
                query([10, 20, 1, 3], "host.b.example"),
                Some(NOW),
                RevokeAt::Never,
                Some(PacketPathError::Denied(PacketDeny::SourceNotPeer)),
            ),
            (
                true,
                bad_ip,
                Some(NOW),
                RevokeAt::Never,
                Some(PacketPathError::Denied(PacketDeny::BadChecksum)),
            ),
            (true, bad_udp, Some(NOW), RevokeAt::Never, None),
            (true, good.clone(), Some(1_800 * UNIT), RevokeAt::Never, unauthorized),
            (true, good.clone(), Some(NOW - 1), RevokeAt::Never, unauthorized),
            (true, good.clone(), None, RevokeAt::Never, unauthorized),
            (true, good.clone(), Some(NOW), RevokeAt::PartialWrite, unauthorized),
            (true, good.clone(), Some(NOW), RevokeAt::FullWrite, unauthorized),
            (true, good.clone(), Some(NOW), RevokeAt::Flush, unauthorized),
            (
                true,
                vec![0; MTU + 1],
                Some(NOW),
                RevokeAt::Never,
                Some(PacketPathError::FrameTooLarge),
            ),
        ] {
            let live = Arc::new(AtomicBool::new(true));
            let gate = Arc::clone(&live);
            let gate: DnsLiveness<'_> = Box::new(move || gate.load(Ordering::SeqCst));
            let (peer, service) = signed_packet_binding(&fixture, MTU, gate);
            let endpoints = AuthorizedEndpoints::bind([0x11; 16], 1, peer, fixture.local, 1500)
                .unwrap();
            let (device, host) = VirtualTun::try_pair(4, 4, MTU).unwrap();
            let (output, written) = OutboundSink::new();
            let flushes = Rc::new(Cell::new(0));
            let circuit = Duplex {
                input: InboundSource::new(encode_packet_frame(&packet, 1500).unwrap()),
                output,
                live,
                revoke_at,
                flushes: Rc::clone(&flushes),
            };
            let mut path = PacketPath::try_new(&device, circuit, endpoints, MTU).unwrap();
            if enable {
                path.private_dns = Some(PrivateDns { service, tcp: false, deferred: false, utc: Box::new(move || utc) });
            }
            // Even on an enabled path, host writes cannot use the DNS VIP.
            host.write_packet(&udp_datagram(vip, edge, 53, 40_000, b"host", true))
                .unwrap();
            assert_eq!(path.step_outbound().unwrap(), None);
            assert_eq!(path.stats().dropped_outbound, 1);
            let outcome = path.step_inbound();
            let written = written.borrow();
            if let Some(error) = expected {
                assert_eq!(outcome, Err(error));
                assert!(!path.is_open());
                assert!(path.circuit.is_none());
                assert!(path.private_dns.is_none());
                match revoke_at {
                    RevokeAt::Never => assert!(written.is_empty()),
                    RevokeAt::PartialWrite => assert_eq!(written.len(), 1),
                    RevokeAt::FullWrite | RevokeAt::Flush => {
                        assert!(decode_packet_frame(&written, MTU).is_ok());
                    }
                }
                assert_eq!(flushes.get(), if revoke_at == RevokeAt::Flush { 1 } else { 0 });
                assert!(host.read_packet().unwrap().is_none());
                assert_eq!(path.stats().outbound_packets, 0);
                assert_eq!(path.stats().inbound_packets, 0);
                assert_eq!(path.step_inbound(), Err(PacketPathError::Poisoned));
            } else {
                assert_eq!(outcome, Ok(Some(packet.len())));
                assert!(path.is_open());
                if packet == good || packet == no_udp_checksum {
                    let reply = decode_packet_frame(&written, MTU).unwrap();
                    assert_eq!(&reply[12..16], &vip);
                    assert_eq!(&reply[16..20], &edge);
                    assert_eq!(&reply[20..24], &[0, 53, 0x9c, 0x40]);
                    let message = dns_payload(reply);
                    assert_eq!(&message[..2], &[0x12, 0x34]);
                    assert_eq!(&message[message.len() - 4..], &core);
                    let expected = udp_datagram(vip, edge, 53, 40_000, message, true);
                    assert_eq!(&reply[20..], &expected[20..]);
                    assert_eq!(path.stats().outbound_packets, 1);
                    assert_eq!(flushes.get(), 1);
                    assert!(host.read_packet().unwrap().is_none());
                } else {
                    assert!(written.is_empty());
                    assert_eq!(flushes.get(), 0);
                    if packet[16..20] == core {
                        assert_eq!(host.read_packet().unwrap(), Some(packet));
                    } else {
                        assert!(host.read_packet().unwrap().is_none());
                    }
                }
            }
        }
    }

    /// Circuit stand-in that records whether the path actually dropped it.
    struct Droppable {
        dropped: Rc<Cell<bool>>,
        written: usize,
    }

    impl Droppable {
        fn new() -> (Self, Rc<Cell<bool>>) {
            let dropped = Rc::new(Cell::new(false));
            (
                Self {
                    dropped: Rc::clone(&dropped),
                    written: 0,
                },
                dropped,
            )
        }
    }

    impl Read for Droppable {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Droppable {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written = self.written.saturating_add(buf.len());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Droppable {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    #[test]
    fn bind_accepts_only_canonical_permanent_pairs() {
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        #[cfg(feature = "openssl-inner-tls")]
        let bound = endpoints(local, peer);
        #[cfg(feature = "openssl-inner-tls")]
        assert_eq!(bound.local.vip, Ipv4Addr::new(10, 20, 3, 1));
        #[cfg(feature = "openssl-inner-tls")]
        assert_eq!(bound.peer.vip, Ipv4Addr::new(10, 20, 3, 9));
        #[cfg(feature = "openssl-inner-tls")]
        assert_eq!(bound.circuit_id, [0x11; 16]);
        #[cfg(feature = "openssl-inner-tls")]
        assert_eq!(bound.path_hops, 1);
        #[cfg(feature = "openssl-inner-tls")]
        assert_eq!(bound.mtu_cap, u16::try_from(DEFAULT_MTU).unwrap());

        // Exactly one verification context for this test. Each call provisions a
        // fresh random root, so a second `test_policy_context` call would carry a
        // different signed policy digest and every pair below would fail as
        // `PolicyMismatch` instead of exercising the rule under test.
        let policy = test_policy_context(NET);
        // An identity from another network cannot carry this policy, so it stays
        // unbound and `bind` still observes the missing verified policy.
        let with_policy = |identity: PeerIdentity| {
            if identity.net_id == NET {
                PeerIdentity::policy_bound(
                    NET,
                    identity.node_id,
                    identity.identity_generation,
                    identity.role,
                    policy,
                )
                .unwrap()
            } else {
                identity
            }
        };
        let bind = |circuit: [u8; 16], hops: u8, peer: PeerIdentity, local: PeerIdentity| {
            AuthorizedEndpoints::bind(
                circuit,
                hops,
                with_policy(peer),
                with_policy(local),
                u16::try_from(DEFAULT_MTU).unwrap(),
            )
        };
        // An enrollment-service node has no packet endpoint.
        assert_eq!(
            bind(
                [0x11; 16],
                1,
                peer,
                identity(0x0201, NodeRole::EnrollmentService)
            )
            .unwrap_err(),
            PacketPathError::InvalidPermanentSlot
        );
        // A Core node may not claim the Edge octet.
        assert_eq!(
            bind([0x11; 16], 1, peer, identity(0x0209, NodeRole::Core)).unwrap_err(),
            PacketPathError::InvalidPermanentSlot
        );
        // Cross-network and same-node bindings fail closed.
        let other_network = PeerIdentity::legacy_default(
            [0x2b; 16],
            peer.node_id,
            peer.identity_generation,
            peer.role,
        );
        assert_eq!(
            bind([0x11; 16], 1, other_network, local).unwrap_err(),
            PacketPathError::PolicyMismatch
        );
        assert_eq!(
            AuthorizedEndpoints::bind([0x11; 16], 1, peer, identity(0x0201, NodeRole::Core), 1400)
                .unwrap_err(),
            PacketPathError::PolicyMismatch,
        );
        assert_eq!(
            bind([0x11; 16], 1, peer, peer).unwrap_err(),
            PacketPathError::IdentityMismatch
        );
        // No circuit, no hops, no binding.
        assert_eq!(
            bind([0; 16], 1, peer, local).unwrap_err(),
            PacketPathError::CircuitMismatch
        );
        assert_eq!(
            bind([0x11; 16], 0, peer, local).unwrap_err(),
            PacketPathError::CircuitMismatch
        );
        assert_eq!(
            bind([0x11; 16], MAX_RELAY_HOPS + 1, peer, local).unwrap_err(),
            PacketPathError::CircuitMismatch
        );
        assert_eq!(
            bind([0x11; 16], 1, peer, identity(0, NodeRole::Core)).unwrap_err(),
            PacketPathError::InvalidIdentity
        );

        // A multi-hop cipher stream is still one endpoint pair: `path_hops` may be
        // above 1, and the adapter is not a forwarder.
        let bound_local = identity(0x0201, NodeRole::Core);
        assert!(bind([0x11; 16], 3, peer, bound_local).is_ok());

        // MTU bounds and the circuit's negotiated cap.
        let pair = VirtualTun::try_pair(1, 1, DEFAULT_MTU).expect("bounded pair");
        match PacketPath::try_new(
            &pair.0,
            OutboundSink::new().0,
            endpoints(local, peer),
            MIN_MTU - 1,
        ) {
            Err(PacketPathError::MtuOutOfRange) => {}
            Err(other) => panic!("unexpected mtu error: {other:?}"),
            Ok(_) => panic!("out-of-range mtu must be refused"),
        }
        match PacketPath::try_new(
            &pair.0,
            OutboundSink::new().0,
            endpoints(local, peer),
            MAX_MTU + 1,
        ) {
            Err(PacketPathError::MtuAboveCircuitCap) => {}
            Err(other) => panic!("unexpected mtu error: {other:?}"),
            Ok(_) => panic!("mtu above the circuit cap must be refused"),
        }
        let capped =
            AuthorizedEndpoints::bind([0x11; 16], 1, with_policy(peer), with_policy(local), 1400)
                .expect("capped permanent pair");
        match PacketPath::try_new(&pair.0, OutboundSink::new().0, capped, 1401) {
            Err(PacketPathError::MtuAboveCircuitCap) => {}
            Err(other) => panic!("unexpected mtu error: {other:?}"),
            Ok(_) => panic!("mtu above the circuit cap must be refused"),
        }
        let capped =
            AuthorizedEndpoints::bind([0x11; 16], 1, with_policy(peer), with_policy(local), 1400)
                .expect("capped permanent pair");
        assert!(PacketPath::try_new(&pair.0, OutboundSink::new().0, capped, 1400).is_ok());
    }

    #[test]
    fn real_virtual_tun_packets_cross_the_framed_path_and_are_hashed() {
        let mtu = DEFAULT_MTU;
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        // `device` is the tunnel-side endpoint: `inject` feeds its reader with a
        // packet the host stack emitted, and `write_packet` lands in the peer
        // endpoint's queue, which stands in for the local host stack.
        let (device, host) = VirtualTun::try_pair(8, 8, mtu).expect("bounded pair");

        let outbound = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"outbound-payload");
        let inbound = ipv4([10, 20, 3, 9], [10, 20, 3, 1], b"inbound-payload");
        assert_eq!(
            inspect_packet(&outbound).map(|info| info.packet_len),
            Ok(outbound.len())
        );

        device.inject(&outbound).expect("valid host packet");
        let (sink, log) = OutboundSink::new();
        let mut sender =
            PacketPath::try_new(&device, sink, endpoints(local, peer), mtu).expect("bound path");
        assert_eq!(sender.mtu(), mtu);
        assert_eq!(sender.step_outbound(), Ok(Some(outbound.len())));
        assert_eq!(sender.step_outbound(), Ok(None), "one packet per step");
        assert_eq!(
            sender.stats(),
            PacketStats {
                outbound_packets: 1,
                outbound_bytes: u64::try_from(outbound.len()).unwrap(),
                ..PacketStats::default()
            }
        );
        assert!(sender.is_open());

        let frames = log.borrow().clone();
        assert_eq!(frames.len(), FRAME_PREFIX_LEN + outbound.len());
        assert_eq!(
            u16::from_be_bytes([frames[0], frames[1]]),
            u16::try_from(outbound.len()).unwrap()
        );
        // The wire bytes decode back to exactly the packet the host emitted.
        let decoded = decode_packet_frame(&frames, mtu).expect("one complete frame");
        assert_eq!(decoded, outbound.as_slice());
        assert_eq!(fnv1a_64(decoded), fnv1a_64(&outbound));
        drop(sender);

        // The peer side decodes exactly the same wire bytes: one frame, one
        // packet, and the inbound direction of the same authorized pair.
        let inbound_frame = encode_packet_frame(&inbound, mtu).expect("inbound frame");
        let mut receiver = PacketPath::try_new(
            &device,
            InboundSource::new(inbound_frame),
            endpoints(local, peer),
            mtu,
        )
        .expect("bound path");
        assert_eq!(receiver.step_inbound(), Ok(Some(inbound.len())));
        assert_eq!(
            receiver.step_inbound(),
            Ok(None),
            "clean close between frames"
        );
        assert!(!receiver.is_open(), "a clean peer close ends the path");
        assert_eq!(
            receiver.first_error(),
            None,
            "a clean close is not a failure"
        );
        assert_eq!(
            receiver.stats(),
            PacketStats {
                inbound_packets: 1,
                inbound_bytes: u64::try_from(inbound.len()).unwrap(),
                ..PacketStats::default()
            }
        );
        let delivered = host.read_packet().expect("host reads").expect("one packet");
        assert_eq!(delivered, inbound);
        assert_eq!(fnv1a_64(&delivered), fnv1a_64(&inbound));
        assert_eq!(
            inspect_packet(&delivered).map(|info| info.source),
            Ok(IpAddr::V4(Ipv4Addr::new(10, 20, 3, 9)))
        );
        assert_eq!(host.read_packet(), Ok(None), "exactly one delivery");
    }

    #[test]
    fn spoofed_addresses_and_malformed_frames_poison_the_path() {
        let mtu = DEFAULT_MTU;
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        let (device, host) = VirtualTun::try_pair(8, 8, mtu).expect("bounded pair");

        // Structurally valid but sourced from a third host: discarded locally.
        let spoofed = ipv4([10, 20, 3, 7], [10, 20, 3, 9], b"spoof");
        device.inject(&spoofed).expect("structurally valid");
        let (sink, log) = OutboundSink::new();
        let mut path =
            PacketPath::try_new(&device, sink, endpoints(local, peer), mtu).expect("bound path");
        assert_eq!(path.step_outbound(), Ok(None));
        assert_eq!(path.first_error(), None);
        assert_eq!(path.step_outbound(), Ok(None));
        assert_eq!(path.stats().dropped_outbound, 1);
        assert_eq!(path.stats().failures, 0);
        assert!(path.is_open());
        assert!(log.borrow().is_empty(), "nothing reaches the wire");

        // A frame whose packet is addressed to the wrong host.
        let wrong_destination = ipv4([10, 20, 3, 9], [10, 20, 3, 7], b"wrong");
        let frame = encode_packet_frame(&wrong_destination, mtu).expect("frame");
        let mut path = PacketPath::try_new(
            &device,
            InboundSource::new(frame),
            endpoints(local, peer),
            mtu,
        )
        .expect("bound path");
        assert_eq!(
            path.step_inbound(),
            Err(PacketPathError::Denied(PacketDeny::DestinationNotLocal))
        );
        assert_eq!(
            host.read_packet(),
            Ok(None),
            "nothing reaches the host stack"
        );

        // A frame that ends inside its declared packet.
        let packet = ipv4([10, 20, 3, 9], [10, 20, 3, 1], b"cut");
        let mut frame = encode_packet_frame(&packet, mtu).expect("frame");
        frame.truncate(frame.len() - 2);
        let mut path = PacketPath::try_new(
            &device,
            InboundSource::new(frame),
            endpoints(local, peer),
            mtu,
        )
        .expect("bound path");
        assert_eq!(path.step_inbound(), Err(PacketPathError::TruncatedFrame));
        assert_eq!(host.read_packet(), Ok(None));
    }

    #[test]
    fn ipv6_is_refused_rather_than_forwarded() {
        let mtu = DEFAULT_MTU;
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        let (device, _host) = VirtualTun::try_pair(4, 4, mtu).expect("bounded pair");

        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[6] = 59;
        v6[7] = 64;
        v6[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 9]);
        v6[24..40].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1]);
        device.inject(&v6).expect("structurally valid IPv6");

        let mut path =
            PacketPath::try_new(&device, OutboundSink::new().0, endpoints(local, peer), mtu)
                .expect("bound path");
        assert_eq!(path.step_outbound(), Ok(None));
        assert!(path.is_open());
        assert_eq!(path.stats().dropped_outbound, 1);
        assert_eq!(path.stats().outbound_packets, 0);
    }

    #[test]
    fn clean_peer_close_and_failures_release_the_circuit_and_end_business() {
        let mtu = DEFAULT_MTU;
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        let (device, _host) = VirtualTun::try_pair(4, 4, mtu).expect("bounded pair");

        // A clean peer close is terminal: the circuit is dropped and neither
        // direction works afterwards, so the path cannot keep sending.
        let (circuit, dropped) = Droppable::new();
        let mut path =
            PacketPath::try_new(&device, circuit, endpoints(local, peer), mtu).expect("bound path");
        assert_eq!(path.step_inbound(), Ok(None));
        assert!(!path.is_open());
        assert_eq!(path.first_error(), None, "a clean close is not a failure");
        assert!(dropped.get(), "a clean close must release the E2E circuit");
        assert_eq!(path.step_outbound(), Err(PacketPathError::Closed));
        assert_eq!(path.step_inbound(), Err(PacketPathError::Closed));

        // Local traffic that is not addressed to the peer is discarded, but the
        // authenticated circuit stays up for the actual peer flow.
        let (circuit, dropped) = Droppable::new();
        let mut path =
            PacketPath::try_new(&device, circuit, endpoints(local, peer), mtu).expect("bound path");
        device
            .inject(&ipv4([10, 20, 3, 7], [10, 20, 3, 9], b"spoofed"))
            .expect("structurally valid");
        assert_eq!(path.step_outbound(), Ok(None));
        assert!(!dropped.get(), "local discard must keep the circuit");
        assert!(path.is_open());
        assert_eq!(path.stats().dropped_outbound, 1);

        // Explicit close is idempotent and releases too.
        let (circuit, dropped) = Droppable::new();
        let mut path =
            PacketPath::try_new(&device, circuit, endpoints(local, peer), mtu).expect("bound path");
        path.close();
        path.close();
        assert!(dropped.get());
        assert_eq!(path.first_error(), None);
        assert_eq!(path.step_inbound(), Err(PacketPathError::Closed));
    }

    #[test]
    fn outbound_reuses_scratch_and_drops_pending_batch_on_read_error() {
        use std::collections::VecDeque;

        struct ScratchIo<'a> {
            reads: RefCell<VecDeque<&'a [u8]>>,
            address: Cell<Option<*const u8>>,
        }
        impl PacketIo for ScratchIo<'_> {
            fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
                panic!("outbound must use the scratch-capable read");
            }

            fn read_for_forwarding<'buf>(
                &self,
                scratch: &'buf mut [u8],
            ) -> Result<Option<PacketRead<'buf>>, TunError> {
                assert_eq!(scratch.len(), MAX_MTU + 1);
                self.address.set(Some(scratch.as_ptr()));
                let Some(bytes) = self.reads.borrow_mut().pop_front() else {
                    return Ok(None);
                };
                let dst = &mut scratch[..bytes.len()];
                dst.copy_from_slice(bytes);
                InspectedPacket::new(dst).map(|packet| Some(PacketRead::Inspected(packet)))
            }

            fn write_packet(&self, _packet: &[u8]) -> Result<(), TunError> {
                unreachable!()
            }
        }

        let p1 = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"longer packet");
        let p2 = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"short");
        let spoof = ipv4([10, 20, 3, 7], [10, 20, 3, 9], b"spoof");
        let mut bad_checksum = p1.clone();
        bad_checksum[10] ^= 1;
        let host = ScratchIo {
            reads: RefCell::new(VecDeque::from([
                p1.as_slice(),
                spoof.as_slice(),
                p2.as_slice(),
                p1.as_slice(),
                bad_checksum.as_slice(),
            ])),
            address: Cell::new(None),
        };
        let io: &dyn PacketIo = &host;
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        let (sink, written) = OutboundSink::new();
        let mtu = DEFAULT_MTU;
        let mut path = PacketPath::try_new(io, sink, endpoints(local, peer), mtu).unwrap();
        assert_eq!(path.step_outbound_batch(0, 1), Ok(0));
        assert_eq!(path.step_outbound_batch(1, 0), Ok(0));
        assert_eq!(path.step_outbound(), Ok(Some(p1.len())));
        // The byte threshold stops the next read but must not split a frame.
        assert_eq!(path.step_outbound_batch(16, 1), Ok(1));
        assert_eq!(host.address.get(), Some(path.outbound_inline[2..].as_ptr()));
        assert_eq!(path.outbound_inline.len(), INLINE_BATCH_STORAGE);
        let mut expected = encode_packet_frame(&p1, mtu).unwrap();
        expected.extend(encode_packet_frame(&p2, mtu).unwrap());
        assert_eq!(
            path.step_outbound_batch(16, 16_000),
            Err(PacketPathError::HostRejected(TunError::InvalidChecksum))
        );
        assert_eq!(path.step_outbound(), Err(PacketPathError::Poisoned));
        assert_eq!(path.stats().dropped_outbound, 1);
        assert_eq!(path.stats().outbound_packets, 2);
        assert_eq!(path.stats().failures, 1);
        assert!(path.circuit.is_none());
        assert_eq!(written.borrow().as_slice(), expected.as_slice());
    }

    #[test]
    fn inspected_host_read_still_checks_negotiated_mtu() {
        let policy = PointToPoint::try_new(
            Ipv4Addr::new(10, 20, 3, 1),
            Ipv4Addr::new(10, 20, 3, 9),
            MIN_MTU,
        )
        .unwrap();
        let bytes = ipv4([10, 20, 3, 1], [10, 20, 3, 9], &[0; MIN_MTU - 19]);
        let packet = PacketRead::Inspected(InspectedPacket::new(&bytes).unwrap());
        assert_eq!(
            policy.authorize_host_read(&packet),
            Err(PacketDeny::MtuExceeded)
        );
    }

    #[test]
    fn inbound_inspected_write_requires_checksum_and_peer_vip() {
        #[derive(Default)]
        struct CheckedSink(RefCell<Vec<Vec<u8>>>);

        impl PacketIo for CheckedSink {
            fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
                unreachable!()
            }

            fn write_packet(&self, _packet: &[u8]) -> Result<(), TunError> {
                panic!("forwarding must pass the inspected bytes to the device");
            }

            fn write_inspected_packet(&self, packet: InspectedPacket<'_>) -> Result<(), TunError> {
                self.0.borrow_mut().push(packet.bytes().to_vec());
                Ok(())
            }
        }

        let io = CheckedSink::default();
        let policy = PointToPoint::try_new(
            Ipv4Addr::new(10, 20, 3, 1),
            Ipv4Addr::new(10, 20, 3, 9),
            DEFAULT_MTU,
        )
        .unwrap();
        let valid = ipv4([10, 20, 3, 9], [10, 20, 3, 1], b"delivery");
        let spoof = ipv4([10, 20, 3, 7], [10, 20, 3, 1], b"spoof");
        let mut corrupt = valid.clone();
        corrupt[10] ^= 1;
        let mut scratch = Vec::new();
        for (bytes, expected) in [
            (&spoof, Err(PacketPathError::Denied(PacketDeny::SourceNotPeer))),
            (&corrupt, Err(PacketPathError::Denied(PacketDeny::BadChecksum))),
            (&valid, Ok(Some(valid.len()))),
        ] {
            let mut frame = InboundSource::new(encode_packet_frame(bytes, policy.mtu()).unwrap());
            let delivery = inbound_once(
                &io,
                &mut frame,
                &policy,
                &mut scratch,
                #[cfg(feature = "openssl-inner-tls")]
                None,
                #[cfg(feature = "openssl-inner-tls")]
                None,
                #[cfg(feature = "openssl-inner-tls")]
                false,
            );
            let length = delivery.map(|item| {
                item.map(|delivery| {
                    assert_eq!(delivery.reply_len, None);
                    delivery.length
                })
            });
            assert_eq!(length, expected);
        }
        assert_eq!(io.0.into_inner(), vec![valid]);
    }

    #[test]
    fn step_outbound_batch_coalesces_ready_packets_and_fails_closed() {
        let mtu = DEFAULT_MTU;
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        let (device, _host) = VirtualTun::try_pair(8, 8, mtu).expect("bounded pair");

        let p1 = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"one");
        let spoof = ipv4([10, 20, 3, 7], [10, 20, 3, 9], b"spoof");
        let p2 = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"two-payload");
        device.inject(&p1).expect("inject p1");
        device.inject(&spoof).expect("inject spoof");
        device.inject(&p2).expect("inject p2");

        let (sink, written) = OutboundSink::new();
        let mut path =
            PacketPath::try_new(&device, sink, endpoints(local, peer), mtu).expect("bound path");
        assert_eq!(path.step_outbound_batch(16, 16_000), Ok(2));
        assert_eq!(path.step_outbound_batch(16, 16_000), Ok(0));
        assert_eq!(path.stats().outbound_packets, 2);
        assert_eq!(path.stats().dropped_outbound, 1);

        let wire = written.borrow();
        let expected_first = encode_packet_frame(&p1, mtu).unwrap();
        let expected_second = encode_packet_frame(&p2, mtu).unwrap();
        assert_eq!(wire.len(), expected_first.len() + expected_second.len());
        assert_eq!(&wire[..expected_first.len()], expected_first.as_slice());
        assert_eq!(&wire[expected_first.len()..], expected_second.as_slice());

        // Malformed packet poisons the path and emits no partial frame.
        struct MalformedIo;
        impl PacketIo for MalformedIo {
            fn read_packet(&self) -> Result<Option<Vec<u8>>, TunError> {
                Ok(Some(vec![0x45, 0x00, 0x00]))
            }
            fn write_packet(&self, _packet: &[u8]) -> Result<(), TunError> {
                Ok(())
            }
        }
        let (sink, written) = OutboundSink::new();
        let malformed_io = MalformedIo;
        let mut path = PacketPath::try_new(&malformed_io, sink, endpoints(local, peer), mtu)
            .expect("bound path");
        assert_eq!(
            path.step_outbound_batch(16, 16_000),
            Err(PacketPathError::Denied(PacketDeny::Truncated))
        );
        assert!(!path.is_open());
        assert!(written.borrow().is_empty());
    }
}
