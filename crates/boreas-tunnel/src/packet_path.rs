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
//! [`PacketIo::write_packet`]. There is no coalescing, no fragmentation, no
//! queued retry and no second FIFO: `boreas_tun::VirtualTun` or a native
//! `PacketIo` queue is the only packet queue, and the circuit stream is the only
//! wire.
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
//!   here, so every IPv6 packet is refused rather than forwarded.
//! * **Status freshness is not integrated into this adapter.** The durable,
//!   verified `FreshStatus` capability that business traffic must consult is
//!   being implemented in a separate status-store slice; this adapter neither
//!   consults nor revalidates status, revocation, generation or clock state.
//!   Its success must not be recorded as `G-REVOKE`, `G-E2E`, `G-DATA` or as
//!   1 GiB production evidence, and the daemon owner must gate construction on a
//!   real verified status capability before enabling business traffic.
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
use boreas_tun::{Error as TunError, IpVersion, PacketInfo, PacketIo, inspect_packet};

use crate::e2e::E2eCircuit;
use crate::relay::MAX_RELAY_HOPS;
use crate::tls::PeerIdentity;

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
            Self::Ipv6NotNegotiated | Self::SourceNotLocal | Self::DestinationNotPeer
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
        self.authorize(packet, Direction::HostToPeer)
    }

    /// Validate and authorize one packet the peer delivered for the host stack.
    ///
    /// The source must be the peer permanent VIP and the destination the local
    /// permanent VIP.
    pub fn authorize_inbound(&self, packet: &[u8]) -> Result<PacketInfo, PacketDeny> {
        self.authorize(packet, Direction::PeerToHost)
    }

    fn authorize(&self, packet: &[u8], direction: Direction) -> Result<PacketInfo, PacketDeny> {
        if packet.len() > self.mtu {
            return Err(PacketDeny::MtuExceeded);
        }
        let Some(&first) = packet.first() else {
            return Err(PacketDeny::EmptyPacket);
        };
        match first >> 4 {
            4 => {}
            6 => return Err(PacketDeny::Ipv6NotNegotiated),
            _ => return Err(PacketDeny::UnknownVersion),
        }
        // Structural validation only: length, header, checksum, fragment fields.
        // `inspect_packet` never decides authorization; the address rules below do.
        let info = inspect_packet(packet)?;
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
        Ok(info)
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
    if packet.is_empty() {
        return Err(PacketPathError::Denied(PacketDeny::EmptyPacket));
    }
    if packet.len() > mtu || packet.len() > MAX_MTU {
        return Err(PacketPathError::Denied(PacketDeny::MtuExceeded));
    }
    let mut frame = vec![0u8; FRAME_PREFIX_LEN + packet.len()];
    let frame_len = encode_packet_frame_into(packet, mtu, &mut frame)?;
    frame.truncate(frame_len);
    Ok(frame)
}

/// Encode one packet into caller-provided storage and return its exact frame size.
fn encode_packet_frame_into(
    packet: &[u8],
    mtu: usize,
    frame: &mut [u8],
) -> Result<usize, PacketPathError> {
    if packet.is_empty() {
        return Err(PacketPathError::Denied(PacketDeny::EmptyPacket));
    }
    if packet.len() > mtu || packet.len() > MAX_MTU {
        return Err(PacketPathError::Denied(PacketDeny::MtuExceeded));
    }
    let length = u16::try_from(packet.len())
        .map_err(|_| PacketPathError::Denied(PacketDeny::MtuExceeded))?;
    let frame_len = FRAME_PREFIX_LEN + packet.len();
    if frame.len() < frame_len {
        return Err(PacketPathError::Denied(PacketDeny::MtuExceeded));
    }
    frame[..FRAME_PREFIX_LEN].copy_from_slice(&length.to_be_bytes());
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
            Err(error) => return Err(PacketPathError::CircuitIo(error.kind())),
        }
    }
    Ok(true)
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
    outbound_pos: usize,
    outbound_needs_flush: bool,
    inbound_scratch: Vec<u8>,
    rx_frame: [u8; MAX_FRAME_BYTES],
    inbound_filled: usize,
    inbound_expected: usize,
}

/// Result of one non-blocking inbound step on [`PacketPath`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundStep {
    /// One authorized L3 packet of `usize` bytes was delivered to the host.
    Packet(usize),
    /// The underlying stream would block before completing the current frame;
    /// partial bytes remain buffered safely inside [`PacketPath`].
    WouldBlock,
    /// The peer closed the circuit cleanly at a frame boundary.
    Closed,
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
    /// This is the only business constructor. It consumes the circuit by value
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
        Self::try_new(io, circuit, endpoints, mtu)
    }

    /// Whether inbound bytes are buffered above the raw outer TCP socket.
    /// The daemon combines this with socket readiness before entering a
    /// blocking frame read, avoiding both arbitrary sleeps and missed TLS data.
    pub fn has_buffered_input(&self) -> bool {
        self.circuit
            .as_ref()
            .is_some_and(E2eCircuit::has_buffered_input)
    }

    /// Whether outbound bytes remain buffered waiting on `POLLOUT`.
    pub fn has_pending_write(&self) -> bool {
        self.has_local_pending_write()
            || self
                .circuit
                .as_ref()
                .is_some_and(E2eCircuit::has_pending_write)
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
            outbound_pos: 0,
            outbound_needs_flush: false,
            inbound_scratch: Vec::new(),
            rx_frame: [0u8; MAX_FRAME_BYTES],
            inbound_filled: 0,
            inbound_expected: 0,
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
        match outbound_once(self.io, circuit, &self.policy) {
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
    /// immediately when `read_packet()` returns `None` or buffered bytes reach
    /// `max_bytes`), frame them contiguously, and emit them in a single E2E
    /// stream write + flush. Zero coalescing timer is used (§6.4).
    ///
    /// Returns the number of packets delivered to the circuit (`0` if none).
    /// Flush any buffered outbound bytes from an earlier `WouldBlock` without
    /// pulling additional host packets. Returns `Ok(true)` once fully flushed,
    /// or `Ok(false)` if the underlying transport still returned `WouldBlock`.
    /// Whether outbound batch bytes remain buffered inside [`PacketPath`] itself.
    pub fn has_local_pending_write(&self) -> bool {
        self.outbound_pos < self.outbound_batch.len() || self.outbound_needs_flush
    }

    /// Whether a partial inbound L3 frame is currently buffered waiting for
    /// the remaining bytes of its frame body.
    pub fn has_partial_inbound(&self) -> bool {
        self.inbound_filled > 0
    }

    pub fn flush_outbound(&mut self) -> Result<bool, PacketPathError> {
        self.check_open()?;
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        let mut interrupts = 0u8;
        while self.outbound_pos < self.outbound_batch.len() {
            match circuit.write(&self.outbound_batch[self.outbound_pos..]) {
                Ok(0) => {
                    self.outbound_batch.clear();
                    self.outbound_pos = 0;
                    return Err(self.fail(PacketPathError::CircuitIo(io::ErrorKind::WriteZero)));
                }
                Ok(n) => {
                    self.outbound_pos += n;
                    interrupts = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupts = interrupts.saturating_add(1);
                    if interrupts >= MAX_INTERRUPT_RETRIES {
                        self.outbound_batch.clear();
                        self.outbound_pos = 0;
                        return Err(
                            self.fail(PacketPathError::CircuitIo(io::ErrorKind::Interrupted))
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(false);
                }
                Err(error) => {
                    self.outbound_batch.clear();
                    self.outbound_pos = 0;
                    return Err(self.fail(PacketPathError::CircuitIo(error.kind())));
                }
            }
        }
        self.outbound_batch.clear();
        self.outbound_pos = 0;
        if self.outbound_needs_flush {
            match circuit.flush() {
                Ok(()) => self.outbound_needs_flush = false,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(false);
                }
                Err(error) => {
                    return Err(self.fail(PacketPathError::CircuitIo(error.kind())));
                }
            }
        }
        Ok(true)
    }

    pub fn step_outbound_batch(
        &mut self,
        max_packets: usize,
        max_bytes: usize,
    ) -> Result<usize, PacketPathError> {
        self.check_open()?;
        if !self.flush_outbound()? {
            return Ok(0);
        }
        if max_packets == 0 || max_bytes == 0 {
            return Ok(0);
        }
        if self.circuit.is_none() {
            return Err(PacketPathError::Poisoned);
        }
        let mut drained = 0usize;
        let mut payload_bytes = 0u64;
        let mut attempts = 0usize;
        let max_attempts = max_packets.saturating_mul(2);
        self.outbound_batch.clear();
        self.outbound_pos = 0;
        while drained < max_packets
            && self.outbound_batch.len() < max_bytes
            && attempts < max_attempts
        {
            attempts += 1;
            let packet = match self.io.read_packet() {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(error) => {
                    self.outbound_batch.clear();
                    return Err(self.fail(PacketPathError::from_host_error(error)));
                }
            };
            match self.policy.authorize_outbound(&packet) {
                Ok(info) => {
                    let mut frame = [0u8; MAX_FRAME_BYTES];
                    let frame_len =
                        match encode_packet_frame_into(&packet, self.policy.mtu(), &mut frame) {
                            Ok(len) => len,
                            Err(error) => {
                                self.outbound_batch.clear();
                                return Err(self.fail(error));
                            }
                        };
                    self.outbound_batch.extend_from_slice(&frame[..frame_len]);
                    drained += 1;
                    payload_bytes = payload_bytes
                        .saturating_add(u64::try_from(info.packet_len).unwrap_or(u64::MAX));
                }
                Err(deny) if deny.is_local_discard() => {
                    self.stats.dropped_outbound = self.stats.dropped_outbound.saturating_add(1);
                }
                Err(deny) => {
                    self.outbound_batch.clear();
                    return Err(self.fail(PacketPathError::Denied(deny)));
                }
            }
        }
        if drained == 0 {
            return Ok(0);
        }
        self.outbound_needs_flush = true;
        self.stats.outbound_packets = self
            .stats
            .outbound_packets
            .saturating_add(u64::try_from(drained).unwrap_or(u64::MAX));
        self.stats.outbound_bytes = self.stats.outbound_bytes.saturating_add(payload_bytes);
        let _ = self.flush_outbound()?;
        Ok(drained)
    }

    /// Non-blocking inbound step preserving partial frame bytes across
    /// `WouldBlock` without poisoning the circuit.
    pub fn step_inbound_nonblocking(&mut self) -> Result<InboundStep, PacketPathError> {
        self.check_open()?;
        let Some(circuit) = self.circuit.as_mut() else {
            return Err(PacketPathError::Poisoned);
        };
        let mut interrupts = 0u8;
        while self.inbound_filled < FRAME_PREFIX_LEN {
            match circuit.read(&mut self.rx_frame[self.inbound_filled..FRAME_PREFIX_LEN]) {
                Ok(0) => {
                    if self.inbound_filled == 0 {
                        self.close();
                        return Ok(InboundStep::Closed);
                    }
                    return Err(self.fail(PacketPathError::TruncatedFrame));
                }
                Ok(n) => {
                    self.inbound_filled += n;
                    interrupts = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupts = interrupts.saturating_add(1);
                    if interrupts >= MAX_INTERRUPT_RETRIES {
                        return Err(
                            self.fail(PacketPathError::CircuitIo(io::ErrorKind::Interrupted))
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(InboundStep::WouldBlock);
                }
                Err(error) => {
                    return Err(self.fail(PacketPathError::CircuitIo(error.kind())));
                }
            }
        }
        if self.inbound_expected == 0 {
            let body_len = usize::from(u16::from_be_bytes([self.rx_frame[0], self.rx_frame[1]]));
            if body_len == 0 {
                return Err(self.fail(PacketPathError::EmptyFrame));
            }
            if body_len > self.policy.mtu() {
                return Err(self.fail(PacketPathError::FrameTooLarge));
            }
            self.inbound_expected = FRAME_PREFIX_LEN + body_len;
        }
        interrupts = 0;
        while self.inbound_filled < self.inbound_expected {
            match circuit.read(&mut self.rx_frame[self.inbound_filled..self.inbound_expected]) {
                Ok(0) => return Err(self.fail(PacketPathError::TruncatedFrame)),
                Ok(n) => {
                    self.inbound_filled += n;
                    interrupts = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupts = interrupts.saturating_add(1);
                    if interrupts >= MAX_INTERRUPT_RETRIES {
                        return Err(
                            self.fail(PacketPathError::CircuitIo(io::ErrorKind::Interrupted))
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(InboundStep::WouldBlock);
                }
                Err(error) => {
                    return Err(self.fail(PacketPathError::CircuitIo(error.kind())));
                }
            }
        }
        let end = self.inbound_expected;
        self.inbound_filled = 0;
        self.inbound_expected = 0;
        let packet = &self.rx_frame[FRAME_PREFIX_LEN..end];
        let length = match self.policy.authorize_inbound(packet) {
            Ok(info) => info.packet_len,
            Err(deny) => return Err(self.fail(PacketPathError::Denied(deny))),
        };
        if let Err(error) = self.io.write_packet(packet) {
            let mapped = match error {
                TunError::QueueFull => PacketPathError::HostQueueFull,
                TunError::QueueClosed => PacketPathError::HostQueueClosed,
                other => PacketPathError::HostRejected(other),
            };
            return Err(self.fail(mapped));
        }
        self.stats.inbound_packets = self.stats.inbound_packets.saturating_add(1);
        self.stats.inbound_bytes = self
            .stats
            .inbound_bytes
            .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
        Ok(InboundStep::Packet(length))
    }

    /// Read one frame from the peer and deliver its packet to the host stack.
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
        match inbound_once(self.io, circuit, &self.policy, &mut self.inbound_scratch) {
            Ok(Some(length)) => {
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
        error
    }
}

/// One outbound step over the borrowed pieces, so the caller can drop the whole
/// circuit on failure without a self-borrow conflict.
fn outbound_once<C: Read + Write, P: PacketIo + ?Sized>(
    io: &P,
    circuit: &mut C,
    policy: &PointToPoint,
) -> Result<Option<usize>, PacketPathError> {
    let packet = match io.read_packet() {
        Ok(Some(packet)) => packet,
        Ok(None) => return Ok(None),
        Err(error) => return Err(PacketPathError::from_host_error(error)),
    };
    let length = policy
        .authorize_outbound(&packet)
        .map_err(PacketPathError::Denied)?
        .packet_len;
    // `read_packet` returns the host-owned packet Vec. Assemble the complete
    // bounded frame on the stack to avoid a second heap allocation. The packet
    // is still copied once into contiguous bytes for the stream writer.
    let mut frame = [0u8; MAX_FRAME_BYTES];
    let frame_len = encode_packet_frame_into(&packet, policy.mtu(), &mut frame)?;
    write_all_bounded(circuit, &frame[..frame_len])?;
    circuit
        .flush()
        .map_err(|error| PacketPathError::CircuitIo(error.kind()))?;
    Ok(Some(length))
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
    let mut written = 0;
    let mut interrupts = 0u8;
    while written < frame.len() {
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
            Err(error) => return Err(PacketPathError::CircuitIo(error.kind())),
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
            Err(error) => return Err(PacketPathError::CircuitIo(error.kind())),
        }
    }
    Ok(())
}

/// One inbound step over the borrowed pieces.
fn inbound_once<C: Read + Write, P: PacketIo + ?Sized>(
    io: &P,
    circuit: &mut C,
    policy: &PointToPoint,
    packet: &mut Vec<u8>,
) -> Result<Option<usize>, PacketPathError> {
    if !read_packet_frame_into(circuit, policy.mtu(), packet)? {
        return Ok(None);
    }
    let length = policy
        .authorize_inbound(packet)
        .map_err(PacketPathError::Denied)?
        .packet_len;
    match io.write_packet(packet) {
        Ok(()) => Ok(Some(length)),
        Err(TunError::QueueFull) => Err(PacketPathError::HostQueueFull),
        Err(TunError::QueueClosed) => Err(PacketPathError::HostQueueClosed),
        Err(error) => Err(PacketPathError::HostRejected(error)),
    }
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
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use boreas_tun::VirtualTun;

    const NET: [u8; 16] = [0x2a; 16];
    const GENERATION: u64 = 7;

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

    #[test]
    fn nonblocking_inbound_and_outbound_preserve_partial_progress_across_would_block() {
        struct NonBlockingCircuit {
            rx_chunks: Vec<Result<Vec<u8>, io::ErrorKind>>,
            rx_idx: usize,
            tx_calls: usize,
            tx_written: Vec<u8>,
        }
        impl Read for NonBlockingCircuit {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.rx_idx >= self.rx_chunks.len() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let item = &self.rx_chunks[self.rx_idx];
                self.rx_idx += 1;
                match item {
                    Ok(bytes) => {
                        let take = bytes.len().min(out.len());
                        out[..take].copy_from_slice(&bytes[..take]);
                        Ok(take)
                    }
                    Err(kind) => Err((*kind).into()),
                }
            }
        }
        impl Write for NonBlockingCircuit {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.tx_calls += 1;
                if self.tx_calls == 1 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let take = buf.len().min(5);
                self.tx_written.extend_from_slice(&buf[..take]);
                Ok(take)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let (device, host) = VirtualTun::try_pair(8, 8, DEFAULT_MTU).expect("bounded pair");
        let local = identity(0x0201, NodeRole::Core);
        let peer = identity(0x0209, NodeRole::Edge);
        let mtu = DEFAULT_MTU;
        let out_pkt = ipv4([10, 20, 3, 1], [10, 20, 3, 9], b"outbound-nb");
        let in_pkt = ipv4([10, 20, 3, 9], [10, 20, 3, 1], b"inbound-nb");
        let in_frame = encode_packet_frame(&in_pkt, mtu).unwrap();
        device.inject(&out_pkt).expect("inject outbound");

        let circuit = NonBlockingCircuit {
            rx_chunks: vec![
                Ok(in_frame[..1].to_vec()),
                Err(io::ErrorKind::WouldBlock),
                Ok(in_frame[1..10].to_vec()),
                Err(io::ErrorKind::WouldBlock),
                Ok(in_frame[10..].to_vec()),
            ],
            rx_idx: 0,
            tx_calls: 0,
            tx_written: Vec::new(),
        };
        let mut path =
            PacketPath::try_new(&device, circuit, endpoints(local, peer), mtu).expect("bound path");

        // Outbound batch hits WouldBlock initially, buffers cleanly, and flushes on retry.
        assert_eq!(path.step_outbound_batch(16, 16_000), Ok(1));
        assert!(path.has_local_pending_write());
        assert_eq!(path.step_outbound_batch(16, 16_000), Ok(0));
        assert_eq!(path.flush_outbound(), Ok(true));
        assert!(!path.has_local_pending_write());

        // Inbound survives WouldBlock across prefix and body splits without poisoning.
        assert_eq!(path.step_inbound_nonblocking(), Ok(InboundStep::WouldBlock));
        assert!(path.has_partial_inbound());
        assert_eq!(path.step_inbound_nonblocking(), Ok(InboundStep::WouldBlock));
        assert_eq!(
            path.step_inbound_nonblocking(),
            Ok(InboundStep::Packet(in_pkt.len()))
        );
        assert!(!path.has_partial_inbound());
        assert_eq!(
            host.read_packet().unwrap().as_deref(),
            Some(in_pkt.as_slice())
        );
        assert!(path.is_open());
    }
}
