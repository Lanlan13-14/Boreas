//! Bounded packet bridge between complete IP packets and smoltcp's TCP stack.
//!
//! [`PacketRuntime`] owns one smoltcp [`Interface`], one [`SocketSet`], a real
//! [`TcpDnsServer`], and a medium-IP [`Device`] backed by two bounded packet
//! queues. It never opens or binds an operating-system socket: the DNS VIP is
//! only an address on the in-process interface, and all ingress/egress is
//! complete IP packets supplied/consumed through [`PacketRuntime::push_input`]
//! and [`PacketRuntime::pop_output`].
//!
//! UDP is deliberately not handled by smoltcp. Packets addressed to the DNS VIP
//! on UDP/53 are passed to the existing [`crate::packet::respond_packet`] path;
//! only TCP is fed to the smoltcp device. This keeps the two bounded C/H paths
//! separate and avoids a second UDP state machine.
//!
//! # This is a packet model, not an authentication authority
//!
//! The runtime never treats an IP source address, a caller-provided `bool`, or a
//! packet field as proof of identity. [`AuthenticatedSourceMap`] must be
//! implemented by the trusted Tunnel/Overlay consumer after it authenticates the
//! endpoint; the map returns the crate's typed
//! [`AuthenticatedPeerSource`] or `None`. The runtime calls it for every input
//! packet and passes the typed value to the UDP path; the same map is also used
//! as the TCP application authorizer. A Tunnel consumer that supplies a map
//! derived from an untrusted IP header would defeat this boundary.
//!
//! # Bounds and polling
//!
//! Input, queue-device ingress, and output are each fixed-capacity queues; one
//! `poll` drains at most `max_packets_per_poll` queued input packets, and the
//! packet byte limit comes from [`PacketConfig`]. Output-queue pressure drops a
//! packet and is left to TCP retransmission; queue insert failures are counted
//! in [`PacketPollStats`]. The caller must poll regularly even with no new input
//! so retransmission, ACK, FIN, and idle timers advance. This module does not
//! implement DNS-over-TCP itself; [`TcpDnsServer`] drives smoltcp's real
//! sequence/ACK/retransmit state machine.

use std::{
    collections::VecDeque,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use smoltcp::{
    iface::{Config, Interface, SocketSet, SocketStorage},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint},
};

use crate::{
    AuthoritativeDns, DnsError,
    dispatch::{ClientAuthorizer, DispatchError, QueryDispatcher},
    packet::{AuthenticatedPeerSource, PacketConfig, inspect_ip_packet, respond_packet_with},
    tcp::{DNS_TCP_PORT, TcpDnsConfig, TcpDnsError, TcpDnsServer, TcpSourceAuthorizer},
};

pub const DEFAULT_QUEUE_PACKETS: usize = 64;
pub const MAX_QUEUE_PACKETS: usize = 256;
pub const DEFAULT_MAX_PACKETS_PER_POLL: usize = 64;
/// Per-queue payload budget. The input, device-ingress, and output queues each
/// check `queue_packets * max_packet_bytes` against this value.
pub const MAX_QUEUED_BYTES_PER_QUEUE: usize = 2 * 1024 * 1024;
/// smoltcp documents 9216 as the maximum device MTU; larger values are refused
/// here even though the raw UDP packet path allows larger IP packets.
const MAX_DEVICE_MTU: usize = 9216;
const DNS_V6_PREFIX: u8 = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRuntimeError {
    InvalidConfiguration,
    InvalidPacket,
    PacketTooLarge,
    InputQueueFull,
    Tcp(TcpDnsError),
}

impl fmt::Display for PacketRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PacketRuntimeError {}

/// Typed source mapping supplied by the trusted packet-ingress owner.
///
/// Implementations must return `Some` only for a source address bound to an
/// authenticated, currently authorized Overlay peer. The runtime does not infer
/// identity from the observed IP header and never accepts a caller-supplied
/// `bool` as authorization. A Tunnel consumer is required to implement this
/// trait; this module only models the packet-side contract.
pub trait AuthenticatedSourceMap: Send + Sync {
    fn authenticated_source(&self, observed_source: IpAddr) -> Option<AuthenticatedPeerSource>;
}

/// Adapter so the TCP server uses exactly the same typed map as UDP without a
/// public blanket implementation that could constrain downstream types.
struct MapAuthorizer<'a, M, F>(&'a M, F);

impl<M: AuthenticatedSourceMap, F: Fn(AuthenticatedPeerSource) -> bool> MapAuthorizer<'_, M, F> {
    fn peer(&self, source: IpAddr) -> Option<AuthenticatedPeerSource> {
        self.0
            .authenticated_source(source)
            .filter(|peer| peer.address() == source && self.1(*peer))
    }
}

impl<M, F> TcpSourceAuthorizer for MapAuthorizer<'_, M, F>
where
    M: AuthenticatedSourceMap,
    F: Fn(AuthenticatedPeerSource) -> bool + Send + Sync,
{
    fn is_authorized_authenticated_peer(&self, source: IpAddr) -> bool {
        self.peer(source).is_some()
    }
}

#[derive(Clone, Debug)]
pub struct PacketRuntimeConfig {
    pub tcp: TcpDnsConfig,
    pub queue_packets: usize,
    pub max_packets_per_poll: usize,
    pub random_seed: u64,
}

impl Default for PacketRuntimeConfig {
    fn default() -> Self {
        Self {
            tcp: TcpDnsConfig::default(),
            queue_packets: DEFAULT_QUEUE_PACKETS,
            max_packets_per_poll: DEFAULT_MAX_PACKETS_PER_POLL,
            random_seed: 0,
        }
    }
}

impl PacketRuntimeConfig {
    fn validate(&self, max_packet_bytes: usize) -> bool {
        self.queue_packets != 0
            && self.queue_packets <= MAX_QUEUE_PACKETS
            && self.max_packets_per_poll != 0
            && self.max_packets_per_poll <= self.queue_packets
            && self
                .queue_packets
                .checked_mul(max_packet_bytes)
                .is_some_and(|bytes| bytes <= MAX_QUEUED_BYTES_PER_QUEUE)
    }
}

/// Counters for one [`PacketRuntime::poll`] call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketPollStats {
    pub input_drained: usize,
    pub udp_answered: usize,
    pub tcp_injected: usize,
    pub tcp_frames: usize,
    pub dropped_unauthenticated: usize,
    pub dropped_malformed: usize,
    pub dropped_unsupported: usize,
    pub dropped_queue_full: usize,
    pub output_queued: usize,
}

struct QueueRx(Vec<u8>);

impl RxToken for QueueRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct QueueTx {
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    max_packets: usize,
    max_packet_bytes: usize,
}

impl TxToken for QueueTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if len > self.max_packet_bytes {
            return result;
        }
        let Ok(mut queue) = self.outbound.lock() else {
            return result;
        };
        if queue.len() < self.max_packets {
            queue.push_back(packet);
        }
        result
    }
}

/// A medium-IP device backed by bounded ingress/egress packet queues. It has no
/// OS socket and no file descriptor; `receive` pops one complete IP packet.
struct QueueDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    max_packets: usize,
    max_packet_bytes: usize,
}

impl QueueDevice {
    fn new(max_packets: usize, max_packet_bytes: usize) -> Self {
        Self {
            inbound: VecDeque::with_capacity(max_packets),
            outbound: Arc::new(Mutex::new(VecDeque::with_capacity(max_packets))),
            max_packets,
            max_packet_bytes,
        }
    }

    fn push_inbound(&mut self, packet: Vec<u8>) -> bool {
        if packet.len() > self.max_packet_bytes || self.inbound.len() >= self.max_packets {
            return false;
        }
        self.inbound.push_back(packet);
        true
    }

    fn push_outbound(&self, packet: Vec<u8>) -> bool {
        if packet.len() > self.max_packet_bytes {
            return false;
        }
        let Ok(mut queue) = self.outbound.lock() else {
            return false;
        };
        if queue.len() >= self.max_packets {
            return false;
        }
        queue.push_back(packet);
        true
    }

    fn pop_outbound(&self) -> Option<Vec<u8>> {
        let mut queue = self.outbound.lock().ok()?;
        queue.pop_front()
    }

    fn output_len(&self) -> usize {
        self.outbound.lock().map_or(0, |queue| queue.len())
    }

    fn tx_token(&self) -> QueueTx {
        QueueTx {
            outbound: self.outbound.clone(),
            max_packets: self.max_packets,
            max_packet_bytes: self.max_packet_bytes,
        }
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx;

    fn receive(&mut self, _timestamp: Instant) -> Option<(QueueRx, QueueTx)> {
        let packet = self.inbound.pop_front()?;
        Some((QueueRx(packet), self.tx_token()))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<QueueTx> {
        Some(self.tx_token())
    }

    // smoltcp's DeviceCapabilities is #[non_exhaustive]; field assignment is the
    // supported construction path.
    #[allow(clippy::field_reassign_with_default)]
    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.max_packet_bytes;
        capabilities
    }
}

/// One bounded, in-process DNS packet endpoint.
pub struct PacketRuntime<D = AuthoritativeDns> {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    tcp: TcpDnsServer,
    dns: D,
    packet_config: PacketConfig,
    listen: IpAddress,
    listen_ip: IpAddr,
    input: VecDeque<Vec<u8>>,
    queue_packets: usize,
    max_packets_per_poll: usize,
}

impl PacketRuntime {
    /// Build the interface, socket set, and real TCP listener for one DNS VIP.
    ///
    /// `listen` must be exactly the IPv4 or IPv6 DNS VIP from `packet_config`.
    /// The interface gets that VIP with the signed network prefix; no host stack
    /// address or OS socket is touched. UDP is handled by the existing packet
    /// path for both families, while TCP is accepted only on `listen`.
    pub fn new(
        dns: AuthoritativeDns,
        packet_config: PacketConfig,
        listen: IpAddress,
        config: PacketRuntimeConfig,
    ) -> Result<Self, PacketRuntimeError> {
        Self::with_backend(dns, packet_config, listen, config)
    }

    /// Drive the legacy packet model with its explicit source map and authority.
    pub fn poll<M: AuthenticatedSourceMap>(
        &mut self,
        now: Instant,
        sources: &M,
    ) -> PacketPollStats {
        self.poll_with(
            now,
            sources,
            |_| true,
            |dns, peer, query, udp| {
                if udp.is_some() {
                    dns.respond_udp(peer.address(), query)
                } else {
                    dns.respond_tcp(peer.address(), query)
                }
            },
        )
    }
}

impl<A: ClientAuthorizer> PacketRuntime<QueryDispatcher<A>> {
    /// Own a single dispatcher for both packet transports. Polling this
    /// runtime never uses the dispatcher's blocking/public upstream path.
    /// This constructor requires an IPv4-only packet configuration.
    pub fn new_private_dispatcher(
        dispatcher: QueryDispatcher<A>,
        packet_config: PacketConfig,
        config: PacketRuntimeConfig,
    ) -> Result<Self, PacketRuntimeError> {
        if packet_config.dns_v6().is_some() {
            return Err(PacketRuntimeError::InvalidConfiguration);
        }
        Self::with_backend(
            dispatcher,
            packet_config,
            IpAddress::Ipv4(packet_config.dns_v4()),
            config,
        )
    }

    /// Drive private UDP and real TCP together. The owner must keep the same
    /// authenticated binding through queueing, polls, and final delivery;
    /// destroy the runtime (including TCP buffers) on binding invalidation.
    pub fn poll_private<M: AuthenticatedSourceMap>(
        &mut self,
        elapsed_millis: i64,
        sources: &M,
    ) -> PacketPollStats {
        self.poll_with(
            Instant::from_millis(elapsed_millis),
            sources,
            QueryDispatcher::permits_private_packet_peer,
            |dispatcher, peer, query, udp| match dispatcher
                .dispatch_private_packet(peer, query, udp)
            {
                Ok(response) => Ok(Some(response)),
                Err(
                    DispatchError::InvalidQuery(error) | DispatchError::AuthorityResponse(error),
                ) => Err(error),
                Err(_) => Ok(None),
            },
        )
    }
}

impl<D> PacketRuntime<D> {
    fn with_backend(
        dns: D,
        packet_config: PacketConfig,
        listen: IpAddress,
        config: PacketRuntimeConfig,
    ) -> Result<Self, PacketRuntimeError> {
        let max_packet_bytes = packet_config.max_packet_bytes();
        if max_packet_bytes > MAX_DEVICE_MTU || !config.validate(max_packet_bytes) {
            return Err(PacketRuntimeError::InvalidConfiguration);
        }
        let PacketRuntimeConfig {
            tcp,
            queue_packets,
            max_packets_per_poll,
            random_seed,
        } = config;
        let listen_ip = match listen {
            IpAddress::Ipv4(address) => IpAddr::V4(address),
            IpAddress::Ipv6(address) => IpAddr::V6(address),
        };
        if listen_ip != IpAddr::V4(packet_config.dns_v4())
            && Some(listen_ip) != packet_config.dns_v6().map(IpAddr::V6)
        {
            return Err(PacketRuntimeError::InvalidConfiguration);
        }
        let prefix = match listen {
            IpAddress::Ipv4(_) => packet_config.ipv4_network().1,
            IpAddress::Ipv6(_) => DNS_V6_PREFIX,
        };

        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = random_seed;
        let mut device = QueueDevice::new(queue_packets, max_packet_bytes);
        let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
        let mut address_error = false;
        iface.update_ip_addrs(|addrs| {
            if addrs.push(IpCidr::new(listen, prefix)).is_err() {
                address_error = true;
            }
        });
        if address_error {
            return Err(PacketRuntimeError::InvalidConfiguration);
        }

        let mut sockets = SocketSet::new(Vec::<SocketStorage<'static>>::new());
        let endpoint = IpListenEndpoint {
            addr: Some(listen),
            port: DNS_TCP_PORT,
        };
        let tcp =
            TcpDnsServer::new(tcp, endpoint, &mut sockets).map_err(PacketRuntimeError::Tcp)?;
        Ok(Self {
            iface,
            device,
            sockets,
            tcp,
            dns,
            packet_config,
            listen,
            listen_ip,
            input: VecDeque::with_capacity(queue_packets),
            queue_packets,
            max_packets_per_poll,
        })
    }

    /// Queue one complete IP packet received from the trusted endpoint. This
    /// only performs size/queue-bound checks; authentication happens in `poll`
    /// through [`AuthenticatedSourceMap`].
    pub fn push_input(&mut self, packet: &[u8]) -> Result<(), PacketRuntimeError> {
        if packet.is_empty() {
            return Err(PacketRuntimeError::InvalidPacket);
        }
        if packet.len() > self.packet_config.max_packet_bytes() {
            return Err(PacketRuntimeError::PacketTooLarge);
        }
        if self.input.len() >= self.queue_packets {
            return Err(PacketRuntimeError::InputQueueFull);
        }
        self.input.push_back(packet.to_vec());
        Ok(())
    }

    /// Pop one complete IP packet to deliver to the trusted endpoint. Returns
    /// `None` when no output is queued.
    pub fn pop_output(&self) -> Option<Vec<u8>> {
        self.device.pop_outbound()
    }

    /// Process queued input, run the real smoltcp TCP state machine, and advance
    /// timers. Call regularly even when no new input is queued so retransmission,
    /// ACK, FIN, and idle timers progress. `sources` is the trusted typed map;
    /// an unauthorized source is dropped before it reaches smoltcp or the UDP
    /// handler.
    fn poll_with<M, F>(
        &mut self,
        now: Instant,
        sources: &M,
        permits: F,
        answer: impl Fn(
            &D,
            AuthenticatedPeerSource,
            &[u8],
            Option<usize>,
        ) -> Result<Option<Vec<u8>>, DnsError>,
    ) -> PacketPollStats
    where
        M: AuthenticatedSourceMap,
        F: Fn(&D, AuthenticatedPeerSource) -> bool + Send + Sync,
        D: Sync,
    {
        let authorizer = MapAuthorizer(sources, |peer| permits(&self.dns, peer));
        let max_packet_bytes = self.packet_config.max_packet_bytes();
        let dns_v4 = IpAddr::V4(self.packet_config.dns_v4());
        let dns_v6 = self.packet_config.dns_v6().map(IpAddr::V6);
        let mut stats = PacketPollStats::default();

        for _ in 0..self.max_packets_per_poll {
            let Some(packet) = self.input.pop_front() else {
                break;
            };
            stats.input_drained += 1;
            let meta = match inspect_ip_packet(&packet, max_packet_bytes) {
                Ok(meta) => meta,
                Err(_) => {
                    stats.dropped_malformed += 1;
                    continue;
                }
            };
            let Some(peer) = authorizer.peer(meta.source) else {
                stats.dropped_unauthenticated += 1;
                continue;
            };
            if meta.destination != dns_v4 && Some(meta.destination) != dns_v6 {
                stats.dropped_unsupported += 1;
                continue;
            }
            match meta.protocol {
                17 => match respond_packet_with(
                    self.packet_config,
                    peer,
                    &packet,
                    |_, query, ceiling| answer(&self.dns, peer, query, Some(ceiling)),
                ) {
                    Ok(Some(response)) => {
                        if self.device.push_outbound(response) {
                            stats.udp_answered += 1;
                        } else {
                            stats.dropped_queue_full += 1;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => stats.dropped_malformed += 1,
                },
                6 => {
                    let is_dns_tcp = meta.destination == self.listen_ip
                        && tcp_destination_port(&packet, meta.header_len) == Some(DNS_TCP_PORT);
                    if !is_dns_tcp {
                        stats.dropped_unsupported += 1;
                    } else if self.device.push_inbound(packet) {
                        stats.tcp_injected += 1;
                    } else {
                        stats.dropped_queue_full += 1;
                    }
                }
                _ => stats.dropped_unsupported += 1,
            }
        }

        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
        stats.tcp_frames =
            self.tcp
                .process_with(
                    &mut self.sockets,
                    &authorizer,
                    now,
                    |source, query| match authorizer.peer(source) {
                        Some(peer) => answer(&self.dns, peer, query, None),
                        None => Ok(None),
                    },
                );
        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
        stats.output_queued = self.device.output_len();
        stats
    }

    pub fn listen(&self) -> IpAddress {
        self.listen
    }

    pub const fn dns_v4(&self) -> std::net::Ipv4Addr {
        self.packet_config.dns_v4()
    }

    pub fn dns_v6(&self) -> Option<std::net::Ipv6Addr> {
        self.packet_config.dns_v6()
    }

    pub const fn max_packet_bytes(&self) -> usize {
        self.packet_config.max_packet_bytes()
    }

    pub fn input_len(&self) -> usize {
        self.input.len()
    }

    pub fn output_len(&self) -> usize {
        self.device.output_len()
    }

    pub fn tcp_connection_capacity(&self) -> usize {
        self.tcp.connection_capacity()
    }
}

fn tcp_destination_port(packet: &[u8], header_len: usize) -> Option<u16> {
    let start = header_len.checked_add(2)?;
    let end = start.checked_add(2)?;
    let bytes = packet.get(start..end)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    // The client side below is an in-memory test Device used only to generate
    // and consume real IP/TCP packets. The server under test is the production
    // PacketRuntime: its QueueDevice, Interface, SocketSet, and TcpDnsServer are
    // not mocked; packets cross the boundary as complete IP datagrams.
    use super::*;
    use crate::{
        AuthoritativeDns, SourceAuthorization, Zone,
        packet::{PacketConfig, TrustedDnsGenesis, checksum},
    };
    use smoltcp::{
        iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage},
        phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
        socket::tcp::{self, SocketBuffer},
        time::Instant,
        wire::{HardwareAddress, IpAddress, IpCidr},
    };
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::{Arc, Mutex},
    };

    const SERVER4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 53);
    const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 2);
    const SERVER6: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 0x53);
    const ULA48: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 0);

    #[derive(Clone)]
    struct TestLink {
        inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
        outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl TestLink {
        fn new() -> Self {
            Self {
                inbound: Arc::new(Mutex::new(VecDeque::new())),
                outbound: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn take_outbound(&self) -> Option<Vec<u8>> {
            self.outbound.lock().ok()?.pop_front()
        }

        fn push_inbound(&self, packet: Vec<u8>) {
            if let Ok(mut queue) = self.inbound.lock() {
                queue.push_back(packet);
            }
        }
    }

    struct TestRx(Vec<u8>);

    impl RxToken for TestRx {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.0)
        }
    }

    struct TestTx {
        queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl TxToken for TestTx {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut packet = vec![0u8; len];
            let result = f(&mut packet);
            if let Ok(mut queue) = self.queue.lock() {
                queue.push_back(packet);
            }
            result
        }
    }

    impl Device for TestLink {
        type RxToken<'a> = TestRx;
        type TxToken<'a> = TestTx;

        fn receive(&mut self, _timestamp: Instant) -> Option<(TestRx, TestTx)> {
            let packet = self.inbound.lock().ok()?.pop_front()?;
            Some((TestRx(packet), TestTx {
                queue: self.outbound.clone(),
            }))
        }

        fn transmit(&mut self, _timestamp: Instant) -> Option<TestTx> {
            Some(TestTx {
                queue: self.outbound.clone(),
            })
        }

        // smoltcp's DeviceCapabilities is #[non_exhaustive].
        #[allow(clippy::field_reassign_with_default)]
        fn capabilities(&self) -> DeviceCapabilities {
            let mut capabilities = DeviceCapabilities::default();
            capabilities.medium = Medium::Ip;
            capabilities.max_transmission_unit = 1500;
            capabilities
        }
    }

    struct Side {
        iface: Interface,
        sockets: SocketSet<'static>,
        device: TestLink,
    }

    fn genesis() -> TrustedDnsGenesis {
        TrustedDnsGenesis::new((Ipv4Addr::new(10, 20, 0, 0), 16), ULA48, SERVER4, SERVER6).unwrap()
    }

    fn packet_config() -> PacketConfig {
        PacketConfig::new(genesis(), 1500).unwrap()
    }

    fn dns() -> AuthoritativeDns {
        let mut zone = Zone::new("corp.example").unwrap();
        zone.add_address(
            "host.corp.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        )
        .unwrap();
        AuthoritativeDns::new(zone, SourceAuthorization::new([IpAddr::V4(CLIENT4)]), 1232).unwrap()
    }

    struct AllowClient;

    impl AuthenticatedSourceMap for AllowClient {
        fn authenticated_source(&self, observed_source: IpAddr) -> Option<AuthenticatedPeerSource> {
            if observed_source == IpAddr::V4(CLIENT4) {
                AuthenticatedPeerSource::from_authenticated_overlay_peer(observed_source).ok()
            } else {
                None
            }
        }
    }

    struct DenyAll;

    impl AuthenticatedSourceMap for DenyAll {
        fn authenticated_source(
            &self,
            _observed_source: IpAddr,
        ) -> Option<AuthenticatedPeerSource> {
            None
        }
    }

    fn client_side(ip: IpAddress, seed: u64) -> Side {
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut device = TestLink::new();
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(match ip {
                    IpAddress::Ipv4(address) => IpCidr::new(IpAddress::Ipv4(address), 16),
                    IpAddress::Ipv6(address) => IpCidr::new(IpAddress::Ipv6(address), 48),
                })
                .unwrap();
        });
        Side {
            iface,
            sockets: SocketSet::new(Vec::<SocketStorage<'static>>::new()),
            device,
        }
    }

    fn server(seed: u64) -> PacketRuntime {
        PacketRuntime::new(
            dns(),
            packet_config(),
            IpAddress::Ipv4(SERVER4),
            PacketRuntimeConfig {
                random_seed: seed,
                ..PacketRuntimeConfig::default()
            },
        )
        .unwrap()
    }

    fn transfer<M: AuthenticatedSourceMap>(
        client: &mut Side,
        runtime: &mut PacketRuntime,
        now: i64,
        sources: &M,
    ) -> PacketPollStats {
        transfer_with(client, runtime, now, |runtime, now| {
            runtime.poll(Instant::from_millis(now), sources)
        })
    }

    fn transfer_with<D>(
        client: &mut Side,
        runtime: &mut PacketRuntime<D>,
        now: i64,
        poll: impl FnOnce(&mut PacketRuntime<D>, i64) -> PacketPollStats,
    ) -> PacketPollStats {
        let time = Instant::from_millis(now);
        let _ = client
            .iface
            .poll(time, &mut client.device, &mut client.sockets);
        while let Some(packet) = client.device.take_outbound() {
            runtime.push_input(&packet).unwrap();
        }
        let stats = poll(runtime, now);
        while let Some(packet) = runtime.pop_output() {
            client.device.push_inbound(packet);
        }
        let _ = client
            .iface
            .poll(time, &mut client.device, &mut client.sockets);
        stats
    }

    fn start_connect(client: &mut Side, local_port: u16) -> SocketHandle {
        let handle = client.sockets.add(tcp::Socket::new(
            SocketBuffer::new(vec![0u8; 8192]),
            SocketBuffer::new(vec![0u8; 8192]),
        ));
        client
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(
                client.iface.context(),
                (IpAddress::Ipv4(SERVER4), DNS_TCP_PORT),
                local_port,
            )
            .unwrap();
        handle
    }

    fn connect(
        client: &mut Side,
        runtime: &mut PacketRuntime,
        sources: &impl AuthenticatedSourceMap,
        local_port: u16,
    ) -> SocketHandle {
        let handle = start_connect(client, local_port);
        for n in 0..12 {
            transfer(client, runtime, 10 + n * 10, sources);
            if client.sockets.get::<tcp::Socket>(handle).may_send() {
                return handle;
            }
        }
        panic!("TCP handshake did not complete");
    }

    fn receive_tcp(sockets: &mut SocketSet<'static>, handle: SocketHandle, out: &mut Vec<u8>) {
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        while socket.can_recv() {
            let mut buffer = [0u8; 1024];
            match socket.recv_slice(&mut buffer) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buffer[..n]),
                Err(_) => break,
            }
        }
    }

    fn query(id: u16) -> Vec<u8> {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[
            1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'h', b'o', b's', b't', 4, b'c', b'o', b'r', b'p', 7,
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
        ]);
        query
    }

    fn framed(query: &[u8]) -> Vec<u8> {
        let mut frame = (query.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(query);
        frame
    }

    fn udp_query_packet(query: &[u8]) -> Vec<u8> {
        let udp_len = 8 + query.len();
        let total = 20 + udp_len;
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&CLIENT4.octets());
        packet[16..20].copy_from_slice(&SERVER4.octets());
        let header_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet[20..22].copy_from_slice(&40_000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&DNS_TCP_PORT.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(query);
        packet
    }

    #[test]
    fn real_syn_synack_ack_split_query_and_framed_response() {
        let mut client = client_side(IpAddress::Ipv4(CLIENT4), 11);
        let mut runtime = server(7);
        let sources = AllowClient;
        let handle = connect(&mut client, &mut runtime, &sources, 53_000);
        let frame = framed(&query(0x1234));

        client
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&frame[..1])
            .unwrap();
        let _ = transfer(&mut client, &mut runtime, 200, &sources);
        client
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&frame[1..])
            .unwrap();

        let mut got = Vec::new();
        let mut frames = 0usize;
        for n in 0..16 {
            let stats = transfer(&mut client, &mut runtime, 210 + n * 10, &sources);
            frames += stats.tcp_frames;
            receive_tcp(&mut client.sockets, handle, &mut got);
            if got.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([got[0], got[1]]));
                if got.len() >= len + 2 {
                    break;
                }
            }
        }
        assert!(frames >= 1, "server did not process a DNS TCP frame");
        assert!(got.len() >= 2, "no length prefix");
        let len = usize::from(u16::from_be_bytes([got[0], got[1]]));
        assert_eq!(got.len(), len + 2, "exactly one complete framed response");
        assert_eq!(&got[2..4], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([got[8], got[9]]), 1);

        client.sockets.get_mut::<tcp::Socket>(handle).close();
        let mut closed = false;
        for n in 0..12 {
            let _ = transfer(&mut client, &mut runtime, 400 + n * 10, &sources);
            if !client.sockets.get::<tcp::Socket>(handle).may_recv() {
                closed = true;
                break;
            }
        }
        assert!(closed, "server FIN not observed after half-close");
    }

    impl ClientAuthorizer for AllowClient {
        fn authorized_node(&self, peer: AuthenticatedPeerSource) -> Option<u16> {
            (peer.address() == IpAddr::V4(CLIENT4)).then_some(2)
        }
    }

    #[test]
    fn private_dispatcher_uses_real_tcp_and_never_calls_configured_upstream() {
        use crate::{MAX_RESPONSE_BYTES, dispatch::AuthoritySnapshot, upstream::TcpUpstream};
        use std::{
            net::TcpListener,
            time::{Duration, Instant as Mono},
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let upstream = TcpUpstream::new(
            listener.local_addr().unwrap(),
            Duration::from_millis(50),
            MAX_RESPONSE_BYTES,
        )
        .unwrap();
        let now = Mono::now();
        let snapshot = AuthoritySnapshot::new(dns(), now, now + Duration::from_secs(60)).unwrap();
        let dispatcher =
            QueryDispatcher::new("corp.example", Some(snapshot), Some(upstream), AllowClient)
                .unwrap();
        let mut runtime = PacketRuntime::new_private_dispatcher(
            dispatcher,
            PacketConfig::new_ipv4(Ipv4Addr::new(10, 20, 0, 0), 1500).unwrap(),
            PacketRuntimeConfig::default(),
        )
        .unwrap();
        let mut client = client_side(IpAddress::Ipv4(CLIENT4), 11);
        let handle = start_connect(&mut client, 53_000);
        let poll = |runtime: &mut PacketRuntime<_>, now| runtime.poll_private(now, &AllowClient);
        for step in 1..=12 {
            transfer_with(&mut client, &mut runtime, step * 10, poll);
        }
        assert!(client.sockets.get::<tcp::Socket>(handle).may_send());
        client
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&framed(&query(0x5678)))
            .unwrap();
        let mut got = Vec::new();
        for step in 13..=28 {
            transfer_with(&mut client, &mut runtime, step * 10, poll);
            receive_tcp(&mut client.sockets, handle, &mut got);
        }
        assert!(got.len() >= 10);
        assert_eq!(&got[2..4], &[0x56, 0x78]);
        assert_eq!(&got[8..10], &[0, 1]);

        let mut public = query(0x6789);
        public[18] = b'x'; // corp.example -> xorp.example
        runtime.push_input(&udp_query_packet(&public)).unwrap();
        assert_eq!(runtime.poll_private(290, &AllowClient).udp_answered, 0);
        assert!(runtime.pop_output().is_none());
        client
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&framed(&public))
            .unwrap();
        got.clear();
        for step in 30..=44 {
            transfer_with(&mut client, &mut runtime, step * 10, poll);
            receive_tcp(&mut client.sockets, handle, &mut got);
        }
        assert!(got.is_empty());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn unauthorized_source_never_reaches_the_tcp_stack() {
        let mut client = client_side(IpAddress::Ipv4(CLIENT4), 12);
        let mut runtime = server(8);
        let handle = start_connect(&mut client, 53_001);
        let mut dropped = 0usize;
        for n in 0..8 {
            let stats = transfer(&mut client, &mut runtime, 10 + n * 10, &DenyAll);
            dropped += stats.dropped_unauthenticated;
        }
        assert!(dropped > 0, "typed map did not reject the SYN source");
        assert!(!client.sockets.get::<tcp::Socket>(handle).may_send());
    }

    #[test]
    fn udp_packet_reuses_the_existing_handler() {
        let mut runtime = server(9);
        let query = query(0x4321);
        let packet = udp_query_packet(&query);
        runtime.push_input(&packet).unwrap();
        let stats = runtime.poll(Instant::from_millis(10), &AllowClient);
        assert_eq!(stats.udp_answered, 1);
        assert_eq!(stats.output_queued, 1);
        let response = runtime.pop_output().expect("UDP response");
        let meta = crate::packet::inspect_ip_packet(&response, 1500).unwrap();
        assert_eq!(meta.source, IpAddr::V4(SERVER4));
        assert_eq!(meta.destination, IpAddr::V4(CLIENT4));
        let udp = &response[meta.header_len..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), DNS_TCP_PORT);
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 40_000);
        let dns = &udp[8..];
        assert_eq!(&dns[0..2], &[0x43, 0x21]);
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1);
        assert!(runtime.pop_output().is_none());
    }

    #[test]
    fn queues_and_config_are_bounded() {
        let error = PacketRuntime::new(
            dns(),
            packet_config(),
            IpAddress::Ipv4(SERVER4),
            PacketRuntimeConfig {
                queue_packets: 0,
                ..PacketRuntimeConfig::default()
            },
        )
        .err();
        assert_eq!(error, Some(PacketRuntimeError::InvalidConfiguration));

        let error = PacketRuntime::new(
            dns(),
            packet_config(),
            IpAddress::Ipv4(Ipv4Addr::new(10, 20, 0, 54)),
            PacketRuntimeConfig::default(),
        )
        .err();
        assert_eq!(error, Some(PacketRuntimeError::InvalidConfiguration));

        let mut runtime = PacketRuntime::new(
            dns(),
            packet_config(),
            IpAddress::Ipv4(SERVER4),
            PacketRuntimeConfig {
                queue_packets: 1,
                max_packets_per_poll: 1,
                ..PacketRuntimeConfig::default()
            },
        )
        .unwrap();
        let packet = udp_query_packet(&query(1));
        runtime.push_input(&packet).unwrap();
        assert_eq!(
            runtime.push_input(&packet),
            Err(PacketRuntimeError::InputQueueFull)
        );
        assert_eq!(
            runtime.push_input(&[]),
            Err(PacketRuntimeError::InvalidPacket)
        );
        assert_eq!(
            runtime.push_input(&vec![0u8; 1501]),
            Err(PacketRuntimeError::PacketTooLarge)
        );
    }
}
