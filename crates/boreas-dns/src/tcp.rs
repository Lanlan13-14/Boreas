//! Bounded DNS-over-TCP endpoint driven by smoltcp's real TCP state machine.
//!
//! The embedding process owns and polls the `Interface`/`Device`; this server
//! owns a fixed pool of listening TCP sockets and bounded DNS framing state.
//! It never opens or binds an operating-system socket.

use std::{net::IpAddr, time::Duration};

use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::tcp,
    wire::{IpAddress, IpListenEndpoint},
};

use crate::{AuthoritativeDns, MAX_QUERY_BYTES, MAX_RESPONSE_BYTES};

pub const DNS_TCP_PORT: u16 = 53;
pub const DEFAULT_MAX_CONNECTIONS: usize = 8;
pub const MAX_TCP_CONNECTIONS: usize = 64;
pub const MAX_TCP_BUFFER_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TCP_BUFFER_BYTES_PER_CONNECTION: usize = 128 * 1024;
pub const DEFAULT_RX_BYTES_PER_CONNECTION: usize = 8192;
pub const DEFAULT_TX_BYTES_PER_CONNECTION: usize = 8192;
pub const DEFAULT_MAX_FRAMES_PER_POLL: usize = 16;
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpDnsError {
    InvalidConfiguration,
    SocketPoolFull,
}

/// Explicit resource ceilings. Aggregate socket buffers are checked and bounded
/// to at most `max_connections * (rx_bytes_per_connection + tx_bytes_per_connection)`.
#[derive(Clone, Debug)]
pub struct TcpDnsConfig {
    pub max_connections: usize,
    pub rx_bytes_per_connection: usize,
    pub tx_bytes_per_connection: usize,
    pub max_frame_bytes: usize,
    pub max_frames_per_poll: usize,
    pub idle_timeout: Duration,
}

impl Default for TcpDnsConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            rx_bytes_per_connection: DEFAULT_RX_BYTES_PER_CONNECTION,
            tx_bytes_per_connection: DEFAULT_TX_BYTES_PER_CONNECTION,
            max_frame_bytes: MAX_QUERY_BYTES,
            max_frames_per_poll: DEFAULT_MAX_FRAMES_PER_POLL,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

impl TcpDnsConfig {
    fn validate(&self) -> Result<(), TcpDnsError> {
        if self.max_connections == 0
            || self.max_connections > MAX_TCP_CONNECTIONS
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > MAX_QUERY_BYTES
            || self.rx_bytes_per_connection < self.max_frame_bytes + 2
            || self.tx_bytes_per_connection < MAX_RESPONSE_BYTES + 2
            || self.rx_bytes_per_connection > MAX_TCP_BUFFER_BYTES_PER_CONNECTION
            || self.tx_bytes_per_connection > MAX_TCP_BUFFER_BYTES_PER_CONNECTION
            || self.max_frames_per_poll == 0
            || self.max_frames_per_poll > 1024
            || self.idle_timeout.is_zero()
            || self
                .max_frame_bytes
                .checked_add(2)
                .is_none_or(|n| n > self.rx_bytes_per_connection)
            || self
                .rx_bytes_per_connection
                .checked_add(self.tx_bytes_per_connection)
                .and_then(|n| n.checked_add(self.max_frame_bytes + 2))
                .and_then(|n| n.checked_add(self.tx_bytes_per_connection))
                .and_then(|n| n.checked_add(MAX_RESPONSE_BYTES + 2))
                .and_then(|n| n.checked_mul(self.max_connections))
                .is_none_or(|n| n > MAX_TCP_BUFFER_BYTES)
        {
            return Err(TcpDnsError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Trusted binding supplied by the Overlay/authentication layer. It must answer
/// true only when the authenticated peer owning this source address is still
/// authorized for DNS. Implementations must not infer identity solely from an
/// untrusted IP header. The DNS resolver's separate address allowlist is also
/// enforced by `AuthoritativeDns::respond_tcp`.
pub trait TcpSourceAuthorizer: Send + Sync {
    fn is_authorized_authenticated_peer(&self, source: IpAddr) -> bool;
}

#[derive(Debug)]
struct Connection {
    handle: SocketHandle,
    receive: Vec<u8>,
    transmit: Vec<u8>,
    transmit_offset: usize,
    last_activity: smoltcp::time::Instant,
    active: bool,
    peer_closed: bool,
}

/// Fixed TCP socket pool. Every socket is a real smoltcp TCP endpoint, so
/// SYN/ACK, sequence numbers, ACKs, retransmission, flow control, and FIN/RST
/// are handled by smoltcp when the caller polls its interface.
pub struct TcpDnsServer {
    config: TcpDnsConfig,
    listen: IpListenEndpoint,
    connections: Vec<Connection>,
}

impl TcpDnsServer {
    /// Allocate the bounded socket pool into an existing smoltcp socket set and
    /// place each socket in LISTEN on port 53. The socket set must be polled by
    /// the caller with the same `Interface` and `Device` that own the DNS VIP.
    pub fn new(
        config: TcpDnsConfig,
        listen: IpListenEndpoint,
        sockets: &mut SocketSet<'static>,
    ) -> Result<Self, TcpDnsError> {
        config.validate()?;
        if listen.port != DNS_TCP_PORT || listen.addr.is_none() {
            return Err(TcpDnsError::InvalidConfiguration);
        }
        if sockets
            .iter()
            .count()
            .checked_add(config.max_connections)
            .is_none()
        {
            return Err(TcpDnsError::SocketPoolFull);
        }
        let mut connections = Vec::with_capacity(config.max_connections);
        let mut added_handles = Vec::with_capacity(config.max_connections);
        for _ in 0..config.max_connections {
            let socket = tcp::Socket::new(
                vec![0; config.rx_bytes_per_connection],
                vec![0; config.tx_bytes_per_connection],
            );
            let handle = sockets.add(socket);
            added_handles.push(handle);
            let listen_result = sockets.get_mut::<tcp::Socket>(handle).listen(listen);
            if listen_result.is_err() {
                for added in added_handles.into_iter().rev() {
                    let _ = sockets.remove(added);
                }
                return Err(TcpDnsError::SocketPoolFull);
            }
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            socket.set_timeout(Some(duration_to_smoltcp(config.idle_timeout)));
            connections.push(Connection {
                handle,
                receive: Vec::with_capacity(config.max_frame_bytes + 2),
                transmit: Vec::with_capacity(config.tx_bytes_per_connection),
                transmit_offset: 0,
                last_activity: smoltcp::time::Instant::from_millis(0),
                active: false,
                peer_closed: false,
            });
        }
        Ok(Self {
            config,
            listen,
            connections,
        })
    }

    pub fn connection_capacity(&self) -> usize {
        self.connections.len()
    }

    /// Consume available TCP stream bytes and enqueue DNS frames. Call after
    /// each interface poll; each invocation handles at most `max_frames_per_poll`
    /// complete DNS queries in total. TCP socket buffers, per-connection parser
    /// state, pending TX, and total connection slots are bounded by config.
    pub fn process<A: TcpSourceAuthorizer>(
        &mut self,
        sockets: &mut SocketSet<'static>,
        dns: &AuthoritativeDns,
        authorizer: &A,
        now: smoltcp::time::Instant,
    ) -> usize {
        let mut completed = 0usize;
        for conn in &mut self.connections {
            let socket = sockets.get_mut::<tcp::Socket>(conn.handle);
            if socket.is_listening() {
                continue;
            }
            if socket.state() == tcp::State::Closed {
                reset_connection(conn, now);
                let _ = socket.listen(self.listen);
                continue;
            }
            if !socket.is_open() {
                // TIME-WAIT remains owned by smoltcp until its timer expires;
                // do not attempt to listen on that still-live state.
                continue;
            }
            if socket.is_active() && !conn.active {
                conn.active = true;
                conn.last_activity = now;
            }
            if socket.is_active()
                && now - conn.last_activity >= duration_to_smoltcp(self.config.idle_timeout)
            {
                socket.abort();
                reset_connection(conn, now);
                continue;
            }

            // Passive LISTEN sockets and embryonic states do not have a peer
            // application stream. Never unwrap a missing remote endpoint.
            let Some(endpoint) = socket.remote_endpoint() else {
                continue;
            };
            let source = remote_ip(Some(endpoint));
            if !socket.is_active() || !authorizer.is_authorized_authenticated_peer(source) {
                if socket.is_active() {
                    socket.abort();
                    reset_connection(conn, now);
                }
                continue;
            }

            // Flush only a bounded amount into smoltcp's fixed send buffer.
            if conn.transmit_offset < conn.transmit.len() && socket.can_send() {
                let left = &conn.transmit[conn.transmit_offset..];
                match socket.send_slice(left) {
                    Ok(n) => conn.transmit_offset += n,
                    Err(_) => {
                        socket.abort();
                        reset_connection(conn, now);
                        continue;
                    }
                }
                if conn.transmit_offset == conn.transmit.len() {
                    conn.transmit.clear();
                    conn.transmit_offset = 0;
                }
            }

            // Process frames already buffered from an earlier poll before
            // reading more stream data; this is necessary when a response
            // temporarily filled the application TX staging buffer.
            if !extract_frames(conn, source, dns, &self.config, &mut completed) {
                socket.abort();
                reset_connection(conn, now);
                continue;
            }
            // TCP.recv_slice returns bytes in-order after smoltcp reassembly and
            // sequence processing; it does not read or synthesize raw segments.
            while socket.can_recv()
                && conn.receive.len() < self.config.max_frame_bytes + 2
                && completed < self.config.max_frames_per_poll
            {
                let remaining = self.config.max_frame_bytes + 2 - conn.receive.len();
                let mut chunk = [0u8; 1024];
                let take = remaining.min(chunk.len());
                match socket.recv_slice(&mut chunk[..take]) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.receive.extend_from_slice(&chunk[..n]);
                        conn.last_activity = now;
                    }
                    Err(_) => break,
                }
                if !extract_frames(conn, source, dns, &self.config, &mut completed) {
                    socket.abort();
                    reset_connection(conn, now);
                    break;
                }
                if completed >= self.config.max_frames_per_poll {
                    break;
                }
            }
            if completed >= self.config.max_frames_per_poll {
                break;
            }
            // FIN with an incomplete DNS frame is invalid. FIN after complete
            // requests permits queued response transmission before local close.
            if !socket.may_recv() {
                if !conn.receive.is_empty() {
                    socket.abort();
                    reset_connection(conn, now);
                } else {
                    conn.peer_closed = true;
                }
            }
            if conn.peer_closed
                && conn.transmit.is_empty()
                && socket.send_queue() == 0
                && socket.may_send()
            {
                socket.close();
            }
        }
        completed
    }
}

fn extract_frames(
    conn: &mut Connection,
    source: IpAddr,
    dns: &AuthoritativeDns,
    config: &TcpDnsConfig,
    completed: &mut usize,
) -> bool {
    loop {
        if conn.receive.len() < 2 {
            return true;
        }
        let frame_len = usize::from(u16::from_be_bytes([conn.receive[0], conn.receive[1]]));
        if frame_len == 0 || frame_len > config.max_frame_bytes {
            return false;
        }
        if conn.receive.len() < frame_len + 2 {
            return true;
        }
        if conn.transmit.len() != conn.transmit_offset {
            return true;
        }
        let query = conn.receive[2..2 + frame_len].to_vec();
        conn.receive.drain(..2 + frame_len);
        match dns.respond_tcp(source, &query) {
            Ok(Some(response)) => {
                if response.len() > u16::MAX as usize
                    || response.len() + 2 > config.tx_bytes_per_connection
                {
                    return false;
                }
                conn.transmit.clear();
                conn.transmit
                    .extend_from_slice(&(response.len() as u16).to_be_bytes());
                conn.transmit.extend_from_slice(&response);
                conn.transmit_offset = 0;
            }
            Ok(None) => return false,
            Err(_) => return false,
        }
        *completed += 1;
        if *completed >= config.max_frames_per_poll || conn.receive.len() < 2 {
            return true;
        }
    }
}

fn remote_ip(endpoint: Option<smoltcp::wire::IpEndpoint>) -> IpAddr {
    match endpoint.map(|e| e.addr) {
        Some(IpAddress::Ipv4(a)) => IpAddr::V4(std::net::Ipv4Addr::from(a.0)),
        Some(IpAddress::Ipv6(a)) => IpAddr::V6(std::net::Ipv6Addr::from(a.0)),
        _ => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    }
}

fn reset_connection(conn: &mut Connection, now: smoltcp::time::Instant) {
    conn.receive.clear();
    conn.transmit.clear();
    conn.transmit_offset = 0;
    conn.last_activity = now;
    conn.active = false;
    conn.peer_closed = false;
}

fn duration_to_smoltcp(d: Duration) -> smoltcp::time::Duration {
    smoltcp::time::Duration::from_millis(d.as_millis().min(u64::MAX as u128) as u64)
}
