//! Linux packet profile for dedicated, confirmed Core routes. Relays use
//! `VerifiedGraph::relay` and cannot instantiate this endpoint exchange.

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use boreas_tun::linux::{LinuxTunError, LinuxTunQueue};

use crate::{
    ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, TunnelError,
    e2e::E2eCircuit,
    mesh_probe::{Error, MeshProbe},
    mesh_relay::EndpointIo,
    mesh_route::{RouteLocator, VerifiedGraph},
    packet_path::{MAX_MTU, PointToPoint},
    resource::Admission,
};

const PROFILE: &[u8] = b"BOREAS CORE TUN 1\0";
const CLOSE_BUDGET: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const PACKET_BUFFER_BYTES: usize = 2 * (MAX_MTU + 1);

#[derive(Clone, Copy, Debug)]
pub struct PacketEpoch {
    pub circuit_id: [u8; 16],
    pub tx: u64,
    pub rx: u64,
}

impl VerifiedGraph<'_> {
    /// A short bidirectional IP epoch. On confirmed loss the selector opens a
    /// new route and the callback reads only subsequently dequeued IP packets.
    /// The failed epoch's plaintext, frames and TLS state are never replayed.
    pub fn connect_tun(
        &self,
        probe: &mut MeshProbe<'_>,
        locators: &[RouteLocator<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
        endpoint: (&LinuxTunQueue, Option<u8>),
        mut confirmed: impl FnMut(&[u8], [u8; 16]),
    ) -> Result<PacketEpoch, Error> {
        let _buffer = admission
            .reserve_bytes(PACKET_BUFFER_BYTES)
            .map_err(TunnelError::from)?;
        let (tun, preferred) = endpoint;
        self.connect_io(
            probe,
            locators,
            outer,
            (admission, preferred),
            |path, c, io| epoch(c, io, tun, true, |id| confirmed(path, id)),
        )
    }

    /// Respond to one incoming epoch on one exact, locally authorized path.
    pub fn respond_tun(
        &self,
        probe: &mut MeshProbe<'_>,
        path: &[u8],
        incoming: TcpStream,
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
        tun: &LinuxTunQueue,
        confirmed: impl FnOnce([u8; 16]),
    ) -> Result<PacketEpoch, Error> {
        let _buffer = admission
            .reserve_bytes(PACKET_BUFFER_BYTES)
            .map_err(TunnelError::from)?;
        self.respond_io(probe, path, incoming, outer, admission, |c, io| {
            epoch(c, io, tun, false, confirmed)
        })
    }
}

fn epoch(
    c: &mut E2eCircuit<'_>,
    io: EndpointIo<'_>,
    tun: &LinuxTunQueue,
    initiator: bool,
    confirmed: impl FnOnce([u8; 16]),
) -> Result<PacketEpoch, TunnelError> {
    let bad = TunnelError::Unsupported("invalid Core TUN profile or packet");
    let policy = PointToPoint::from_mesh_circuit(c, tun.mtu()).map_err(|_| bad)?;
    let mut expected = [0; PROFILE.len() + 2];
    expected[..PROFILE.len()].copy_from_slice(PROFILE);
    expected[PROFILE.len()..].copy_from_slice(&(tun.mtu() as u16).to_be_bytes());
    let mut received = [0; PROFILE.len() + 2];
    // This is still admission, not established business I/O: an EOF may
    // mean the other side rejected the profile and cannot authorize failover.
    let profile_error = |_| TunnelError::Unsupported("Core TUN profile or MTU mismatch");
    if initiator {
        c.write_all(&expected).map_err(profile_error)?;
    }
    c.read_exact(&mut received).map_err(profile_error)?;
    if received != expected {
        return Err(TunnelError::Unsupported("Core TUN profile or MTU mismatch"));
    }
    if !initiator {
        c.write_all(&expected).map_err(profile_error)?;
    }
    (io.check)()?;
    let mut stats = PacketEpoch {
        circuit_id: c.circuit_id(),
        tx: 0,
        rx: 0,
    };
    confirmed(stats.circuit_id);

    let rotate = io
        .deadline
        .checked_sub(CLOSE_BUDGET)
        .ok_or(TunnelError::Timeout)?;
    let mut incoming = [0; MAX_MTU];
    let mut outgoing = [0; MAX_MTU + 1];
    let mut closing = false;
    while Instant::now() < io.deadline {
        (io.check)()?;
        if initiator && !closing && Instant::now() >= rotate {
            c.write_all(&[0; 2])?;
            closing = true;
        }
        let next = if initiator && !closing {
            rotate
        } else {
            io.deadline
        };
        let (wire_ready, tun_ready) = ready(c, io.socket, (!closing).then_some(tun), next)?;
        if wire_ready {
            let mut prefix = [0; 2];
            c.read_exact(&mut prefix)?;
            let n = usize::from(u16::from_be_bytes(prefix));
            if n == 0 {
                (io.check)()?;
                if !initiator {
                    c.write_all(&[0; 2])?;
                } else if !closing {
                    return Err(TunnelError::Unsupported("unsolicited mesh epoch end"));
                }
                // Outer owner still does close_notify + CircuitClose.
                return Ok(stats);
            }
            if n > tun.mtu() {
                return Err(TunnelError::Unsupported("mesh packet above MTU"));
            }
            let packet = &mut incoming[..n];
            c.read_exact(packet)?;
            policy
                .authorize_inbound(packet)
                .map_err(|_| TunnelError::Unsupported("mesh inbound VIP or IP rejected"))?;
            (io.check)()?;
            match tun.write_packet(packet) {
                Ok(()) => stats.rx = stats.rx.saturating_add(1),
                Err(LinuxTunError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(_) => return Err(TunnelError::Unsupported("mesh TUN write failed")),
            }
        }
        if tun_ready && (!initiator || Instant::now() < rotate) {
            let packet = match tun.try_read_packet_into(&mut outgoing) {
                Ok(Some(packet)) => packet,
                Ok(None) | Err(LinuxTunError::Packet(_)) => continue,
                Err(_) => return Err(TunnelError::Unsupported("mesh TUN read failed")),
            };
            if policy.authorize_outbound(packet).is_ok() {
                (io.check)()?;
                c.write_all(&(packet.len() as u16).to_be_bytes())?;
                c.write_all(packet)?;
                stats.tx = stats.tx.saturating_add(1);
            }
        }
    }
    Err(TunnelError::Timeout)
}

fn ready(
    c: &E2eCircuit<'_>,
    socket: &TcpStream,
    tun: Option<&LinuxTunQueue>,
    until: Instant,
) -> Result<(bool, bool), TunnelError> {
    let buffered = c.has_buffered_input();
    let mut fds = [
        libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tun.map_or(-1, LinuxTunQueue::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let ms = if buffered {
        0
    } else {
        until
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL)
            .as_millis() as i32
    };
    // SAFETY: initialized array; fd ownership remains with the borrowed socket/TUN.
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok((false, false));
        }
        return Err(TunnelError::Unsupported("mesh endpoint poll failed"));
    }
    if fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(TunnelError::Unsupported("mesh TUN unavailable"));
    }
    Ok((
        buffered || fds[0].revents != 0,
        fds[1].revents & libc::POLLIN != 0,
    ))
}
