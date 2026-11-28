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
    OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, TunnelError,
    e2e::E2eCircuit,
    mesh_probe::{Error, MeshProbe},
    mesh_relay::EndpointIo,
    mesh_route::{RouteLocator, RoutedPair, VerifiedGraph},
    packet_path::{MAX_MTU, PointToPoint},
    resource::Admission,
};

const PROFILE: &[u8] = b"BOREAS CORE TUN 1\0";
const CLOSE_BUDGET: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const PACKET_BUFFER_BYTES: usize = 2 * (MAX_MTU + 1);
// This synchronous path fails closed rather than retrying an interrupted
// transport indefinitely or losing track of a partially accepted message.
const MAX_WRITE_INTERRUPTS: u8 = 16;

pub(crate) fn write_chunks_and_flush<W: Write + ?Sized>(
    writer: &mut W,
    chunks: &[&[u8]],
) -> io::Result<()> {
    for chunk in chunks {
        let mut offset = 0;
        let mut interrupts = 0;
        while offset < chunk.len() {
            match writer.write(&chunk[offset..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    offset += n;
                    interrupts = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupts += 1;
                    if interrupts >= MAX_WRITE_INTERRUPTS {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
    let mut interrupts = 0;
    loop {
        match writer.flush() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupts += 1;
                if interrupts >= MAX_WRITE_INTERRUPTS {
                    return Err(error);
                }
            }
            result => return result,
        }
    }
}

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
        endpoint: (&Admission, &LinuxTunQueue),
        confirmed: impl FnOnce([u8; 16]),
    ) -> Result<PacketEpoch, Error> {
        let (admission, tun) = endpoint;
        let _buffer = admission
            .reserve_bytes(PACKET_BUFFER_BYTES)
            .map_err(TunnelError::from)?;
        self.respond_io(probe, path, incoming, outer, admission, |c, io| {
            epoch(c, io, tun, false, confirmed)
        })
    }

    /// Same packet profile and no-replay semantics as `connect_tun`, with
    /// candidates derived from the verified graph and adjacent locators.
    pub fn connect_routed_tun(
        &self,
        probe: &mut MeshProbe<'_>,
        pair: &RoutedPair<'_>,
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
        endpoint: (&LinuxTunQueue, Option<u8>),
        mut confirmed: impl FnMut(&[u8], [u8; 16]),
    ) -> Result<PacketEpoch, Error> {
        let _buffer = admission
            .reserve_bytes(PACKET_BUFFER_BYTES)
            .map_err(TunnelError::from)?;
        let (tun, preferred) = endpoint;
        self.connect_routed_io(probe, pair, outer, (admission, preferred), |path, c, io| {
            epoch(c, io, tun, true, |id| confirmed(path, id))
        })
    }

    pub fn respond_routed_tun(
        &self,
        probe: &mut MeshProbe<'_>,
        pair: &RoutedPair<'_>,
        incoming: TcpStream,
        outer: &OpenSslOuterTlsAcceptor,
        endpoint: (&Admission, &LinuxTunQueue),
        confirmed: impl FnOnce(&[u8], [u8; 16]),
    ) -> Result<PacketEpoch, Error> {
        let (admission, tun) = endpoint;
        let _buffer = admission
            .reserve_bytes(PACKET_BUFFER_BYTES)
            .map_err(TunnelError::from)?;
        self.respond_routed_io(probe, pair, incoming, outer, admission, |path, c, io| {
            epoch(c, io, tun, false, |id| confirmed(path, id))
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
    tun.set_nonblocking(true)
        .map_err(|_| TunnelError::Unsupported("cannot enable nonblocking mesh TUN"))?;
    let policy = PointToPoint::from_mesh_circuit(c, tun.mtu()).map_err(|_| bad)?;
    let mut expected = [0; PROFILE.len() + 2];
    expected[..PROFILE.len()].copy_from_slice(PROFILE);
    expected[PROFILE.len()..].copy_from_slice(&(tun.mtu() as u16).to_be_bytes());
    let mut received = [0; PROFILE.len() + 2];
    // This is still admission, not established business I/O: an EOF may
    // mean the other side rejected the profile and cannot authorize failover.
    let profile_error = |_| TunnelError::Unsupported("Core TUN profile or MTU mismatch");
    if initiator {
        write_chunks_and_flush(c, &[&expected]).map_err(profile_error)?;
    }
    c.read_exact(&mut received).map_err(profile_error)?;
    if received != expected {
        return Err(TunnelError::Unsupported("Core TUN profile or MTU mismatch"));
    }
    if !initiator {
        write_chunks_and_flush(c, &[&expected]).map_err(profile_error)?;
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
            write_chunks_and_flush(c, &[&[0; 2]])?;
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
                    write_chunks_and_flush(c, &[&[0; 2]])?;
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
                let prefix = (packet.len() as u16).to_be_bytes();
                write_chunks_and_flush(c, &[&prefix, packet])?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct BufferedShortWriter {
        pending: Vec<u8>,
        wire: Vec<u8>,
        blocked_flush: bool,
        writes: usize,
        flushes: usize,
    }

    impl Write for BufferedShortWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let count = input.len().min(2);
            self.pending.extend_from_slice(&input[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.blocked_flush {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.wire.append(&mut self.pending);
            Ok(())
        }
    }

    #[test]
    fn short_writes_are_flushed_in_order_before_success() {
        let mut output = BufferedShortWriter::default();
        write_chunks_and_flush(&mut output, &[b"prefix", b"payload"]).unwrap();
        assert_eq!(output.wire.as_slice(), b"prefixpayload");
        assert!(output.pending.is_empty());
        assert_eq!(output.flushes, 1);
        assert!(output.writes > 2);
    }

    #[test]
    fn blocked_flush_does_not_report_message_delivery_or_spin() {
        let mut output = BufferedShortWriter {
            blocked_flush: true,
            ..Default::default()
        };
        let error = write_chunks_and_flush(&mut output, &[b"first", b"last"]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(output.flushes, 1);
        assert!(output.wire.is_empty());
        assert_eq!(output.pending.as_slice(), b"firstlast");
        // Retrying flush alone never duplicates the accepted plaintext.
        output.blocked_flush = false;
        output.flush().unwrap();
        assert_eq!(output.wire.as_slice(), b"firstlast");
    }

    struct InterruptWriter {
        fail_write: bool,
        writes: usize,
        flushes: usize,
    }

    impl Write for InterruptWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail_write {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(input.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Err(io::ErrorKind::Interrupted.into())
        }
    }

    #[test]
    fn repeated_interrupts_are_bounded_for_writes_and_flushes() {
        let mut writer = InterruptWriter {
            fail_write: true,
            writes: 0,
            flushes: 0,
        };
        assert_eq!(
            write_chunks_and_flush(&mut writer, &[b"x"]).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(writer.writes, usize::from(MAX_WRITE_INTERRUPTS));
        assert_eq!(writer.flushes, 0);

        let mut writer = InterruptWriter {
            fail_write: false,
            writes: 0,
            flushes: 0,
        };
        assert_eq!(
            write_chunks_and_flush(&mut writer, &[b"x"]).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, usize::from(MAX_WRITE_INTERRUPTS));
    }
}
