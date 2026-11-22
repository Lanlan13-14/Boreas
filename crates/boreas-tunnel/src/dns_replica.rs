//! Fixed profile confirmation on an already authenticated, dedicated DNS E2E
//! circuit. This is not discovery, a snapshot transfer, or a new TLS identity.

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Instant,
};

use crate::{
    TunnelError,
    e2e::E2eCircuit,
    runtime::bounded_link_operation,
};

const HEADER: [u8; 6] = *b"BDNS\x01\0";
const PIN_BYTES: usize = 96;
const RECORD_BYTES: usize = HEADER.len() + PIN_BYTES;

#[derive(Clone, Copy)]
pub enum Side {
    Edge,
    Core,
}

/// Confirm that the authenticated peer agrees to the private-only profile,
/// the exact locally approved DNS objects and the TCP setting. The pin and
/// role-specific record are sent inside E2E TLS, not as unauthenticated hints.
/// The Edge offers, the Core verifies before acknowledging. A mismatch or
/// failure leaves the circuit unusable; never retry on the same stream.
pub fn confirm(
    circuit: &mut E2eCircuit<'_>,
    socket: &TcpStream,
    deadline: Instant,
    side: Side,
    pin: &[u8; PIN_BYTES],
    tcp: bool,
) -> Result<(), TunnelError> {
    bounded_link_operation(socket, deadline, || exchange(circuit, side, pin, tcp))?;
    circuit.mark_private_dns_only();
    Ok(())
}

fn exchange(
    stream: &mut (impl Read + Write),
    side: Side,
    pin: &[u8; PIN_BYTES],
    tcp: bool,
) -> Result<(), TunnelError> {
    let mut offer = [0; RECORD_BYTES];
    offer[..HEADER.len()].copy_from_slice(&HEADER);
    offer[HEADER.len() - 1] = u8::from(tcp);
    offer[HEADER.len()..].copy_from_slice(pin);
    let mut ack = offer;
    ack[HEADER.len() - 1] |= 0x80;
    let mut received = [0; RECORD_BYTES];
    let rejected = TunnelError::Unsupported("private DNS replica profile/pin mismatch");
    match side {
        Side::Edge => {
            stream.write_all(&offer)?;
            stream.flush()?;
            stream.read_exact(&mut received)?;
            if received != ack {
                return Err(rejected);
            }
        }
        Side::Core => {
            stream.read_exact(&mut received)?;
            if received != offer {
                return Err(rejected);
            }
            stream.write_all(&ack)?;
            stream.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, os::unix::net::UnixStream, thread, time::Duration};

    const PIN: [u8; PIN_BYTES] = [0x42; PIN_BYTES];

    #[test]
    fn matching_pin_and_profile_complete_in_both_directions() {
        let (mut edge, mut core) = UnixStream::pair().unwrap();
        for socket in [&edge, &core] {
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        }
        thread::scope(|scope| {
            let server = scope.spawn(|| exchange(&mut core, Side::Core, &PIN, true));
            exchange(&mut edge, Side::Edge, &PIN, true).unwrap();
            server.join().unwrap().unwrap();
        });
    }

    struct Script {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn core_never_acknowledges_wrong_role_tcp_pin_or_short_offer() {
        let mut offer = HEADER.to_vec();
        offer.extend(PIN);
        for offset in [HEADER.len() - 1, HEADER.len(), RECORD_BYTES - 1] {
            let mut wrong = offer.clone();
            wrong[offset] ^= 1;
            let mut wire = Script { input: Cursor::new(wrong), output: Vec::new() };
            assert!(exchange(&mut wire, Side::Core, &PIN, false).is_err());
            assert!(wire.output.is_empty());
        }
        let mut wire = Script { input: Cursor::new(offer.clone()), output: Vec::new() };
        assert!(exchange(&mut wire, Side::Edge, &PIN, false).is_err(), "no reflected offers");
        offer.pop();
        let mut wire = Script { input: Cursor::new(offer), output: Vec::new() };
        assert!(exchange(&mut wire, Side::Core, &PIN, false).is_err());
        assert!(wire.output.is_empty());
    }
}
