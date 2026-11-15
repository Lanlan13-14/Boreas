//! Feature-gated seam between the tunnel crate and the reviewed OpenSSL inner TLS.
//!
//! This module does not negotiate its own groups, ciphers, or certificates. It
//! only links `boreas-crypto`'s strict pq768 connector/acceptor and records that
//! a completed handshake is still not application authorization or `G-CRYPTO`.
//! Certificate files are supplied by the caller; this crate never generates keys.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::Duration;

use boreas_crypto::backend::{BackendError, EstablishedStream, OpenSslAcceptor, OpenSslConnector};
use boreas_crypto::{Policy, PolicyError, Suite};

/// Bound for one seam exchange. Production framing stays in `boreas-proto`.
pub const MAX_SEAM_PAYLOAD: usize = 16 * 1024;
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum SeamError {
    Policy(PolicyError),
    Backend(BackendError),
    Io(std::io::ErrorKind),
    PayloadTooLarge,
    PeerClosed,
}

impl From<PolicyError> for SeamError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<BackendError> for SeamError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

/// The only policy this seam will hand to the backend.
pub fn required_policy() -> Policy {
    Policy::production_default()
}

fn require_pq768(policy: Policy) -> Result<Policy, SeamError> {
    if policy.suite != Suite::Pq768 || policy.allow_pq1024 {
        return Err(SeamError::Policy(PolicyError::Pq1024NotEnabled));
    }
    Ok(policy)
}

/// Loopback connector against an already-listening strict acceptor.
pub fn connect_inner(
    address: std::net::SocketAddr,
    certificate: &Path,
    private_key: &Path,
    trust_anchor: &Path,
) -> Result<EstablishedStream<TcpStream>, SeamError> {
    let policy = require_pq768(required_policy())?;
    let connector =
        OpenSslConnector::from_pem_files(certificate, private_key, trust_anchor, policy)?;
    let stream = TcpStream::connect_timeout(&address, HANDSHAKE_WAIT)
        .map_err(|error| SeamError::Io(error.kind()))?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_WAIT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_WAIT));
    Ok(connector.connect(stream)?)
}

/// Accept one loopback inner-TLS connection on an already-bound listener.
pub fn accept_inner(
    listener: &TcpListener,
    certificate: &Path,
    private_key: &Path,
    trust_anchor: &Path,
) -> Result<EstablishedStream<TcpStream>, SeamError> {
    let policy = require_pq768(required_policy())?;
    let acceptor = OpenSslAcceptor::from_pem_files(certificate, private_key, trust_anchor, policy)?;
    let (stream, _) = listener
        .accept()
        .map_err(|error| SeamError::Io(error.kind()))?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_WAIT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_WAIT));
    Ok(acceptor.accept(stream)?)
}

/// Write one bounded payload and read the same number of bytes back.
pub fn exchange(
    stream: &mut EstablishedStream<TcpStream>,
    payload: &[u8],
) -> Result<Vec<u8>, SeamError> {
    if payload.is_empty() || payload.len() > MAX_SEAM_PAYLOAD {
        return Err(SeamError::PayloadTooLarge);
    }
    stream
        .write_all(payload)
        .map_err(|error| SeamError::Io(error.kind()))?;
    stream
        .flush()
        .map_err(|error| SeamError::Io(error.kind()))?;
    let mut received = vec![0; payload.len()];
    stream
        .read_exact(&mut received)
        .map_err(|error| SeamError::Io(error.kind()))?;
    Ok(received)
}

/// Run the acceptor on a background thread and connect to it.
///
/// The caller owns both identities. A successful return only means the strict
/// backend completed a handshake and echoed `payload`; it does not authorize a
/// node, open a relay circuit, or pass `G-CRYPTO`.
pub fn loopback_echo(
    server_certificate: &Path,
    server_key: &Path,
    client_certificate: &Path,
    client_key: &Path,
    trust_anchor: &Path,
    payload: &[u8],
) -> Result<Vec<u8>, SeamError> {
    if payload.is_empty() || payload.len() > MAX_SEAM_PAYLOAD {
        return Err(SeamError::PayloadTooLarge);
    }
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| SeamError::Io(error.kind()))?;
    let address = listener
        .local_addr()
        .map_err(|error| SeamError::Io(error.kind()))?;
    let server_certificate = server_certificate.to_path_buf();
    let server_key = server_key.to_path_buf();
    let trust = trust_anchor.to_path_buf();
    let expected = payload.to_vec();
    let server = thread::spawn(move || -> Result<(), SeamError> {
        let mut accepted = accept_inner(&listener, &server_certificate, &server_key, &trust)?;
        let echoed = exchange(&mut accepted, &expected)?;
        if echoed != expected {
            return Err(SeamError::PeerClosed);
        }
        Ok(())
    });
    let mut client = connect_inner(address, client_certificate, client_key, trust_anchor)?;
    let echoed = exchange(&mut client, payload)?;
    match server.join() {
        Ok(Ok(())) => Ok(echoed),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(SeamError::PeerClosed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seam_refuses_anything_but_the_pq768_policy() {
        let policy = required_policy();
        assert_eq!(policy.suite, Suite::Pq768);
        assert!(!policy.allow_pq1024);
        assert!(require_pq768(policy).is_ok());
        assert!(payload_bound_rejects_empty());
    }

    fn payload_bound_rejects_empty() -> bool {
        matches!(
            exchange_without_socket(&[]),
            Err(SeamError::PayloadTooLarge)
        )
    }

    fn exchange_without_socket(payload: &[u8]) -> Result<(), SeamError> {
        if payload.is_empty() || payload.len() > MAX_SEAM_PAYLOAD {
            Err(SeamError::PayloadTooLarge)
        } else {
            Ok(())
        }
    }

    #[test]
    fn oversized_seam_payload_is_rejected_before_io() {
        let payload = vec![0u8; MAX_SEAM_PAYLOAD + 1];
        assert!(matches!(
            exchange_without_socket(&payload),
            Err(SeamError::PayloadTooLarge)
        ));
    }
}
