//! Bounded connection and byte admission credits. No identity is trusted before
//! authentication: pre-authentication reservations are global-only, never keyed
//! by a claimed peer identifier.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerId(pub(crate) u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub handshakes_global: usize,
    pub authenticated_global: usize,
    pub authenticated_per_peer: usize,
    pub bytes_global: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    HandshakeLimit,
    ConnectionLimit,
    PeerLimit,
    ByteLimit,
    Overflow,
    Poisoned,
}

#[derive(Debug, Default)]
struct Counts {
    handshakes: usize,
    authenticated: usize,
    bytes: usize,
    peers: HashMap<PeerId, usize>,
}
struct Inner {
    limits: Limits,
    counts: Mutex<Counts>,
}

/// Shared admission ledger. All counters are changed while holding one mutex,
/// so reservation and release are atomic with respect to competing callers.
#[derive(Clone)]
pub struct Admission {
    inner: Arc<Inner>,
}
impl Admission {
    pub fn new(limits: Limits) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                counts: Mutex::new(Counts::default()),
            }),
        }
    }

    /// Reserve one global unauthenticated handshake slot. Caller-supplied names
    /// or key IDs are intentionally absent from this API.
    pub fn reserve_handshake(&self) -> Result<HandshakeCredit, AdmissionError> {
        let mut c = self
            .inner
            .counts
            .lock()
            .map_err(|_| AdmissionError::Poisoned)?;
        if c.handshakes >= self.inner.limits.handshakes_global {
            return Err(AdmissionError::HandshakeLimit);
        }
        c.handshakes += 1;
        Ok(HandshakeCredit {
            inner: Some(self.inner.clone()),
        })
    }

    /// Reserve a bounded number of bytes across all connections. The returned
    /// guard remains charged until dropped after its resource has been consumed.
    pub fn reserve_bytes(&self, bytes: usize) -> Result<ByteCredit, AdmissionError> {
        let mut c = self
            .inner
            .counts
            .lock()
            .map_err(|_| AdmissionError::Poisoned)?;
        let next = c.bytes.checked_add(bytes).ok_or(AdmissionError::Overflow)?;
        if next > self.inner.limits.bytes_global {
            return Err(AdmissionError::ByteLimit);
        }
        c.bytes = next;
        Ok(ByteCredit {
            inner: Some(self.inner.clone()),
            bytes,
        })
    }

    pub fn snapshot(&self) -> Result<Snapshot, AdmissionError> {
        let c = self
            .inner
            .counts
            .lock()
            .map_err(|_| AdmissionError::Poisoned)?;
        Ok(Snapshot {
            handshakes: c.handshakes,
            authenticated: c.authenticated,
            bytes: c.bytes,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub handshakes: usize,
    pub authenticated: usize,
    pub bytes: usize,
}

/// Authentication result must be created only by trusted in-crate TLS adapter
/// after certificate, identity, generation and authorization checks succeed.
/// There is deliberately no public constructor accepting an untrusted peer ID.
pub struct AuthenticatedPeer {
    id: PeerId,
    _private: (),
}
impl AuthenticatedPeer {
    #[cfg(test)]
    fn test_only(id: PeerId) -> Self {
        Self { id, _private: () }
    }
}

pub struct HandshakeCredit {
    inner: Option<Arc<Inner>>,
}
impl HandshakeCredit {
    /// Atomically convert this pre-auth global handshake reservation to a
    /// post-auth global/per-peer connection reservation. Claimed IDs cannot be
    /// charged before this transition.
    pub fn authenticate(
        mut self,
        peer: &AuthenticatedPeer,
    ) -> Result<ConnectionCredit, AdmissionError> {
        let inner = self.inner.as_ref().expect("credit is live").clone();
        {
            let mut c = inner.counts.lock().map_err(|_| AdmissionError::Poisoned)?;
            if c.handshakes == 0 {
                return Err(AdmissionError::Poisoned);
            }
            let peer_count = c.peers.get(&peer.id).copied().unwrap_or(0);
            if c.authenticated >= inner.limits.authenticated_global {
                return Err(AdmissionError::ConnectionLimit);
            }
            if peer_count >= inner.limits.authenticated_per_peer {
                return Err(AdmissionError::PeerLimit);
            }
            c.handshakes -= 1;
            c.authenticated += 1;
            *c.peers.entry(peer.id).or_default() += 1;
        }
        // Keep ownership transfer after successful atomic counter transition;
        // on any earlier error Drop releases the handshake reservation.
        self.inner.take();
        Ok(ConnectionCredit {
            inner: Some(inner),
            peer: peer.id,
        })
    }
}
impl Drop for HandshakeCredit {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            if let Ok(mut c) = inner.counts.lock() {
                c.handshakes = c.handshakes.saturating_sub(1);
            }
        }
    }
}

pub struct ConnectionCredit {
    inner: Option<Arc<Inner>>,
    peer: PeerId,
}
impl Drop for ConnectionCredit {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            if let Ok(mut c) = inner.counts.lock() {
                c.authenticated = c.authenticated.saturating_sub(1);
                let remove_peer = if let Some(n) = c.peers.get_mut(&self.peer) {
                    *n = n.saturating_sub(1);
                    *n == 0
                } else {
                    false
                };
                if remove_peer {
                    c.peers.remove(&self.peer);
                }
            }
        }
    }
}

pub struct ByteCredit {
    inner: Option<Arc<Inner>>,
    bytes: usize,
}
impl ByteCredit {
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}
impl Drop for ByteCredit {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            if let Ok(mut c) = inner.counts.lock() {
                c.bytes = c.bytes.saturating_sub(self.bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn admission() -> Admission {
        Admission::new(Limits {
            handshakes_global: 1,
            authenticated_global: 2,
            authenticated_per_peer: 1,
            bytes_global: 10,
        })
    }
    #[test]
    fn handshake_global_and_raii_release() {
        let a = admission();
        let credit = a.reserve_handshake().unwrap();
        assert_eq!(
            a.reserve_handshake().err(),
            Some(AdmissionError::HandshakeLimit)
        );
        drop(credit);
        assert_eq!(a.snapshot().unwrap().handshakes, 0);
    }
    #[test]
    fn authenticated_limits_use_verified_peer_and_failed_upgrade_releases_handshake() {
        let a = admission();
        let verified = AuthenticatedPeer::test_only(PeerId(9));
        let conn = a
            .reserve_handshake()
            .unwrap()
            .authenticate(&verified)
            .unwrap();
        assert_eq!(
            a.reserve_handshake().unwrap().authenticate(&verified).err(),
            Some(AdmissionError::PeerLimit)
        );
        assert_eq!(a.snapshot().unwrap().handshakes, 0);
        drop(conn);
        assert_eq!(a.snapshot().unwrap().authenticated, 0);
    }
    #[test]
    fn byte_credit_is_held_until_drop() {
        let a = admission();
        let b = a.reserve_bytes(10).unwrap();
        assert_eq!(a.reserve_bytes(1).err(), Some(AdmissionError::ByteLimit));
        drop(b);
        assert_eq!(a.reserve_bytes(10).unwrap().bytes(), 10);
    }
}
