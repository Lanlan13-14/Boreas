//! One-shot fixed Core-to-Core E2E circuit; no route discovery or daemon/TUN.
//!
//! The operator authorizes an exact, ordered route using signed Core identities
//! at every participant. This deliberately does not authorize Edge attachment,
//! source IP prefixes, subnet routes or multipath. No wire opener is inferred:
//! at ingress the first adjacent peer must be the configured source; at later
//! relays the route is local configuration, not a previous Core's assertion.

use std::{net::TcpStream, os::fd::AsRawFd, sync::Arc, time::Instant};

use boreas_crypto::{
    Policy,
    backend::{OpenSslAcceptor, OpenSslConnector},
};
use boreas_proto::{
    ControlType, Frame, Kind,
    messages::{CircuitAccept, CircuitClose, CircuitOpen, CircuitReset, RelayFragment},
};

use crate::{
    CircuitReject, EstablishedSession, OpenSslE2eBackend, PeerIdentity, PkiIdentityExtractor,
    TunnelError,
    e2e::{E2eCircuit, accept_e2e, open_e2e},
    mesh_probe::{Adjacency, Core, Error, MeshProbe},
    resource::Admission,
    runtime::bounded_link_operation,
};

const MAX_ROUTE: usize = 4;
const FORWARD_BUFFER_BUDGET: usize = 2 * boreas_proto::MAX_BODY_LEN as usize;

/// Private, locally authorized route facts (no keys, raw objects or sockets).
pub struct FixedRoute {
    pub(crate) members: Vec<Core>,
    pub(crate) position: usize,
    /// Per-member replay head and exclusive UTC deadline for graph routes.
    pub(crate) advertisements: Vec<([u8; 32], u64)>,
    pub(crate) attempt_until: Option<Instant>,
}

impl FixedRoute {
    pub(crate) fn deadline(
        &self,
        probe: &mut MeshProbe<'_>,
        links: &[&Adjacency],
    ) -> Result<Instant, Error> {
        let mut deadline = probe.route_deadline(&self.members, links)?;
        if let Some(until) = self.attempt_until {
            deadline = deadline.min(until);
        }
        // An adjacent hop exchanging a newer LSA advances the same replay
        // slot below; the snapshot then fails closed rather than mixing views.
        for (member, &(id, expiry)) in self.members.iter().zip(&self.advertisements) {
            deadline = deadline.min(probe.route_lsa_deadline(member, id, expiry)?);
        }
        Ok(deadline)
    }

    pub(crate) fn expiry(&self, adjacent_expiry: u64) -> u64 {
        self.advertisements
            .iter()
            .fold(adjacent_expiry, |expiry, ad| expiry.min(ad.1))
    }
}

impl MeshProbe<'_> {
    /// This is explicit local admission, not authority derived from topology
    /// or from E2E TLS. A path contains two endpoints and one or two relays.
    pub fn authorize_fixed_route(&mut self, signed: &[&[u8]]) -> Result<FixedRoute, Error> {
        if !(3..=MAX_ROUTE).contains(&signed.len()) {
            return Err(Error::NoRoute);
        }
        let mut members = Vec::<Core>::with_capacity(signed.len());
        for raw in signed {
            let member = self.verified_core(raw)?;
            if members.iter().any(|previous| previous.id == member.id) {
                return Err(Error::NoRoute);
            }
            members.push(member);
        }
        let pos = members
            .iter()
            .position(|m| identity(m) == self.local())
            .ok_or(Error::Identity)?;
        // A deterministic opener also fixes the TLS client, allowing the
        // batch to start without any reverse business-trigger semantics.
        if source(&members).node_id >= destination(&members).node_id {
            return Err(Error::NoRoute);
        }
        self.route_deadline(&members, &[])?;
        Ok(FixedRoute {
            members,
            position: pos,
            advertisements: Vec::new(),
            attempt_until: None,
        })
    }
}

fn identity(core: &Core) -> PeerIdentity {
    core.identity.peer_identity()
}
fn source(members: &[Core]) -> PeerIdentity {
    identity(&members[0])
}
fn destination(members: &[Core]) -> PeerIdentity {
    identity(&members[members.len() - 1])
}

impl FixedRoute {
    fn check_owner(&self, probe: &MeshProbe<'_>) -> Result<(), Error> {
        if !probe.is_exact_local(&self.members[self.position]) {
            return Err(Error::Identity);
        }
        Ok(())
    }
    fn hops(&self) -> u8 {
        (self.members.len() - 1) as u8
    }
}

/// Consume both dedicated links for one circuit. Only complete, validated
/// records are handled; once a blocking read starts, any timeout is fatal for
/// both links, never interpreted as idle. No endpoint TLS backend or callback
/// is present on this forwarding path. No retransmission or queueing of cipher
/// fragments: each write must finish before another frame is read.
pub fn forward_fixed(
    probe: &mut MeshProbe<'_>,
    route: &FixedRoute,
    mut left: Adjacency,
    mut right: Adjacency,
    admission: &Admission,
) -> Result<Forwarded, Error> {
    route.check_owner(probe)?;
    let pos = route.position;
    if pos == 0 || pos + 1 >= route.members.len() {
        return Err(Error::NoRoute);
    }
    if left.peer.identity != route.members[pos - 1].identity
        || right.peer.identity != route.members[pos + 1].identity
    {
        return Err(Error::Identity);
    }
    let _credit = admission
        .reserve_bytes(FORWARD_BUFFER_BUDGET)
        .map_err(TunnelError::from)?;
    let deadline = route.deadline(probe, &[&left, &right])?;
    let (left_socket, right_socket) = (&left.socket, &right.socket);
    let remote_expiry = route.expiry(left.remote_lsa_expiry.min(right.remote_lsa_expiry));
    let check = || {
        probe
            .check_route_utc(&route.members, remote_expiry)
            .map_err(|_| TunnelError::Unsupported("fixed-route authority expired"))
    };
    probe.with_live_identity(
        &route.members,
        remote_expiry,
        &[left_socket, right_socket],
        || {
            bounded_link_operation(left_socket, deadline, || {
                bounded_link_operation(right_socket, deadline, || {
                    let frame = control(&mut left.session, ControlType::CircuitOpen)?;
                    let open = CircuitOpen::decode(&frame.body)?;
                    let dst = destination(&route.members);
                    if open.destination_node_id != dst.node_id
                        || open.destination_identity_generation != dst.identity_generation
                    {
                        return Err(CircuitReject::WrongDestination.into());
                    }
                    if open.path_hops != route.hops() {
                        return Err(CircuitReject::HopsMismatch.into());
                    }
                    check()?;
                    right
                        .session
                        .send_control(ControlType::CircuitOpen, &frame.body)?;
                    let frame = control(&mut right.session, ControlType::CircuitAccept)?;
                    let accept = CircuitAccept::decode(&frame.body)?;
                    if accept.circuit_id != open.circuit_id || accept.path_hops != open.path_hops {
                        return Err(CircuitReject::BadBody.into());
                    }
                    check()?;
                    left.session
                        .send_control(ControlType::CircuitAccept, &frame.body)?;
                    pump(
                        [left_socket, right_socket],
                        [&mut left.session, &mut right.session],
                        open,
                        pos,
                        deadline,
                        check,
                    )
                })
            })
            .map_err(Error::from)
        },
    )
}

/// Nonsecret observation of a completed relay lifetime, not an E2E proof.
#[derive(Clone, Copy, Debug)]
pub struct Forwarded {
    pub circuit_id: [u8; 16],
    pub ciphertext_bytes: [u64; 2],
}

fn control(session: &mut EstablishedSession, kind: ControlType) -> Result<Frame, TunnelError> {
    let frame = session.recv_frame()?;
    if frame.header.kind != Kind::Control || frame.body.first() != Some(&(kind as u8)) {
        return Err(CircuitReject::UnexpectedFrame.into());
    }
    Ok(frame)
}

fn pump(
    sockets: [&TcpStream; 2],
    sessions: [&mut EstablishedSession; 2],
    open: CircuitOpen,
    pos: usize,
    deadline: Instant,
    mut check: impl FnMut() -> Result<(), TunnelError>,
) -> Result<Forwarded, TunnelError> {
    let mut offsets = [0u64; 2];
    let mut preferred = 0;
    loop {
        let side = next_ready(sockets, &sessions, preferred, deadline)?;
        preferred = 1 - side;
        let frame = sessions[side].recv_frame()?;
        if Instant::now() >= deadline {
            return Err(TunnelError::Timeout);
        }
        check()?;
        match frame.header.kind {
            Kind::RelayCircuit => {
                let mut body = frame.body;
                let fragment = RelayFragment::decode_ref(&body)?;
                if fragment.circuit_id != open.circuit_id {
                    return Err(CircuitReject::UnknownCircuit.into());
                }
                if usize::from(fragment.direction) != side {
                    return Err(CircuitReject::DirectionMismatch.into());
                }
                let traversed = if side == 0 {
                    pos - 1
                } else {
                    usize::from(open.path_hops) - pos - 1
                };
                let remaining = open.path_hops - traversed as u8;
                if fragment.hops_remaining != remaining || remaining <= 1 {
                    return Err(CircuitReject::HopsMismatch.into());
                }
                if fragment.payload.is_empty() || fragment.byte_offset != offsets[side] {
                    return Err(CircuitReject::OffsetMismatch.into());
                }
                let next = fragment
                    .byte_offset
                    .checked_add(fragment.payload.len() as u64)
                    .ok_or(CircuitReject::OffsetMismatch)?;
                // The registered fragment layout ends its fixed header with
                // hops_remaining; never copy or interpret the ciphertext.
                body[boreas_proto::messages::RELAY_FRAGMENT_FIXED_LEN - 1] = remaining - 1;
                sessions[1 - side].send_frame(Kind::RelayCircuit, &body)?;
                offsets[side] = next;
            }
            Kind::Control => {
                let (t, id) = match frame.body.first().copied() {
                    Some(t) if t == ControlType::CircuitReset as u8 => (
                        ControlType::CircuitReset,
                        CircuitReset::decode(&frame.body)?.circuit_id,
                    ),
                    Some(t) if t == ControlType::CircuitClose as u8 => (
                        ControlType::CircuitClose,
                        CircuitClose::decode(&frame.body)?.circuit_id,
                    ),
                    _ => return Err(CircuitReject::UnexpectedFrame.into()),
                };
                if id != open.circuit_id {
                    return Err(CircuitReject::UnknownCircuit.into());
                }
                if t == ControlType::CircuitClose && side != 0 {
                    return Err(CircuitReject::UnexpectedFrame.into());
                }
                sessions[1 - side].send_control(t, &frame.body)?;
                if t == ControlType::CircuitReset {
                    return Err(CircuitReject::ResetReceived.into());
                }
                return Ok(Forwarded {
                    circuit_id: id,
                    ciphertext_bytes: offsets,
                });
            }
            Kind::HopIpBatch => return Err(CircuitReject::UnexpectedFrame.into()),
        }
    }
}

fn next_ready(
    sockets: [&TcpStream; 2],
    sessions: &[&mut EstablishedSession; 2],
    preferred: usize,
    deadline: Instant,
) -> Result<usize, TunnelError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(TunnelError::Timeout)?;
        if remaining.is_zero() {
            return Err(TunnelError::Timeout);
        }
        let buffered = [
            sessions[0].has_buffered_input(),
            sessions[1].has_buffered_input(),
        ];
        let mut watched = sockets.map(|socket| libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        let ms = if buffered.iter().any(|b| *b) {
            0
        } else {
            remaining.as_millis().max(1).min(i32::MAX as u128) as i32
        };
        // SAFETY: `watched` is initialized and valid for two pollfds, and
        // the borrowed TcpStreams own both descriptors until poll returns.
        let rc = unsafe { libc::poll(watched.as_mut_ptr(), watched.len() as libc::nfds_t, ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        for side in [preferred, 1 - preferred] {
            if buffered[side] || watched[side].revents != 0 {
                return Ok(side);
            }
        }
    }
}

/// Run a finite endpoint application exchange after verified E2E TLS and
/// confirmation. Consumes a dedicated adjacency; no API reattaches its TLS
/// state, circuit ID, offsets, or bytes to another route. On route loss the
/// owner must select and authenticate fresh links, then call again.
///
/// The closure is trusted endpoint code; the guard bounds socket operations,
/// not arbitrary work in the closure. There is no automatic application retry.
pub fn with_fixed_endpoint<T>(
    probe: &mut MeshProbe<'_>,
    route: &FixedRoute,
    hop: Adjacency,
    exchange: impl FnOnce(&mut E2eCircuit<'_>) -> Result<T, TunnelError>,
) -> Result<T, Error> {
    with_fixed_endpoint_io(probe, route, hop, |c, _| exchange(c))
}

pub(crate) struct EndpointIo<'a> {
    pub socket: &'a TcpStream,
    pub deadline: Instant,
    pub check: &'a mut dyn FnMut() -> Result<(), TunnelError>,
}

pub(crate) fn with_fixed_endpoint_io<T>(
    probe: &mut MeshProbe<'_>,
    route: &FixedRoute,
    mut hop: Adjacency,
    exchange: impl FnOnce(&mut E2eCircuit<'_>, EndpointIo<'_>) -> Result<T, TunnelError>,
) -> Result<T, Error> {
    route.check_owner(probe)?;
    let initiator = route.position == 0;
    let (next, peer) = if initiator {
        (1, &route.members[route.members.len() - 1])
    } else if route.position + 1 == route.members.len() {
        (route.position - 1, &route.members[0])
    } else {
        return Err(Error::NoRoute);
    };
    if hop.peer.identity != route.members[next].identity {
        return Err(Error::Identity);
    }
    let deadline = route.deadline(probe, &[&hop])?;
    // The graph profile binds exact signed identity and LSA TBS digests in
    // addition to the existing endpoint TLS SPKI checks and route facts.
    let mut binding = if route.advertisements.is_empty() {
        b"BOREAS-FIXED-CORE-ROUTE-v1\0".to_vec()
    } else {
        b"BOREAS-VERIFIED-CORE-ROUTE-v1\0".to_vec()
    };
    binding.extend_from_slice(&probe.policy_digest());
    binding.push(route.hops());
    for member in &route.members {
        let id = identity(member);
        binding.extend_from_slice(&id.node_id.to_be_bytes());
        binding.extend_from_slice(&id.identity_generation.to_be_bytes());
    }
    for (member, advertisement) in route.members.iter().zip(&route.advertisements) {
        binding.extend_from_slice(&member.object_id);
        binding.extend_from_slice(&advertisement.0);
    }
    let binding = openssl::sha::sha256(&binding);
    let pem = probe.endpoint_credential();
    let connector = OpenSslConnector::from_pem_identity(pem, Policy::production_default())
        .map_err(|_| Error::Identity)?;
    let acceptor = OpenSslAcceptor::from_pem_identity(pem, Policy::production_default())
        .map_err(|_| Error::Identity)?;
    let remote_expiry = route.expiry(hop.remote_lsa_expiry);
    let backend = OpenSslE2eBackend::new(
        Arc::new(connector),
        Arc::new(acceptor),
        Arc::new(PkiIdentityExtractor::new(vec![peer.identity.clone()])?),
    );
    probe.with_live_identity(&route.members, remote_expiry, &[&hop.socket], || {
        bounded_link_operation(&hop.socket, deadline, || {
            let mut circuit = if initiator {
                open_e2e(&mut hop.session, &backend, identity(peer), route.hops())?
            } else {
                accept_e2e(&mut hop.session, &backend, identity(peer))?
            };
            if circuit.info().path_hops != route.hops() {
                return Err(CircuitReject::HopsMismatch.into());
            }
            // Private to this fixed-path profile; does not change the ordinary
            // circuit wire layouts/version. Not an attestation of physical route.
            use std::io::{Read, Write};
            let mut remote = [0u8; 32];
            if initiator {
                circuit.write_all(&binding)?;
            }
            circuit.read_exact(&mut remote)?;
            if remote != binding {
                return Err(crate::SessionReject::PeerIdentityMismatch.into());
            }
            if !initiator {
                circuit.write_all(&binding)?;
            }
            let mut check = || {
                if Instant::now() >= deadline {
                    return Err(TunnelError::Timeout);
                }
                probe
                    .check_route_utc(&route.members, remote_expiry)
                    .map_err(|_| TunnelError::Unsupported("fixed-route authority expired"))
            };
            check()?;
            let result = exchange(&mut circuit, EndpointIo {
                socket: &hop.socket,
                deadline,
                check: &mut check,
            })?;
            check()?;
            if initiator {
                circuit.finish_dedicated()?;
            } else {
                circuit.wait_dedicated_close()?;
            }
            probe
                .check_route_utc(&route.members, remote_expiry)
                .map_err(|_| TunnelError::Unsupported("fixed-route authority expired"))?;
            Ok(result)
        })
        .map_err(Error::from)
    })
}
