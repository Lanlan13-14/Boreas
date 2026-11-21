//! Bounded direct Core adjacency selection and LSA exchange on strict pq768
//! hop sessions. No graph route, application frames, or E2E secrets enter here.

use std::{
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use boreas_crypto::{
    NodeRole, Policy,
    backend::{OpenSslAcceptor, OpenSslConnector, PemIdentity},
};
use boreas_pki::{
    VerifiedNetworkContext,
    management::{ManagementTrust, VerifiedObject},
    provisioning::RootsBundle,
    status_store::{AuthenticatedPeer, FreshStatus, PeerRevocation, StatusStore},
};
use boreas_proto::{
    ControlType, Kind,
    messages::{PathRole, Probe, ProbeKind},
    objects::{CoreLsa, ObjectBody},
};

use crate::{
    ClientTarget, EstablishedSession, LinkClient, LinkServer, OpenSslInnerAcceptor,
    OpenSslInnerConnector, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, PeerIdentity,
    PeerIdentityExtractor, PkiIdentityExtractor, SessionPolicy, TunnelError, VerifiedNodeIdentity,
    resource::Admission, runtime::bounded_link_operation,
};

pub const ATTEMPT_LIMIT: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: usize = 3;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Trust,
    Identity,
    Lsa,
    Status,
    Clock,
    NoRoute,
    WrongReply,
    /// TCP dial failed before emitting any TLS bytes (graph profile only).
    PathUnavailable(TunnelError),
    /// At least one confirmed business circuit lost transport, with no replay.
    ConfirmedPathLost(TunnelError),
    Transport(TunnelError),
}

impl From<TunnelError> for Error {
    fn from(value: TunnelError) -> Self {
        Self::Transport(value)
    }
}

/// Root authorizations must match the same independent pin that verified the
/// local signed network policy. Configured socket addresses are locators only.
pub fn management_trust(
    roots: &RootsBundle,
    policy: &VerifiedNetworkContext,
    now: u64,
) -> Result<ManagementTrust, Error> {
    let net = policy.net_id();
    let (fingerprint, grants) = roots.verify_all(net, now).map_err(|_| Error::Trust)?;
    if fingerprint != policy.root_key_fingerprint() {
        return Err(Error::Trust);
    }
    let mut trust = ManagementTrust::new(net);
    for grant in grants {
        trust
            .add_verified_issuer(&grant)
            .map_err(|_| Error::Trust)?;
    }
    Ok(trust)
}

pub fn utc_now() -> Result<u64, Error> {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?;
    u64::try_from(n.as_micros()).map_err(|_| Error::Clock)
}

#[derive(Clone)]
pub(crate) struct Core {
    pub(crate) id: u8,
    pub(crate) identity: VerifiedNodeIdentity,
    pub(crate) until: u64,
    pub(crate) object_id: [u8; 32],
}

impl Core {
    fn from_object(
        object: &VerifiedObject,
        policy: &VerifiedNetworkContext,
    ) -> Result<Self, Error> {
        let ObjectBody::NodeIdentity(node) = &object.object().body else {
            return Err(Error::Identity);
        };
        let identity = VerifiedNodeIdentity::from_verified_object(object, policy)?;
        if identity.role() != NodeRole::Core {
            return Err(Error::Identity);
        }
        Ok(Self {
            id: node.home_core_id,
            until: identity.expires().min(object.valid_until()),
            identity,
            object_id: object.object_id(),
        })
    }

    fn check(&self, fresh: &FreshStatus<'_>, now: u64) -> Result<(), Error> {
        if now < self.identity.not_before() || now >= self.until {
            return Err(Error::Identity);
        }
        let peer = AuthenticatedPeer::new(
            self.identity.net_id(),
            self.identity.node_id(),
            self.identity.identity_generation(),
        )
        .ok_or(Error::Identity)?;
        match fresh.peer_revocation(&peer) {
            PeerRevocation::Verified(state) if !state.sessions_revoked() => Ok(()),
            _ => Err(Error::Status),
        }
    }

    fn peer(&self) -> PeerIdentity {
        self.identity.peer_identity()
    }
}

/// Locators are untrusted until the exact corresponding root-authorized
/// NodeIdentity is verified and the hop TLS certificate matches its SPKI.
pub struct Candidate<'a> {
    pub target: &'a ClientTarget,
    pub signed_identity: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selected {
    pub core_id: u8,
    pub attempts: usize,
    /// Original authenticated LSA envelope, not reconstructed TBS or signatures.
    pub signed_lsa: Vec<u8>,
}

/// A dedicated live adjacency; not clonable and not constructible from an LSA.
/// Accepted-link admission credits stay attached until the transport is dropped.
pub struct Adjacency {
    pub(crate) session: EstablishedSession,
    pub(crate) socket: TcpStream,
    pub(crate) expires: Instant,
    pub(crate) peer: Core,
    pub(crate) remote_lsa_expiry: u64,
    remote_lsa_id: [u8; 32],
    selected: Selected,
    _credits: (
        crate::resource::ConnectionCredit,
        crate::resource::ByteCredit,
    ),
}

impl Adjacency {
    pub fn report(&self) -> &Selected {
        &self.selected
    }
}

impl Drop for Adjacency {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

/// One operation owner. Keeps management replay state for its lifetime and
/// borrows the durable status store; no unverified constructor or key loading
/// from routing inputs. The PEM contains only the local hop credential.
pub struct MeshProbe<'a> {
    policy: VerifiedNetworkContext,
    trust: ManagementTrust,
    local: Core,
    local_lsa: VerifiedObject,
    status: &'a mut StatusStore,
    pem: &'a PemIdentity,
}

impl<'a> MeshProbe<'a> {
    pub fn new(
        policy: VerifiedNetworkContext,
        roots: &RootsBundle,
        status: &'a mut StatusStore,
        pem: &'a PemIdentity,
        local_identity: &[u8],
        local_lsa: &[u8],
    ) -> Result<Self, Error> {
        if status.net_id() != policy.net_id() {
            return Err(Error::Status);
        }
        let now = utc_now()?.max(status.last_trusted_utc());
        let mut trust = management_trust(roots, &policy, now)?;
        if !status.has_same_authorities(&trust) {
            return Err(Error::Status);
        }
        let local = Core::from_object(
            &trust
                .verify_and_authorize(local_identity, now)
                .map_err(|_| Error::Identity)?,
            &policy,
        )?;
        OpenSslConnector::from_pem_identity(pem, Policy::production_default())
            .map_err(|_| Error::Identity)?;
        let leaf = openssl::x509::X509::from_pem(&pem.certificate_pem)
            .and_then(|cert| cert.to_der())
            .map_err(|_| Error::Identity)?;
        if extractor(&local)?.extract(&leaf) != Some(local.peer()) {
            return Err(Error::Identity);
        }
        let local_lsa = trust
            .verify_and_authorize(local_lsa, now)
            .map_err(|_| Error::Lsa)?;
        lsa(&local_lsa, local.id, now)?;
        Ok(Self {
            policy,
            trust,
            local,
            local_lsa,
            status,
            pem,
        })
    }

    pub fn local(&self) -> PeerIdentity {
        self.local.peer()
    }

    /// Import operator-published updates between bounded circuits. The owner,
    /// replay heads and durable snapshot deadline are not recreated on reload.
    pub fn refresh_runtime_authority(
        &mut self,
        snapshot: &[u8],
        identity_revocation: Option<&[u8]>,
        local_lsa: &[u8],
    ) -> Result<(), Error> {
        let observed = utc_now()?;
        let mono = Instant::now();
        self.status
            .accept_signed_snapshot(snapshot, observed, mono)
            .map_err(|_| Error::Status)?;
        if let Some(raw) = identity_revocation {
            self.status
                .accept_identity_revocation(raw, utc_now()?)
                .map_err(|_| Error::Status)?;
        }
        let now = effective_utc(self.status)?;
        let verified = self
            .trust
            .verify_and_authorize(local_lsa, now)
            .map_err(|_| Error::Lsa)?;
        lsa(&verified, self.local.id, now)?;
        self.local_lsa = verified;
        self.check(&self.local.clone())?;
        Ok(())
    }

    /// Select a *direct* CDN-class neighbor. Only TCP failures before any TLS
    /// bytes enable fallback. Wrong identity, protocol, authorization, or LSA
    /// terminates the transaction instead of being misclassified as path loss.
    pub fn select(
        &mut self,
        candidates: &[Candidate<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
    ) -> Result<Selected, Error> {
        let admission = Admission::new(crate::resource::Limits {
            handshakes_global: 1,
            authenticated_global: 1,
            authenticated_per_peer: 1,
            bytes_global: crate::runtime::CONNECTION_BUFFER_BUDGET,
        });
        Ok(self.dial(candidates, outer, &admission)?.report().clone())
    }

    /// Keep an authenticated link and its credits. Use the same shared
    /// admission ledger for all links and forwarding work in a node.
    pub fn dial(
        &mut self,
        candidates: &[Candidate<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
    ) -> Result<Adjacency, Error> {
        self.dial_classified(candidates, outer, admission, None)
            .map_err(|error| match error {
                Error::PathUnavailable(cause) => Error::Transport(cause),
                other => other,
            })
    }

    pub(crate) fn dial_classified(
        &mut self,
        candidates: &[Candidate<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
        route_deadline: Option<Instant>,
    ) -> Result<Adjacency, Error> {
        if candidates.is_empty() || candidates.len() > MAX_ATTEMPTS {
            return Err(Error::NoRoute);
        }
        let now = effective_utc(self.status)?;
        let mut ordered = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let peer = Core::from_object(
                &self
                    .trust
                    .verify_and_authorize(candidate.signed_identity, now)
                    .map_err(|_| Error::Identity)?,
                &self.policy,
            )?;
            if peer.id == self.local.id
                || ordered
                    .iter()
                    .any(|entry: &(u16, u32, u8, Core, &ClientTarget)| entry.2 == peer.id)
            {
                return Err(Error::Identity);
            }
            let score = neighbor(lsa(&self.local_lsa, self.local.id, now)?, peer.id)?;
            ordered.push((score.0, score.1, peer.id, peer, candidate.target));
        }
        ordered.sort_unstable_by_key(|entry| (entry.0, entry.1, entry.2));
        let mut last_dial = Error::NoRoute;
        for (index, (_, _, id, peer, target)) in ordered.into_iter().enumerate() {
            let mut deadline = self.deadline(&peer)?;
            if let Some(route_deadline) = route_deadline {
                deadline = deadline.min(route_deadline);
            }
            if Instant::now() >= deadline {
                return Err(Error::Status);
            }
            let handshake = admission.reserve_handshake().map_err(TunnelError::from)?;
            let buffer = admission
                .reserve_bytes(crate::runtime::CONNECTION_BUFFER_BUDGET)
                .map_err(TunnelError::from)?;
            let connector =
                OpenSslConnector::from_pem_identity(self.pem, Policy::production_default())
                    .map_err(|_| Error::Identity)?;
            let client = LinkClient::new(
                Box::new(outer()?),
                Box::new(OpenSslInnerConnector::new(connector, extractor(&peer)?)),
            );
            let tcp = match client
                .connect_tcp(target, deadline.saturating_duration_since(Instant::now()))
            {
                Ok(tcp) => tcp,
                Err(error) if path_loss(error.kind()) => {
                    last_dial = Error::PathUnavailable(error.into());
                    continue;
                }
                Err(error) => return Err(Error::Transport(error.into())),
            };
            let socket = tcp.try_clone().map_err(TunnelError::from)?;
            let mut session = client.connect_preconnected_until(
                tcp,
                target,
                SessionPolicy::default_pq768(self.local(), peer.peer()),
                deadline,
            )?;
            let peer_credit =
                crate::resource::AuthenticatedPeer::from_verified_identity(session.peer());
            let credit = handshake
                .authenticate(&peer_credit)
                .map_err(TunnelError::from)?;
            let deadline = deadline.min(self.deadline(&peer)?);
            let received = bounded_link_operation(&socket, deadline, || {
                let sent = Probe {
                    kind: ProbeKind::Ping,
                    challenge: crate::csprng::random_array()?,
                    sent_monotonic_us: 0,
                    echo_monotonic_us: 0,
                };
                session.send_control(ControlType::Probe, &sent.encode()?)?;
                let reply = Probe::decode(&recv_control(&mut session, ControlType::Probe)?)?;
                if reply.kind != ProbeKind::Pong
                    || reply.challenge != sent.challenge
                    || reply.echo_monotonic_us != sent.sent_monotonic_us
                {
                    return Err(TunnelError::Unsupported("invalid Core probe reply"));
                }
                send_lsa(&mut session, &self.local_lsa)?;
                recv_control(&mut session, ControlType::Lsa)
            })?;
            let now = self.check(&peer)?;
            let raw = &received[1..];
            let remote = self
                .trust
                .verify_and_authorize(raw, now)
                .map_err(|_| Error::Lsa)?;
            neighbor(lsa(&remote, id, now)?, self.local.id)?;
            let remote_lsa_expiry = remote.valid_until();
            let expires = self.authority_deadline(&peer, remote_lsa_expiry)?;
            return Ok(Adjacency {
                session,
                socket,
                expires,
                peer,
                remote_lsa_expiry,
                remote_lsa_id: remote.object_id(),
                selected: Selected {
                    core_id: id,
                    attempts: index + 1,
                    signed_lsa: raw.to_vec(),
                },
                _credits: (credit, buffer),
            });
        }
        Err(last_dial)
    }

    /// Serve a single live exchange from one expected root-authorized neighbor.
    /// The caller owns the listener and supplies a shared acceptance budget.
    pub fn respond(
        &mut self,
        tcp: TcpStream,
        signed_peer_identity: &[u8],
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
    ) -> Result<Selected, Error> {
        Ok(self
            .accept(tcp, signed_peer_identity, outer, admission)?
            .report()
            .clone())
    }

    pub fn accept(
        &mut self,
        tcp: TcpStream,
        signed_peer_identity: &[u8],
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
    ) -> Result<Adjacency, Error> {
        self.accept_until(tcp, signed_peer_identity, outer, admission, None)
    }

    pub(crate) fn accept_until(
        &mut self,
        tcp: TcpStream,
        signed_peer_identity: &[u8],
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
        route_deadline: Option<Instant>,
    ) -> Result<Adjacency, Error> {
        let now = effective_utc(self.status)?;
        let peer = Core::from_object(
            &self
                .trust
                .verify_and_authorize(signed_peer_identity, now)
                .map_err(|_| Error::Identity)?,
            &self.policy,
        )?;
        if peer.id == self.local.id {
            return Err(Error::Identity);
        }
        neighbor(lsa(&self.local_lsa, self.local.id, now)?, peer.id)?;
        let mut deadline = self.deadline(&peer)?;
        if let Some(route_deadline) = route_deadline {
            deadline = deadline.min(route_deadline);
        }
        if Instant::now() >= deadline {
            return Err(Error::Status);
        }
        let socket = tcp.try_clone().map_err(TunnelError::from)?;
        let inner = OpenSslAcceptor::from_pem_identity(self.pem, Policy::production_default())
            .map_err(|_| Error::Identity)?;
        let server = LinkServer::new(Box::new(OpenSslInnerAcceptor::new(
            inner,
            extractor(&peer)?,
        )));
        let mut accepted = server.accept_tls_stream_until(
            tcp,
            outer,
            SessionPolicy::default_pq768(self.local(), peer.peer()),
            deadline,
            admission,
        )?;
        let deadline = deadline.min(self.deadline(&peer)?);
        let received = bounded_link_operation(&socket, deadline, || {
            let session = &mut accepted.session;
            let ping = Probe::decode(&recv_control(session, ControlType::Probe)?)?;
            if ping.kind != ProbeKind::Ping {
                return Err(TunnelError::Unsupported("expected Core probe challenge"));
            }
            let pong = Probe {
                kind: ProbeKind::Pong,
                echo_monotonic_us: ping.sent_monotonic_us,
                ..ping
            };
            session.send_control(ControlType::Probe, &pong.encode()?)?;
            recv_control(session, ControlType::Lsa)
        })?;
        let now = self.check(&peer)?;
        let remote = self
            .trust
            .verify_and_authorize(&received[1..], now)
            .map_err(|_| Error::Lsa)?;
        neighbor(lsa(&remote, peer.id, now)?, self.local.id)?;
        let deadline = deadline.min(self.deadline(&peer)?);
        bounded_link_operation(&socket, deadline, || {
            send_lsa(&mut accepted.session, &self.local_lsa)
        })?;
        let remote_lsa_expiry = remote.valid_until();
        let expires = self.authority_deadline(&peer, remote_lsa_expiry)?;
        let selected = Selected {
            core_id: peer.id,
            attempts: 1,
            signed_lsa: received[1..].to_vec(),
        };
        Ok(Adjacency {
            session: accepted.session,
            socket,
            expires,
            peer,
            remote_lsa_expiry,
            remote_lsa_id: remote.object_id(),
            selected,
            _credits: (accepted.credit, accepted.buffer_credit),
        })
    }

    pub(crate) fn verified_core(&mut self, signed: &[u8]) -> Result<Core, Error> {
        let now = effective_utc(self.status)?;
        Core::from_object(
            &self
                .trust
                .verify_and_authorize(signed, now)
                .map_err(|_| Error::Identity)?,
            &self.policy,
        )
    }

    pub(crate) fn verified_lsa(
        &mut self,
        core: &Core,
        signed: &[u8],
    ) -> Result<VerifiedObject, Error> {
        let now = self.check(core)?;
        let object = self
            .trust
            .verify_and_authorize(signed, now)
            .map_err(|_| Error::Lsa)?;
        lsa(&object, core.id, now)?;
        Ok(object)
    }

    pub(crate) fn local_lsa(&self) -> &VerifiedObject {
        &self.local_lsa
    }

    pub(crate) fn is_exact_local(&self, core: &Core) -> bool {
        core.object_id == self.local.object_id && core.identity == self.local.identity
    }

    pub(crate) fn route_lsa_deadline(
        &mut self,
        core: &Core,
        object_id: [u8; 32],
        expires: u64,
    ) -> Result<Instant, Error> {
        if !self.trust.is_current_core_lsa(core.id, object_id) {
            return Err(Error::Lsa);
        }
        self.authority_deadline(core, expires)
    }

    // The status store is single-owner while a bounded transaction runs. An
    // already-issued monotonic cutoff is never extended; this fast check also
    // rejects UTC jumps without fsync per fragment. Rollback is durably latched.
    pub(crate) fn check_route_utc(
        &mut self,
        route: &[Core],
        remote_lsa_expiry: u64,
    ) -> Result<(), Error> {
        let observed = utc_now()?;
        let floor = self.status.last_trusted_utc();
        match self.status.check_active_snapshot(observed, Instant::now()) {
            Ok(()) => (),
            Err(boreas_pki::status_store::Error::ClockRollback) => {
                let _ = self.status.observe_trusted_utc(observed);
                return Err(Error::Status);
            }
            Err(_) => return Err(Error::Status),
        }
        let now = observed.max(floor);
        let cutoff = self
            .policy
            .validity()
            .1
            .min(self.local_lsa.valid_until())
            .min(remote_lsa_expiry);
        if now >= cutoff {
            return Err(Error::Status);
        }
        for node in route {
            let peer = AuthenticatedPeer::new(
                node.identity.net_id(),
                node.identity.node_id(),
                node.identity.identity_generation(),
            )
            .ok_or(Error::Identity)?;
            if now >= node.until
                || !matches!(self.status.peer_revocation(&peer),
                PeerRevocation::Verified(state) if !state.sessions_revoked())
            {
                return Err(Error::Status);
            }
        }
        Ok(())
    }

    pub(crate) fn endpoint_credential(&self) -> &PemIdentity {
        self.pem
    }
    pub(crate) fn policy_digest(&self) -> [u8; 32] {
        self.policy.policy_digest()
    }

    pub(crate) fn route_deadline(
        &mut self,
        route: &[Core],
        links: &[&Adjacency],
    ) -> Result<Instant, Error> {
        let mut deadline = Instant::now() + ATTEMPT_LIMIT;
        for link in links {
            if link.session.local() != self.local() {
                return Err(Error::Identity);
            }
            if !self
                .trust
                .is_current_core_lsa(link.peer.id, link.remote_lsa_id)
            {
                return Err(Error::Lsa);
            }
            deadline = deadline
                .min(link.expires)
                .min(self.authority_deadline(&link.peer, link.remote_lsa_expiry)?);
        }
        for member in route {
            deadline = deadline.min(self.authority_deadline(member, u64::MAX)?);
        }
        if Instant::now() >= deadline {
            return Err(Error::Status);
        }
        Ok(deadline)
    }

    fn check(&mut self, peer: &Core) -> Result<u64, Error> {
        self.with_fresh(peer, |_, now| now)
    }

    fn deadline(&mut self, peer: &Core) -> Result<Instant, Error> {
        Ok(self
            .authority_deadline(peer, u64::MAX)?
            .min(Instant::now() + ATTEMPT_LIMIT))
    }

    fn authority_deadline(
        &mut self,
        peer: &Core,
        remote_lsa_expiry: u64,
    ) -> Result<Instant, Error> {
        let utc = self
            .policy
            .validity()
            .1
            .min(self.local.until)
            .min(peer.until)
            .min(self.local_lsa.valid_until())
            .min(remote_lsa_expiry);
        self.with_fresh(peer, |fresh, now| {
            let left = Duration::from_micros(utc.saturating_sub(now));
            let now_mono = Instant::now();
            if left.is_zero() {
                return Err(Error::Lsa);
            }
            Ok(now_mono
                .checked_add(left)
                .unwrap_or(fresh.deadline())
                .min(fresh.deadline()))
        })?
    }

    fn with_fresh<T>(
        &mut self,
        peer: &Core,
        f: impl FnOnce(&FreshStatus<'_>, u64) -> T,
    ) -> Result<T, Error> {
        let observed = utc_now()?;
        for node in [&self.local, peer] {
            if !self
                .trust
                .is_current_identity(node.identity.node_id(), node.object_id)
            {
                return Err(Error::Identity);
            }
        }
        if !self
            .trust
            .is_current_core_lsa(self.local.id, self.local_lsa.object_id())
        {
            return Err(Error::Lsa);
        }
        let now = observed.max(self.status.last_trusted_utc());
        let fresh = self
            .status
            .current_fresh(observed, Instant::now())
            .map_err(|_| Error::Status)?;
        let (start, end) = self.policy.validity();
        if now < start || now >= end {
            return Err(Error::Trust);
        }
        self.local.check(&fresh, now)?;
        peer.check(&fresh, now)?;
        lsa(&self.local_lsa, self.local.id, now)?;
        Ok(f(&fresh, now))
    }
}

fn effective_utc(status: &mut StatusStore) -> Result<u64, Error> {
    status
        .observe_trusted_utc(utc_now()?)
        .map_err(|_| Error::Status)
}

fn lsa(object: &VerifiedObject, core: u8, now: u64) -> Result<&CoreLsa, Error> {
    match &object.object().body {
        ObjectBody::CoreLsa(lsa) if lsa.core_id == core && now < object.valid_until() => Ok(lsa),
        _ => Err(Error::Lsa),
    }
}

fn neighbor(lsa: &CoreLsa, peer: u8) -> Result<(u16, u32), Error> {
    lsa.neighbors
        .iter()
        .find(|n| n.peer_core_id == peer && n.path_type == PathRole::Cdn as u8)
        .map(|n| (n.rtt_p50_ms, n.loss_ppm))
        .ok_or(Error::NoRoute)
}

fn extractor(peer: &Core) -> Result<Arc<PkiIdentityExtractor>, TunnelError> {
    Ok(Arc::new(PkiIdentityExtractor::new(vec![
        peer.identity.clone(),
    ])?))
}

fn send_lsa(session: &mut EstablishedSession, object: &VerifiedObject) -> Result<(), TunnelError> {
    let mut body = vec![ControlType::Lsa as u8];
    body.extend_from_slice(object.raw_signed_object());
    session.send_control(ControlType::Lsa, &body)
}

fn recv_control(
    session: &mut EstablishedSession,
    control: ControlType,
) -> Result<Vec<u8>, TunnelError> {
    let frame = session.recv_frame()?;
    if frame.header.kind != Kind::Control || frame.body.first() != Some(&(control as u8)) {
        return Err(crate::CircuitReject::UnexpectedFrame.into());
    }
    Ok(frame.body)
}

fn path_loss(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        kind,
        TimedOut | ConnectionRefused | NetworkUnreachable | HostUnreachable
    )
}
