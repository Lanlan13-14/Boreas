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

struct Core {
    id: u8,
    identity: VerifiedNodeIdentity,
    until: u64,
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

#[derive(Debug, Eq, PartialEq)]
pub struct Selected {
    pub core_id: u8,
    pub attempts: usize,
    /// Original authenticated LSA envelope, not reconstructed TBS or signatures.
    pub signed_lsa: Vec<u8>,
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

    /// Select a *direct* CDN-class neighbor. Only TCP failures before any TLS
    /// bytes enable fallback. Wrong identity, protocol, authorization, or LSA
    /// terminates the transaction instead of being misclassified as path loss.
    pub fn select(
        &mut self,
        candidates: &[Candidate<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
    ) -> Result<Selected, Error> {
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
            let deadline = self.deadline(&peer)?;
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
                    last_dial = Error::Transport(error.into());
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
            let deadline = deadline.min(self.deadline(&peer)?);
            let (reply, received) = bounded_link_operation(&socket, deadline, || {
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
                let received = recv_control(&mut session, ControlType::Lsa)?;
                Ok((reply, received))
            })?;
            debug_assert_eq!(reply.kind, ProbeKind::Pong);
            let now = self.check(&peer)?;
            let raw = &received[1..];
            let remote = self
                .trust
                .verify_and_authorize(raw, now)
                .map_err(|_| Error::Lsa)?;
            neighbor(lsa(&remote, id, now)?, self.local.id)?;
            return Ok(Selected {
                core_id: id,
                attempts: index + 1,
                signed_lsa: raw.to_vec(),
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
        let deadline = self.deadline(&peer)?;
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
        Ok(Selected {
            core_id: peer.id,
            attempts: 1,
            signed_lsa: received[1..].to_vec(),
        })
    }

    fn check(&mut self, peer: &Core) -> Result<u64, Error> {
        self.with_fresh(peer, |_, now| now)
    }

    fn deadline(&mut self, peer: &Core) -> Result<Instant, Error> {
        let utc = self
            .policy
            .validity()
            .1
            .min(self.local.until)
            .min(peer.until)
            .min(self.local_lsa.valid_until());
        self.with_fresh(peer, |fresh, now| {
            let left = Duration::from_micros(utc.saturating_sub(now)).min(ATTEMPT_LIMIT);
            fresh.deadline().min(Instant::now() + left)
        })
    }

    fn with_fresh<T>(
        &mut self,
        peer: &Core,
        f: impl FnOnce(&FreshStatus<'_>, u64) -> T,
    ) -> Result<T, Error> {
        let observed = utc_now()?;
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
