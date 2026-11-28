//! Bounded direct Core adjacency, LSA and identity revocation exchange on strict pq768
//! hop sessions. No graph route, application frames, or E2E secrets enter here.

use std::{
    collections::BTreeMap,
    net::TcpStream,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use boreas_crypto::{
    NodeRole, Policy,
    backend::PemIdentity,
    pq_wg::PqWgIdentity,
};
use boreas_pki::{
    Authority, VerifiedNetworkContext,
    authority_revocation::AuthorityRevocationTrust,
    management::{Error as ManagementError, ManagementTrust, VerifiedObject},
    provisioning::RootsBundle,
    status_store::{AuthenticatedPeer, FreshStatus, PeerRevocation, StatusStore},
};
use boreas_proto::{
    ControlType, Kind,
    authority_revocation::MAX_IDENTITY_REVOCATIONS,
    messages::{
        PathRole, Probe, ProbeKind, decode_identity_revocation, encode_identity_revocation,
    },
    objects::{CoreLsa, ObjectBody},
};

use crate::{
    ClientTarget, EstablishedSession, LinkClient, LinkServer, OpenSslOuterTlsAcceptor,
    OpenSslOuterTlsConnector, PeerIdentity, PqWgInnerAcceptor, PqWgInnerConnector,
    PeerIdentityExtractor, PkiIdentityExtractor, SessionPolicy, TunnelError, VerifiedNodeIdentity,
    resource::Admission, runtime::bounded_link_operation,
};

mod directory_sync;
mod live_identity;
mod routed_business;

pub const ATTEMPT_LIMIT: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: usize = 3;

#[derive(Clone, Copy)]
enum HopPurpose {
    Business(Option<(Instant, [u8; 32])>),
    // A separately provisioned transport adjacency, not a business edge.
    Directory,
}

impl HopPurpose {
    fn route(self) -> Option<(Instant, [u8; 32])> {
        match self {
            Self::Business(route) => route,
            Self::Directory => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Trust,
    Identity,
    Lsa,
    /// A verified same-version fork was persisted, or restored at startup.
    LsaConflict,
    /// The durable CoreLSA authority state is unavailable or inconsistent.
    LsaState,
    Status,
    /// Local mailbox input or a live authority worker failed; stop business.
    RevocationState,
    IdentityRevoked,
    /// The pinned NetworkRoot denied this Core generation.
    CoreRevoked,
    Clock,
    NoRoute,
    /// A configured Core has no seed and no learned directory head yet.
    DirectoryPending,
    WrongReply,
    /// An authenticated hop advanced a graph member; rebuild before retrying.
    TopologyChanged,
    /// TCP dial failed before emitting any TLS bytes (graph profile only).
    PathUnavailable(TunnelError),
    /// At least one confirmed business circuit lost transport, with no replay.
    ConfirmedPathLost(TunnelError),
    Transport(TunnelError),
}

impl Error {
    /// A committed member denial is an authority event, not a transport loss.
    pub const fn member_denial(&self) -> bool {
        matches!(self, Self::IdentityRevoked | Self::CoreRevoked)
    }
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
    mesh_trust(roots, policy, now).map(|(management, _)| management)
}

/// Both verifiers are derived from the same root-bound grants. A Core is
/// a transport peer, never an issuer of another identity's denial.
pub fn mesh_trust(
    roots: &RootsBundle,
    policy: &VerifiedNetworkContext,
    now: u64,
) -> Result<(ManagementTrust, AuthorityRevocationTrust), Error> {
    let net = policy.net_id();
    let (fingerprint, grants) = roots.verify_all(net, now).map_err(|_| Error::Trust)?;
    if fingerprint != policy.root_key_fingerprint() {
        return Err(Error::Trust);
    }
    let mut trust = ManagementTrust::new(net);
    let mut identity = AuthorityRevocationTrust::new(net);
    identity.add_network_root(&roots.network_root_pin().map_err(|_| Error::Trust)?, fingerprint)
        .map_err(|_| Error::Trust)?;
    let (mut has_status, mut has_identity) = (false, false);
    for grant in grants {
        trust.add_verified_issuer(&grant).map_err(|_| Error::Trust)?;
        let authority = grant.issuer_record().authority;
        has_status |= authority == Authority::StatusSigner;
        has_identity |= authority == Authority::IdentityAuthority;
        if matches!(authority, Authority::IdentityAuthority | Authority::RouteAuthority
            | Authority::CoreOperationalKey { .. })
        {
            identity.add_verified_issuer(grant).map_err(|_| Error::Trust)?;
        }
    }
    if !has_status || !has_identity {
        return Err(Error::Trust);
    }
    Ok((trust, identity))
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
        let peer = self.authenticated_slot()?;
        match fresh.identity_revoked(&peer) {
            Ok(false) => (),
            Ok(true) => return Err(Error::IdentityRevoked),
            Err(_) => return Err(Error::Status),
        }
        match fresh.core_revoked(&peer) {
            Ok(false) => (),
            Ok(true) => return Err(Error::CoreRevoked),
            Err(_) => return Err(Error::Status),
        }
        match fresh.peer_revocation(&peer) {
            PeerRevocation::Verified(state) if !state.sessions_revoked() => Ok(()),
            _ => Err(Error::Status),
        }
    }

    fn authenticated_slot(&self) -> Result<AuthenticatedPeer, Error> {
        AuthenticatedPeer::new(
            self.identity.net_id(),
            self.identity.node_id(),
            self.identity.identity_generation(),
        )
        .ok_or(Error::Identity)
    }

    fn check_identity_denial(&self, status: &StatusStore) -> Result<(), Error> {
        let peer = self.authenticated_slot()?;
        match status.identity_revoked(&peer) {
            Ok(false) => (),
            Ok(true) => return Err(Error::IdentityRevoked),
            Err(_) => return Err(Error::Status),
        }
        match status.core_revoked(&peer) {
            Ok(false) => Ok(()),
            Ok(true) => Err(Error::CoreRevoked),
            Err(_) => Err(Error::Status),
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
    attempt_until: Instant,
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
    // One verified envelope per remote Core ID (at most 15). Both configured
    // seeds and authenticated hop sessions update this same replay-backed view.
    remote_lsas: BTreeMap<u8, VerifiedObject>,
    durable: bool,
    status: Mutex<&'a mut StatusStore>,
    live_identity: live_identity::Mailbox<'a>,
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
        Self::new_inner(policy, roots, status, pem, local_identity, local_lsa, None)
    }

    /// Mesh service constructor. Replay floors and exact fork evidence are
    /// durable for every LSA source, not just directory control links.
    pub fn new_durable(
        policy: VerifiedNetworkContext,
        roots: &RootsBundle,
        status: &'a mut StatusStore,
        pem: &'a PemIdentity,
        local_identity: &[u8],
        local_lsa: &[u8],
        state: (&std::path::Path, u32),
    ) -> Result<Self, Error> {
        Self::new_inner(
            policy,
            roots,
            status,
            pem,
            local_identity,
            local_lsa,
            Some(state),
        )
    }

    fn new_inner(
        policy: VerifiedNetworkContext,
        roots: &RootsBundle,
        status: &'a mut StatusStore,
        pem: &'a PemIdentity,
        local_identity: &[u8],
        local_lsa: &[u8],
        state: Option<(&std::path::Path, u32)>,
    ) -> Result<Self, Error> {
        if status.net_id() != policy.net_id() {
            return Err(Error::Status);
        }
        let now = utc_now()?.max(status.last_trusted_utc());
        let (mut trust, identity_trust) = mesh_trust(roots, &policy, now)?;
        if !status.has_same_authorities(&trust)
            || !status.has_same_identity_authorities(policy.root_key_fingerprint(), &identity_trust)
        {
            return Err(Error::Status);
        }
        let local = Core::from_object(
            &trust
                .verify_and_authorize(local_identity, now)
                .map_err(|_| Error::Identity)?,
            &policy,
        )?;
        let pq_identity = PqWgIdentity::from_private_key_pem(&pem.private_key_pem)
            .map_err(|_| Error::Identity)?;
        if extractor(&local)?
            .resolve_spki_hash(pq_identity.spki_hash())
            .map(|(spki, peer)| spki == pq_identity.public_spki() && peer == local.peer())
            != Some(true)
        {
            return Err(Error::Identity);
        }
        let mut remote_lsas = match state {
            Some((path, owner)) => trust
                .open_core_lsa_ledger(path, owner, policy.root_key_fingerprint(), local.id, now)
                .map_err(|e| map_lsa_error(e, true))?
                .into_iter()
                .collect(),
            None => BTreeMap::new(),
        };
        let original = remote_lsas.remove(&local.id);
        let verified = trust
            .verify_core_lsa(local_lsa, local.id, now)
            .map_err(|e| map_lsa_error(e, state.is_some()))?;
        let local_lsa = if verified.is_duplicate() {
            original.unwrap_or(verified)
        } else {
            verified
        };
        lsa(&local_lsa, local.id, now)?;
        Ok(Self {
            policy,
            trust,
            local,
            local_lsa,
            remote_lsas,
            durable: state.is_some(),
            status: Mutex::new(status),
            live_identity: live_identity::Mailbox::default(),
            pem,
        })
    }

    pub fn local(&self) -> PeerIdentity {
        self.local.peer()
    }

    fn status(&self) -> Result<MutexGuard<'_, &'a mut StatusStore>, Error> {
        self.status.lock().map_err(|_| Error::RevocationState)
    }

    fn effective_utc(&self) -> Result<u64, Error> {
        let mut status = self.status()?;
        effective_utc(&mut status)
    }

    /// Check only the independent durable denial for a verified slot. A
    /// directory can isolate a remote denial without weakening local authority.
    pub(crate) fn check_identity_denial(&self, core: &Core) -> Result<(), Error> {
        let status = self.status()?;
        core.check_identity_denial(&status)
    }

    pub(crate) fn check_local_identity_denial(&self) -> Result<(), Error> {
        self.check_identity_denial(&self.local)
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
        self.status()?
            .accept_signed_snapshot(snapshot, observed, mono)
            .map_err(|_| Error::Status)?;
        self.poll_identity_mailbox()?;
        if let Some(raw) = identity_revocation {
            self.status()?
                .accept_identity_revocation(raw, utc_now()?)
                .map_err(|_| Error::Status)?;
        }
        let now = self.effective_utc()?;
        let verified = self
            .trust
            .verify_core_lsa(local_lsa, self.local.id, now)
            .map_err(|e| map_lsa_error(e, self.durable))?;
        lsa(&verified, self.local.id, now)?;
        if !verified.is_duplicate() {
            self.local_lsa = verified;
        }
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
        route: Option<(Instant, [u8; 32])>,
    ) -> Result<Adjacency, Error> {
        self.dial_for(candidates, outer, admission, HopPurpose::Business(route))
    }

    fn dial_for(
        &mut self,
        candidates: &[Candidate<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
        purpose: HopPurpose,
    ) -> Result<Adjacency, Error> {
        self.poll_identity_mailbox()?;
        let route = purpose.route();
        if candidates.is_empty() || candidates.len() > MAX_ATTEMPTS {
            return Err(Error::NoRoute);
        }
        let now = self.effective_utc()?;
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
            let score = match purpose {
                HopPurpose::Business(_) => {
                    neighbor(lsa(&self.local_lsa, self.local.id, now)?, peer.id)?
                }
                HopPurpose::Directory => (0, 0),
            };
            ordered.push((score.0, score.1, peer.id, peer, candidate.target));
        }
        ordered.sort_unstable_by_key(|entry| (entry.0, entry.1, entry.2));
        let mut last_dial = Error::NoRoute;
        for (index, (_, _, id, peer, target)) in ordered.into_iter().enumerate() {
            let mut deadline = self.deadline(&peer)?;
            if let Some((route_deadline, _)) = route {
                deadline = deadline.min(route_deadline);
            }
            if Instant::now() >= deadline {
                return Err(Error::Status);
            }
            let handshake = admission.reserve_handshake().map_err(TunnelError::from)?;
            let buffer = admission
                .reserve_bytes(crate::runtime::CONNECTION_BUFFER_BUDGET)
                .map_err(TunnelError::from)?;
            let pq_identity = PqWgIdentity::from_private_key_pem(&self.pem.private_key_pem)
                .map_err(|_| Error::Identity)?;
            let client = LinkClient::new(
                Box::new(outer()?),
                Box::new(
                    PqWgInnerConnector::new(
                        pq_identity,
                        Policy::production_default(),
                        extractor(&peer)?,
                    )
                    .map_err(|_| Error::Identity)?,
                ),
            );
            let tcp = match client
                .connect_tcp(target, deadline.saturating_duration_since(Instant::now()))
            {
                Ok(tcp) => tcp,
                Err(error) if path_loss(error.kind()) => {
                    self.poll_identity_mailbox()?;
                    self.check(&peer)?;
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
            let raw = &received[1..];
            let (remote, now) = self.verify_remote_lsa(&peer, Some(raw), false)?;
            let changed = match self.check_hop_advertisement(&remote, id, now, purpose) {
                Ok(()) => false,
                Err(Error::TopologyChanged) => true,
                Err(e) => return Err(e),
            };
            let remote_lsa_expiry = remote.valid_until();
            self.exchange_identity_revocations(
                &mut session,
                &socket,
                &peer,
                remote_lsa_expiry,
                deadline,
                true,
            )?;
            if changed {
                return Err(Error::TopologyChanged);
            }
            let expires = self.authority_deadline(&peer, remote_lsa_expiry)?;
            return Ok(Adjacency {
                session,
                socket,
                expires,
                attempt_until: deadline,
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
        route: Option<(Instant, [u8; 32])>,
    ) -> Result<Adjacency, Error> {
        self.accept_for(
            tcp,
            signed_peer_identity,
            outer,
            admission,
            HopPurpose::Business(route),
        )
    }

    fn accept_for(
        &mut self,
        tcp: TcpStream,
        signed_peer_identity: &[u8],
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
        purpose: HopPurpose,
    ) -> Result<Adjacency, Error> {
        self.poll_identity_mailbox()?;
        let route = purpose.route();
        let now = self.effective_utc()?;
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
        if matches!(purpose, HopPurpose::Business(_)) {
            neighbor(lsa(&self.local_lsa, self.local.id, now)?, peer.id)?;
        }
        let mut deadline = self.deadline(&peer)?;
        if let Some((route_deadline, _)) = route {
            deadline = deadline.min(route_deadline);
        }
        if Instant::now() >= deadline {
            return Err(Error::Status);
        }
        let socket = tcp.try_clone().map_err(TunnelError::from)?;
        let pq_identity = PqWgIdentity::from_private_key_pem(&self.pem.private_key_pem)
            .map_err(|_| Error::Identity)?;
        let server = LinkServer::new(Box::new(
            PqWgInnerAcceptor::new(pq_identity, Policy::production_default(), extractor(&peer)?)
                .map_err(|_| Error::Identity)?,
        ));
        let accepted = server.accept_tls_stream_until(
            tcp,
            outer,
            SessionPolicy::default_pq768(self.local(), peer.peer()),
            deadline,
            admission,
        )?;
        self.accept_advertisements(accepted, socket, peer, purpose, deadline)
    }

    fn accept_advertisements(
        &mut self,
        mut accepted: crate::AcceptedSession,
        socket: TcpStream,
        peer: Core,
        purpose: HopPurpose,
        deadline: Instant,
    ) -> Result<Adjacency, Error> {
        self.poll_identity_mailbox()?;
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
        let (remote, now) = self.verify_remote_lsa(&peer, Some(&received[1..]), false)?;
        let changed = match self.check_hop_advertisement(&remote, peer.id, now, purpose) {
            Ok(()) => false,
            Err(Error::TopologyChanged) => true,
            Err(e) => return Err(e),
        };
        let deadline = deadline.min(self.deadline(&peer)?);
        bounded_link_operation(&socket, deadline, || {
            send_lsa(&mut accepted.session, &self.local_lsa)
        })?;
        let remote_lsa_expiry = remote.valid_until();
        self.exchange_identity_revocations(
            &mut accepted.session,
            &socket,
            &peer,
            remote_lsa_expiry,
            deadline,
            false,
        )?;
        if changed {
            return Err(Error::TopologyChanged);
        }
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
            attempt_until: deadline,
            peer,
            remote_lsa_expiry,
            remote_lsa_id: remote.object_id(),
            selected,
            _credits: (accepted.credit, accepted.buffer_credit),
        })
    }

    // One batch in each direction after the signed LSA exchange. Use the
    // existing absolute budget; no timeout-as-idle or downgrade to old Revoke.
    fn exchange_identity_revocations(
        &mut self,
        session: &mut EstablishedSession,
        socket: &TcpStream,
        peer: &Core,
        remote_lsa_expiry: u64,
        deadline: Instant,
        initiator: bool,
    ) -> Result<(), Error> {
        let deadline = deadline.min(self.authority_deadline(peer, remote_lsa_expiry)?);
        // Bound the whole transaction and preserve the actual local error for
        // the caller. A responder may echo newly committed evidence; exact
        // previously accepted carriers never extend status or decision TTL.
        let mut local_error = None;
        let result = bounded_link_operation(socket, deadline, || {
            let outcome = (|| -> Result<(), Error> {
                if initiator {
                    self.send_revocations(session)?;
                }
                for index in 0..=MAX_IDENTITY_REVOCATIONS {
                    let body = recv_control(session, ControlType::IdentityRevocation)?;
                    let raw = decode_identity_revocation(&body).map_err(TunnelError::from)?;
                    let Some(raw) = raw else { break };
                    if index == MAX_IDENTITY_REVOCATIONS {
                        return Err(TunnelError::Unsupported(
                            "identity revocation batch exceeds bound",
                        )
                        .into());
                    }
                    self.check_route_utc(std::slice::from_ref(peer), remote_lsa_expiry)?;
                    match self.status()?.accept_identity_revocation(raw, utc_now()?) {
                        // The store returns Stale only after verifying both
                        // signatures, exact scope and current validity. It
                        // already holds a newer denial of the same generation.
                        Ok(()) | Err(boreas_pki::status_store::Error::RevocationStale) => (),
                        Err(
                            boreas_pki::status_store::Error::AuthorityRevocation(_)
                            | boreas_pki::status_store::Error::RevocationPermission,
                        ) => return Err(Error::Status),
                        Err(_) => return Err(Error::RevocationState),
                    }
                    // Stop promptly if the object names either endpoint, or if
                    // the independent status/LSA/policy deadline expired.
                    self.check_route_utc(std::slice::from_ref(peer), remote_lsa_expiry)?;
                }
                self.check_route_utc(std::slice::from_ref(peer), remote_lsa_expiry)?;
                if !initiator {
                    self.send_revocations(session)?;
                }
                Ok(())
            })();
            match outcome {
                Ok(()) => Ok(()),
                Err(Error::Transport(e)) => Err(e),
                Err(e) => {
                    local_error = Some(e);
                    Err(TunnelError::Unsupported(
                        "identity revocation exchange rejected",
                    ))
                }
            }
        });
        if let Some(error) = local_error {
            return Err(error);
        }
        result.map_err(Error::from)
    }

    fn send_revocations(&mut self, session: &mut EstablishedSession) -> Result<(), Error> {
        // Control exchange is serial with business: no live mailbox worker
        // exists in this phase. Borrow rather than copying the whole batch.
        let mut status = self.status()?;
        let evidence = status
            .relayable_identity_revocations(utc_now()?)
            .map_err(|_| Error::Status)?;
        for raw in evidence {
            let body = encode_identity_revocation(Some(raw)).map_err(TunnelError::from)?;
            session.send_control(ControlType::IdentityRevocation, &body)?;
        }
        let end = encode_identity_revocation(None).map_err(TunnelError::from)?;
        session.send_control(ControlType::IdentityRevocation, &end)?;
        Ok(())
    }

    pub(crate) fn verified_core(&mut self, signed: &[u8]) -> Result<Core, Error> {
        let now = self.effective_utc()?;
        Core::from_object(
            &self
                .trust
                .verify_and_authorize(signed, now)
                .map_err(|_| Error::Identity)?,
            &self.policy,
        )
    }

    pub(crate) fn verify_remote_lsa(
        &mut self,
        core: &Core,
        signed: Option<&[u8]>,
        use_directory: bool,
    ) -> Result<(VerifiedObject, u64), Error> {
        if core.id == self.local.id {
            return Err(Error::Lsa);
        }
        let now = self.check(core)?;
        if let Some(raw) = signed {
            match self.trust.verify_core_lsa(raw, core.id, now) {
                Ok(object) => {
                    if !object.is_duplicate() || !self.remote_lsas.contains_key(&core.id) {
                        self.remote_lsas.insert(core.id, object.clone());
                    } else if use_directory {
                        return Ok((self.remote_lsas[&core.id].clone(), now));
                    }
                    return Ok((object, now));
                }
                Err(ManagementError::StaleSequence) if use_directory => (),
                Err(e) => return Err(map_lsa_error(e, self.durable)),
            }
        } else if !use_directory {
            return Err(Error::Lsa);
        }
        // A missing seed or a still-valid, authenticated older seed can use
        // the directory head. Neither an invalid seed nor a poisoned/expired
        // head can extend authority or resurrect an older route.
        let head = self
            .remote_lsas
            .get(&core.id)
            .ok_or(Error::DirectoryPending)?;
        if !self.trust.is_current_core_lsa(core.id, head.object_id()) {
            return Err(Error::Lsa);
        }
        lsa(head, core.id, now)?;
        Ok((head.clone(), now))
    }

    fn check_hop_advertisement(
        &self,
        remote: &VerifiedObject,
        id: u8,
        now: u64,
        purpose: HopPurpose,
    ) -> Result<(), Error> {
        let lsa = lsa(remote, id, now)?;
        if let HopPurpose::Business(route) = purpose {
            if route.is_some_and(|(_, expected)| expected != remote.object_id()) {
                return Err(Error::TopologyChanged);
            }
            neighbor(lsa, self.local.id)?;
        }
        Ok(())
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

    // The status ledger is serialized with the scoped mailbox watcher. An
    // already-issued monotonic cutoff is never extended; this quick check
    // rejects UTC jumps without fsync per fragment. Rollback is durably latched.
    pub(crate) fn check_route_utc(
        &self,
        route: &[Core],
        remote_lsa_expiry: u64,
    ) -> Result<(), Error> {
        let observed = utc_now()?;
        self.live_identity.check_fault()?;
        let mut status = self.status()?;
        let floor = status.last_trusted_utc();
        match status.check_active_snapshot(observed, Instant::now()) {
            Ok(()) => (),
            Err(boreas_pki::status_store::Error::ClockRollback) => {
                let _ = status.observe_trusted_utc(observed);
                return Err(Error::Status);
            }
            Err(_) => return Err(Error::Status),
        }
        let now = observed.max(floor);
        let (start, policy_expiry) = self.policy.validity();
        let cutoff = policy_expiry
            .min(self.local_lsa.valid_until())
            .min(remote_lsa_expiry);
        self.local.check_identity_denial(&status)?;
        for node in route {
            node.check_identity_denial(&status)?;
        }
        if now < start
            || now >= cutoff
            || now < self.local.identity.not_before()
            || now >= self.local.until
            || route
                .iter()
                .any(|node| now < node.identity.not_before() || now >= node.until)
        {
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
                || !matches!(status.peer_revocation(&peer),
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
        self.poll_identity_mailbox()?;
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

    pub(crate) fn check(&mut self, peer: &Core) -> Result<u64, Error> {
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
        self.live_identity.check_fault()?;
        let mut status = self.status()?;
        let now = observed.max(status.last_trusted_utc());
        let fresh = status
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

fn map_lsa_error(error: ManagementError, durable: bool) -> Error {
    match error {
        ManagementError::Equivocation if durable => Error::LsaConflict,
        ManagementError::CoreLsaState => Error::LsaState,
        _ => Error::Lsa,
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
