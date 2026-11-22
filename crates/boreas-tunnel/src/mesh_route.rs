//! Bounded Core graph profile for dedicated E2E circuits. Trust inputs are
//! local policy, status, signed identities and signed LSAs, not a peer's path
//! assertion. Runtime configuration binds an endpoint pair and adjacent hop
//! transports; this module neither discovers locators nor floods LSAs.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    net::TcpStream,
    time::Instant,
};

use boreas_pki::management::VerifiedObject;
use boreas_proto::{
    ControlType, Kind,
    messages::{MAX_MESH_PATH_CORES, PathRole, decode_mesh_path, encode_mesh_path},
    objects::ObjectBody,
};

use crate::{
    ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, TunnelError,
    e2e::E2eCircuit,
    mesh_probe::{ATTEMPT_LIMIT, Adjacency, Candidate, Core, Error, MeshProbe},
    mesh_relay::{EndpointIo, FixedRoute, Forwarded, forward_fixed, with_fixed_endpoint_io},
    resource::Admission,
    runtime::bounded_link_operation,
    ws::WsError,
};

const MAX_CORES: usize = 16;
const MAX_ROUTE_CORES: usize = MAX_MESH_PATH_CORES;
type PathRank = (u64, u32, usize, [u8; MAX_ROUTE_CORES]);
type RankedPath = (PathRank, Vec<u8>);

/// Non-local Core input; no locator or public key is taken from its LSA.
pub struct SignedCore<'a> {
    pub identity: &'a [u8],
    pub lsa: &'a [u8],
}

/// Configured Core identity and an optional operator-published LSA seed.
pub struct DirectoryCore<'a> {
    pub identity: &'a [u8],
    pub seed_lsa: Option<&'a [u8]>,
}

struct Vertex<'a> {
    core: Core,
    identity: &'a [u8],
    lsa: VerifiedObject,
}

/// An owner-bound graph snapshot. Each route use checks selected members
/// against this probe's current replay heads, policy and revocation state.
pub struct VerifiedGraph<'a> {
    local: crate::PeerIdentity,
    vertices: BTreeMap<u8, Vertex<'a>>,
    denied: u32,
}

impl MeshProbe<'_> {
    /// The local signed materials are already loaded in the probe and must
    /// not be duplicated here. Reject malformed, stale or equivocating input
    /// instead of silently turning it into a smaller trusted graph.
    pub fn verify_route_graph<'a>(
        &mut self,
        local_identity: &'a [u8],
        others: &[SignedCore<'a>],
    ) -> Result<VerifiedGraph<'a>, Error> {
        self.build_graph(
            local_identity,
            others.iter().map(|raw| (raw.identity, Some(raw.lsa))),
            false,
        )
    }

    /// Select the live LSA directory head for each configured Core. A still
    /// valid old seed may lag an authenticated hop update. Invalid signatures,
    /// equivocation, revocation and expiry are not path-loss signals.
    pub fn verify_directory_graph<'a>(
        &mut self,
        local_identity: &'a [u8],
        others: &[DirectoryCore<'a>],
    ) -> Result<VerifiedGraph<'a>, Error> {
        self.build_graph(
            local_identity,
            others.iter().map(|raw| (raw.identity, raw.seed_lsa)),
            true,
        )
    }

    fn build_graph<'a>(
        &mut self,
        local_identity: &'a [u8],
        others: impl ExactSizeIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
        use_directory: bool,
    ) -> Result<VerifiedGraph<'a>, Error> {
        if others.len() >= MAX_CORES {
            return Err(Error::NoRoute);
        }
        self.poll_identity_mailbox()?;
        let local = self.verified_core(local_identity)?;
        if !self.is_exact_local(&local) {
            return Err(Error::Identity);
        }
        self.check(&local)?;
        let local_id = local.id;
        let mut seen = 1u32 << local_id;
        let mut vertices = BTreeMap::from([(local_id, Vertex {
            core: local,
            identity: local_identity,
            lsa: self.local_lsa().clone(),
        })]);
        let mut pending = false;
        let mut denied = 0;
        for (identity, seed) in others {
            let core = self.verified_core(identity)?;
            // Verify before rejecting duplicate IDs so a signed fork poisons
            // the replay slot in the long-lived owner, not merely this import.
            let head = self.verify_remote_lsa(&core, seed, use_directory);
            let bit = 1u32 << core.id;
            if seen & bit != 0 {
                return Err(Error::Lsa);
            }
            seen |= bit;
            match head {
                Ok((lsa, _)) => {
                    vertices.insert(core.id, Vertex {
                        core,
                        identity,
                        lsa,
                    });
                }
                Err(Error::DirectoryPending) => pending = true,
                // In the runtime directory profile, a committed remote denial
                // removes usable edges, not configured membership. Preserve
                // healthy control links so signed denials can cross the mesh.
                Err(Error::IdentityRevoked) if use_directory => {
                    self.check_local_identity_denial()?;
                    match self.check_identity_denial(&core) {
                        Err(Error::IdentityRevoked) => denied |= bit,
                        Err(e) => return Err(e),
                        Ok(()) => return Err(Error::IdentityRevoked),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        for v in vertices.values() {
            self.route_lsa_deadline(&v.core, v.lsa.object_id(), v.lsa.valid_until())?;
        }
        if pending {
            return Err(Error::DirectoryPending);
        }
        Ok(VerifiedGraph {
            local: self.local(),
            vertices,
            denied,
        })
    }
}

impl VerifiedGraph<'_> {
    /// Verified slots, independent of untrusted material filenames.
    pub fn core_ids(&self) -> impl Iterator<Item = u8> + '_ {
        (1..=MAX_CORES as u8)
            .filter(|&id| self.vertices.contains_key(&id) || self.denied & (1u32 << id) != 0)
    }

    /// Original envelope captured by this snapshot, for inspection only.
    /// A caller must still use a route authorization method for current authority.
    pub fn signed_lsa(&self, id: u8) -> Option<&[u8]> {
        Some(self.vertices.get(&id)?.lsa.raw_signed_object())
    }

    fn vertex(&self, id: u8) -> Result<&Vertex<'_>, Error> {
        if id <= MAX_CORES as u8 && self.denied & (1u32 << id) != 0 {
            return Err(Error::IdentityRevoked);
        }
        self.vertices.get(&id).ok_or(Error::NoRoute)
    }

    fn edge(&self, a: u8, b: u8) -> Option<(u32, u64)> {
        let lookup = |from, to| {
            let ObjectBody::CoreLsa(lsa) = &self.vertices.get(&from)?.lsa.object().body else {
                return None;
            };
            let n = lsa.neighbors.iter().find(|n| {
                n.peer_core_id == to && n.path_type == PathRole::Cdn as u8 && n.loss_ppm < 1_000_000
            })?;
            Some((u32::from(n.rtt_p50_ms), u64::from(n.loss_ppm)))
        };
        let (ar, al) = lookup(a, b)?;
        let (br, bl) = lookup(b, a)?;
        Some((ar.max(br), al.max(bl)))
    }

    fn owner(&self, probe: &MeshProbe<'_>) -> Result<(), Error> {
        if self.local != probe.local() {
            return Err(Error::Identity);
        }
        Ok(())
    }

    /// Exact receiver/relay route for a dedicated listener. Provisioning an
    /// ordered list constrains where the listener can go; it does not bypass
    /// two-sided signed adjacency or the endpoint/profile binding.
    pub fn authorize_path(
        &self,
        probe: &mut MeshProbe<'_>,
        ids: &[u8],
    ) -> Result<FixedRoute, Error> {
        if ids.len() < 3 {
            return Err(Error::NoRoute);
        }
        self.authorize_graph_path(probe, ids, Instant::now() + ATTEMPT_LIMIT)
    }

    fn authorize_graph_path(
        &self,
        probe: &mut MeshProbe<'_>,
        ids: &[u8],
        until: Instant,
    ) -> Result<FixedRoute, Error> {
        self.owner(probe)?;
        probe.poll_identity_mailbox()?;
        if !(2..=MAX_ROUTE_CORES).contains(&ids.len())
            || ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id))
        {
            return Err(Error::NoRoute);
        }
        let mut members = Vec::with_capacity(ids.len());
        let mut advertisements = Vec::with_capacity(ids.len());
        for &id in ids {
            let v = self.vertex(id)?;
            let ad = (v.lsa.object_id(), v.lsa.valid_until());
            self.check_vertex(probe, v)?;
            members.push(v.core.clone());
            advertisements.push(ad);
        }
        if members[0].identity.node_id() >= members[ids.len() - 1].identity.node_id()
            || self.rank(ids).is_none()
        {
            return Err(Error::NoRoute);
        }
        let position = members
            .iter()
            .position(|m| m.identity.peer_identity() == self.local)
            .ok_or(Error::Identity)?;
        Ok(FixedRoute {
            members,
            position,
            advertisements,
            attempt_until: Some(until),
        })
    }

    fn check_vertex(&self, probe: &mut MeshProbe<'_>, v: &Vertex<'_>) -> Result<(), Error> {
        probe.route_lsa_deadline(&v.core, v.lsa.object_id(), v.lsa.valid_until())?;
        Ok(())
    }

    fn rank(&self, ids: &[u8]) -> Option<PathRank> {
        if !(2..=MAX_ROUTE_CORES).contains(&ids.len())
            || ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id))
        {
            return None;
        }
        let mut loss = 0;
        let mut rtt = 0;
        for pair in ids.windows(2) {
            let (edge_rtt, edge_loss) = self.edge(pair[0], pair[1])?;
            rtt += edge_rtt;
            loss += edge_loss;
        }
        let mut tie = [0; MAX_ROUTE_CORES];
        tie[..ids.len()].copy_from_slice(ids);
        Some((loss, rtt, ids.len(), tie))
    }
}

/// One preprovisioned listener for an exact route. The locator is not trusted
/// for identity. Routes must use distinct first hops so a failed first-hop
/// connection cannot fill the budget with routes that use the same link.
pub struct RouteLocator<'a> {
    pub path: &'a [u8],
    pub target: &'a ClientTarget,
}

const MAX_ROUTE_ATTEMPTS: usize = 3;

impl VerifiedGraph<'_> {
    /// Open a dedicated E2E circuit across the best eligible signed path.
    /// On typed path loss only, close it before opening a fresh circuit on
    /// the next path. No stream/fragment/offset or application data is queued
    /// or replayed by this API. `exchange` is called once per *confirmed*
    /// circuit and must make an explicit choice about application replay (e.g.
    /// run an idempotent query or submit the next independent FIFO item).
    /// The network budget is three sequential attempts, five seconds each;
    /// trusted callback computation itself is not interruptible.
    pub fn connect<T>(
        &self,
        probe: &mut MeshProbe<'_>,
        locators: &[RouteLocator<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
        mut exchange: impl FnMut(&[u8], &mut E2eCircuit<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        self.connect_io(probe, locators, outer, (admission, None), |path, c, _| {
            exchange(path, c)
        })
        .map_err(|e| match e {
            Error::ConfirmedPathLost(cause) => Error::Transport(cause),
            other => other,
        })
    }

    pub(crate) fn connect_io<T>(
        &self,
        probe: &mut MeshProbe<'_>,
        locators: &[RouteLocator<'_>],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        budget: (&Admission, Option<u8>),
        exchange: impl FnMut(&[u8], &mut E2eCircuit<'_>, EndpointIo<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        let (admission, preferred) = budget;
        self.owner(probe)?;
        probe.poll_identity_mailbox()?;
        probe.check_local_identity_denial()?;
        if locators.is_empty() || locators.len() > MAX_ROUTE_ATTEMPTS {
            return Err(Error::NoRoute);
        }
        let mut ranked = Vec::with_capacity(locators.len());
        let mut first_hops = Vec::with_capacity(locators.len());
        let source = locators[0].path.first();
        let destination = locators[0].path.last();
        for locator in locators {
            let path = locator.path;
            if !(3..=MAX_ROUTE_CORES).contains(&path.len())
                || path.first() != source
                || path.last() != destination
                || path[0] >= path[path.len() - 1]
                || first_hops.contains(&path[1])
                || path
                    .iter()
                    .enumerate()
                    .any(|(i, id)| path[..i].contains(id))
            {
                return Err(Error::NoRoute);
            }
            first_hops.push(path[1]);
            let mut denied = false;
            for &id in path {
                match self.vertex(id).and_then(|v| self.check_vertex(probe, v)) {
                    Ok(()) => (),
                    Err(Error::IdentityRevoked) => denied = true,
                    Err(e) => return Err(e),
                }
            }
            if denied {
                continue;
            }
            if self.vertex(path[0])?.core.identity.peer_identity() != self.local {
                return Err(Error::Identity);
            }
            // An authentic, current advertisement can withdraw an edge.
            // Unknown, stale or conflicted inputs above are not withdrawals.
            if let Some(score) = self.rank(path) {
                ranked.push((score, locator));
            }
        }
        ranked
            .sort_unstable_by_key(|(score, locator)| (preferred != Some(locator.path[1]), *score));
        self.try_routes(
            probe,
            ranked
                .into_iter()
                .map(|(_, locator)| (locator.path, locator.target)),
            outer,
            admission,
            false,
            exchange,
        )
    }

    fn try_routes<'a, T>(
        &self,
        probe: &mut MeshProbe<'_>,
        locators: impl IntoIterator<Item = (&'a [u8], &'a ClientTarget)>,
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
        routed: bool,
        mut exchange: impl FnMut(&[u8], &mut E2eCircuit<'_>, EndpointIo<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        let mut loss = Error::NoRoute;
        for (path, target) in locators {
            // Recheck all route facts after the previous circuit was dropped.
            let route = self.authorize_graph_path(probe, path, Instant::now() + ATTEMPT_LIMIT)?;
            let next = self.vertex(path[1])?;
            let deadline = route.deadline(probe, &[])?;
            let mut hop = match probe.dial_classified(
                &[Candidate {
                    target,
                    signed_identity: next.identity,
                }],
                outer,
                admission,
                Some((deadline, next.lsa.object_id())),
            ) {
                Err(error @ Error::PathUnavailable(_)) => {
                    probe.poll_identity_mailbox()?;
                    for &id in path {
                        self.check_vertex(probe, self.vertex(id)?)?;
                    }
                    loss = error;
                    continue;
                }
                other => other?,
            };
            if routed {
                send_path(probe, &route, &mut hop, path)?;
            }
            let mut reported_loss = false;
            let result = with_fixed_endpoint_io(probe, &route, hop, |c, io| {
                let result = exchange(path, c, io);
                reported_loss = result.as_ref().is_err_and(established_loss);
                result
            });
            match result {
                // In particular do not retry EOF during nested TLS / path
                // confirmation: a downstream auth failure can look like EOF.
                // Also never invoke the callback again after it succeeded.
                Err(Error::Transport(e)) if reported_loss && established_loss(&e) => {
                    // A time/status cutoff must never be treated as permission
                    // to route past an expired, revoked or equivocated path.
                    for &id in path {
                        self.check_vertex(probe, self.vertex(id)?)?;
                    }
                    loss = Error::ConfirmedPathLost(e);
                }
                other => return other,
            }
        }
        Err(loss)
    }

    /// Run one dedicated relay listener after its caller accepts TCP. No
    /// endpoint key exchange or application callback runs on this branch.
    pub fn relay(
        &self,
        probe: &mut MeshProbe<'_>,
        path: &[u8],
        incoming: TcpStream,
        outgoing: &ClientTarget,
        outer: (
            &OpenSslOuterTlsAcceptor,
            &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        ),
        admission: &Admission,
    ) -> Result<Forwarded, Error> {
        let route = self.authorize_path(probe, path)?;
        let pos = route.position;
        if pos == 0 || pos + 1 >= path.len() {
            return Err(Error::NoRoute);
        }
        let deadline = route.deadline(probe, &[])?;
        let previous = self.vertex(path[pos - 1])?;
        let next = self.vertex(path[pos + 1])?;
        let left = probe.accept_until(
            incoming,
            previous.identity,
            outer.0,
            admission,
            Some((deadline, previous.lsa.object_id())),
        )?;
        let deadline = route.deadline(probe, &[&left])?;
        let right = probe.dial_classified(
            &[Candidate {
                target: outgoing,
                signed_identity: next.identity,
            }],
            outer.1,
            admission,
            Some((deadline, next.lsa.object_id())),
        )?;
        forward_fixed(probe, &route, left, right, admission)
    }

    /// Run one dedicated destination listener. The opener, first adjacent
    /// peer, route and endpoint TLS identity are all independently checked.
    pub fn respond<T>(
        &self,
        probe: &mut MeshProbe<'_>,
        path: &[u8],
        incoming: TcpStream,
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
        exchange: impl FnOnce(&mut E2eCircuit<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        self.respond_io(probe, path, incoming, outer, admission, |c, _| exchange(c))
    }

    pub(crate) fn respond_io<T>(
        &self,
        probe: &mut MeshProbe<'_>,
        path: &[u8],
        incoming: TcpStream,
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
        exchange: impl FnOnce(&mut E2eCircuit<'_>, EndpointIo<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        let route = self.authorize_path(probe, path)?;
        if route.position + 1 != path.len() {
            return Err(Error::NoRoute);
        }
        let deadline = route.deadline(probe, &[])?;
        let previous = self.vertex(path[path.len() - 2])?;
        let left = probe.accept_until(
            incoming,
            previous.identity,
            outer,
            admission,
            Some((deadline, previous.lsa.object_id())),
        )?;
        with_fixed_endpoint_io(probe, &route, left, exchange)
    }
}

/// Local-only transport permission for one ordered pair. An outbound locator
/// is never sourced from a proposal or an LSA, and inbound peers are explicit.
pub struct RoutedPair<'a> {
    pub endpoints: (u8, u8),
    pub incoming: &'a [u8],
    pub outgoing: &'a BTreeMap<u8, ClientTarget>,
}

impl VerifiedGraph<'_> {
    fn pair_ids(&self, pair: &RoutedPair<'_>) -> Result<(u8, u8, u8), Error> {
        let (src, dst) = pair.endpoints;
        if src >= dst {
            return Err(Error::NoRoute);
        }
        for id in [src, dst] {
            match self.vertex(id) {
                Err(Error::IdentityRevoked) => return Err(Error::NoRoute),
                result => {
                    result?;
                }
            }
        }
        let local = self
            .vertices
            .values()
            .find(|v| v.core.identity.peer_identity() == self.local)
            .ok_or(Error::Identity)?;
        Ok((src, dst, local.core.id))
    }

    /// Enumerate only simple paths of up to four members. With 16 slots this
    /// considers at most 1 + 14 + 14*13 paths; no wire input expands the search.
    fn eligible_paths(
        &self,
        probe: &MeshProbe<'_>,
        pair: &RoutedPair<'_>,
    ) -> Result<Vec<RankedPath>, Error> {
        probe.poll_identity_mailbox()?;
        probe.check_local_identity_denial()?;
        let (src, dst, local) = self.pair_ids(pair)?;
        let mut transit = Vec::new();
        for (&id, vertex) in &self.vertices {
            // Even a graph built before the mailbox update must exclude the
            // denied generation. Other authority failures are not withdrawals.
            match probe.check_identity_denial(&vertex.core) {
                Ok(()) if id != src && id != dst => transit.push(id),
                Ok(()) => (),
                Err(Error::IdentityRevoked) if id == src || id == dst => {
                    return Err(Error::NoRoute);
                }
                Err(Error::IdentityRevoked) => (),
                Err(e) => return Err(e),
            }
        }
        let mut paths = Vec::new();
        let mut consider = |ids: &[u8]| {
            if let Some((score, _)) = self.local_path(pair, local, ids) {
                paths.push((score, ids.to_vec()));
            }
        };
        consider(&[src, dst]);
        for &a in &transit {
            consider(&[src, a, dst]);
            for &b in &transit {
                if a != b {
                    consider(&[src, a, b, dst]);
                }
            }
        }
        paths.sort_unstable_by_key(|(score, _)| *score);
        Ok(paths)
    }

    fn local_path(
        &self,
        pair: &RoutedPair<'_>,
        local: u8,
        path: &[u8],
    ) -> Option<(PathRank, usize)> {
        let pos = path.iter().position(|&id| id == local)?;
        if path.first() != Some(&pair.endpoints.0)
            || path.last() != Some(&pair.endpoints.1)
            || (pos > 0 && !pair.incoming.contains(&path[pos - 1]))
            || path
                .get(pos + 1)
                .is_some_and(|id| !pair.outgoing.contains_key(id))
        {
            return None;
        }
        Some((self.rank(path)?, pos))
    }

    /// Gate local TUN/listener startup on a currently authorized signed path
    /// with provisioned adjacent transport at this process.
    pub fn authorize_routed_pair(
        &self,
        probe: &mut MeshProbe<'_>,
        pair: &RoutedPair<'_>,
    ) -> Result<(), Error> {
        self.owner(probe)?;
        let paths = self.eligible_paths(probe, pair)?;
        let (_, path) = paths.first().ok_or(Error::NoRoute)?;
        self.authorize_graph_path(probe, path, Instant::now() + ATTEMPT_LIMIT)?;
        Ok(())
    }

    pub(crate) fn connect_routed_io<T>(
        &self,
        probe: &mut MeshProbe<'_>,
        pair: &RoutedPair<'_>,
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        budget: (&Admission, Option<u8>),
        exchange: impl FnMut(&[u8], &mut E2eCircuit<'_>, EndpointIo<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        self.owner(probe)?;
        probe.check_local_identity_denial()?;
        let (src, _, local) = self.pair_ids(pair)?;
        if src != local {
            return Err(Error::Identity);
        }
        let (admission, preferred) = budget;
        let mut paths = self.eligible_paths(probe, pair)?;
        paths.sort_unstable_by_key(|(score, path)| (preferred != Some(path[1]), *score));
        let mut seen = BTreeSet::new();
        let ranked = paths
            .iter()
            .filter(|(_, path)| seen.insert(path[1]))
            .take(MAX_ROUTE_ATTEMPTS)
            .map(|(_, path)| (path.as_slice(), &pair.outgoing[&path[1]]));
        self.try_routes(probe, ranked, outer, admission, true, exchange)
    }

    fn receive_path(
        &self,
        probe: &mut MeshProbe<'_>,
        pair: &RoutedPair<'_>,
        incoming: TcpStream,
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
    ) -> Result<(Vec<u8>, FixedRoute, Adjacency), Error> {
        let until = Instant::now() + ATTEMPT_LIMIT;
        self.owner(probe)?;
        let (src, dst, local) = self.pair_ids(pair)?;
        if src == local {
            return Err(Error::NoRoute);
        }
        // Only predecessors on locally feasible signed paths may authenticate.
        let mut allowed = BTreeSet::new();
        for (_, path) in self.eligible_paths(probe, pair)? {
            let pos = path
                .iter()
                .position(|id| *id == local)
                .ok_or(Error::Identity)?;
            allowed.insert(path[pos - 1]);
        }
        let mut neighbors = Vec::with_capacity(allowed.len());
        for id in allowed {
            let v = self.vertex(id)?;
            self.check_vertex(probe, v)?;
            neighbors.push((v.core.clone(), v.lsa.object_id()));
        }
        let mut left =
            probe.accept_routed_neighbor(incoming, &neighbors, outer, admission, until)?;
        let read_deadline = probe.route_deadline(&[], &[&left])?.min(until);
        let path = probe.with_live_identity(
            std::slice::from_ref(&left.peer),
            left.remote_lsa_expiry,
            &[&left.socket],
            || {
                bounded_link_operation(&left.socket, read_deadline, || {
                    let frame = left.session.recv_frame()?;
                    if frame.header.kind != Kind::Control {
                        return Err(crate::CircuitReject::UnexpectedFrame.into());
                    }
                    Ok(decode_mesh_path(&frame.body)?.to_vec())
                })
                .map_err(Error::from)
            },
        )?;
        let (_, pos) = self.local_path(pair, local, &path).ok_or(Error::NoRoute)?;
        if pos == 0 || (local == dst) != (pos + 1 == path.len()) || left.peer.id != path[pos - 1] {
            return Err(Error::Identity);
        }
        let route = self.authorize_graph_path(probe, &path, until)?;
        route.deadline(probe, &[&left])?;
        Ok((path, route, left))
    }

    /// Receive a path proposal after adjacent mTLS; verify pair, predecessor,
    /// every signed edge and the local next-hop locator before dialing it.
    pub fn relay_routed(
        &self,
        probe: &mut MeshProbe<'_>,
        pair: &RoutedPair<'_>,
        incoming: TcpStream,
        outer: (
            &OpenSslOuterTlsAcceptor,
            &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        ),
        admission: &Admission,
    ) -> Result<Forwarded, Error> {
        let (path, route, left) = self.receive_path(probe, pair, incoming, outer.0, admission)?;
        let next_id = *path.get(route.position + 1).ok_or(Error::NoRoute)?;
        let next = self.vertex(next_id)?;
        let target = pair.outgoing.get(&next_id).ok_or(Error::NoRoute)?;
        let deadline = route.deadline(probe, &[&left])?;
        let mut right = probe.dial_classified(
            &[Candidate {
                target,
                signed_identity: next.identity,
            }],
            outer.1,
            admission,
            Some((deadline, next.lsa.object_id())),
        )?;
        send_path(probe, &route, &mut right, &path)?;
        forward_fixed(probe, &route, left, right, admission)
    }

    pub(crate) fn respond_routed_io<T>(
        &self,
        probe: &mut MeshProbe<'_>,
        pair: &RoutedPair<'_>,
        incoming: TcpStream,
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
        exchange: impl FnOnce(&[u8], &mut E2eCircuit<'_>, EndpointIo<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        let (path, route, left) = self.receive_path(probe, pair, incoming, outer, admission)?;
        if route.position + 1 != path.len() {
            return Err(Error::NoRoute);
        }
        with_fixed_endpoint_io(probe, &route, left, |c, io| exchange(&path, c, io))
    }
}

fn send_path(
    probe: &mut MeshProbe<'_>,
    route: &FixedRoute,
    link: &mut Adjacency,
    path: &[u8],
) -> Result<(), Error> {
    let body = encode_mesh_path(path).map_err(TunnelError::from)?;
    let deadline = route.deadline(probe, &[link])?;
    probe.with_live_identity(
        &route.members,
        route.expiry(link.remote_lsa_expiry),
        &[&link.socket],
        || {
            bounded_link_operation(&link.socket, deadline, || {
                link.session.send_control(ControlType::MeshPath, &body)
            })
            .map_err(Error::from)
        },
    )
}

fn established_loss(error: &TunnelError) -> bool {
    // Ambiguous timeouts/reset alerts/protocol failures are terminal; only
    // known transport truncation, socket reset or failed writes get replaced.
    use ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
    matches!(
        error,
        TunnelError::Closed
            | TunnelError::Ws(WsError::Closed)
            | TunnelError::Io(BrokenPipe | ConnectionAborted | ConnectionReset)
            | TunnelError::Ws(WsError::Io(
                BrokenPipe | ConnectionAborted | ConnectionReset
            ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CircuitReject, SessionReject};

    #[test]
    fn only_typed_established_path_loss_is_retryable() {
        for error in [
            TunnelError::Timeout,
            TunnelError::Io(ErrorKind::Other),
            TunnelError::Ws(WsError::BadStatus),
            TunnelError::InnerTls("e2e handshake"),
            TunnelError::Session(SessionReject::PeerIdentityMismatch),
            TunnelError::Circuit(CircuitReject::ResetReceived),
            TunnelError::Circuit(CircuitReject::OffsetMismatch),
        ] {
            let wrapped = std::io::Error::new(ErrorKind::InvalidData, error);
            assert!(!established_loss(&wrapped.into()));
        }
        for error in [
            TunnelError::Closed,
            TunnelError::Ws(WsError::Closed),
            TunnelError::Io(ErrorKind::ConnectionReset),
        ] {
            let wrapped = std::io::Error::new(ErrorKind::InvalidData, error);
            assert!(established_loss(&wrapped.into()));
        }
    }
}
