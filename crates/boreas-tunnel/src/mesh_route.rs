//! Bounded Core graph profile for dedicated E2E circuits. Trust inputs are
//! local policy, status, signed identities and signed LSAs, not a peer's path
//! assertion. The caller provisions the graph snapshot and dedicated listeners;
//! this module is not discovery, LSA flooding, or a shared listener dispatcher.

use std::{collections::BTreeMap, io::ErrorKind, net::TcpStream, time::Instant};

use boreas_pki::management::VerifiedObject;
use boreas_proto::{messages::PathRole, objects::ObjectBody};

use crate::{
    ClientTarget, OpenSslOuterTlsAcceptor, OpenSslOuterTlsConnector, TunnelError,
    e2e::E2eCircuit,
    mesh_probe::{ATTEMPT_LIMIT, Candidate, Core, Error, MeshProbe},
    mesh_relay::{EndpointIo, FixedRoute, Forwarded, forward_fixed, with_fixed_endpoint_io},
    resource::Admission,
    ws::WsError,
};

const MAX_CORES: usize = 16;
pub(crate) const MAX_ROUTE_CORES: usize = 4;

/// Non-local Core input; no locator or public key is taken from its LSA.
pub struct SignedCore<'a> {
    pub identity: &'a [u8],
    pub lsa: &'a [u8],
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
        if others.len() >= MAX_CORES {
            return Err(Error::NoRoute);
        }
        let local = self.verified_core(local_identity)?;
        if !self.is_exact_local(&local) {
            return Err(Error::Identity);
        }
        let mut vertices = BTreeMap::from([(local.id, Vertex {
            core: local,
            identity: local_identity,
            lsa: self.local_lsa().clone(),
        })]);
        for raw in others {
            let core = self.verified_core(raw.identity)?;
            // Verify before rejecting duplicate IDs so a signed fork poisons
            // the replay slot in the long-lived owner, not merely this import.
            let lsa = self.verified_lsa(&core, raw.lsa)?;
            if vertices.contains_key(&core.id) {
                return Err(Error::Lsa);
            }
            vertices.insert(core.id, Vertex {
                core,
                identity: raw.identity,
                lsa,
            });
        }
        for v in vertices.values() {
            self.route_lsa_deadline(&v.core, v.lsa.object_id(), v.lsa.valid_until())?;
        }
        Ok(VerifiedGraph {
            local: self.local(),
            vertices,
        })
    }
}

impl VerifiedGraph<'_> {
    /// Verified slots, independent of untrusted material filenames.
    pub fn core_ids(&self) -> impl Iterator<Item = u8> + '_ {
        self.vertices.keys().copied()
    }

    fn vertex(&self, id: u8) -> Result<&Vertex<'_>, Error> {
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
        self.owner(probe)?;
        if !(3..=MAX_ROUTE_CORES).contains(&ids.len())
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
            attempt_until: Some(Instant::now() + ATTEMPT_LIMIT),
        })
    }

    fn check_vertex(&self, probe: &mut MeshProbe<'_>, v: &Vertex<'_>) -> Result<(), Error> {
        probe.route_lsa_deadline(&v.core, v.lsa.object_id(), v.lsa.valid_until())?;
        Ok(())
    }

    fn rank(&self, ids: &[u8]) -> Option<(u64, u32, usize, [u8; MAX_ROUTE_CORES])> {
        if !(3..=MAX_ROUTE_CORES).contains(&ids.len())
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
        mut exchange: impl FnMut(&[u8], &mut E2eCircuit<'_>, EndpointIo<'_>) -> Result<T, TunnelError>,
    ) -> Result<T, Error> {
        let (admission, preferred) = budget;
        self.owner(probe)?;
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
            for &id in path {
                self.check_vertex(probe, self.vertex(id)?)?;
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
        let mut loss = Error::NoRoute;
        for (_, locator) in ranked {
            // Recheck all route facts after the previous circuit was dropped.
            let route = self.authorize_path(probe, locator.path)?;
            let next = self.vertex(locator.path[1])?;
            let deadline = route.deadline(probe, &[])?;
            let hop = match probe.dial_classified(
                &[Candidate {
                    target: locator.target,
                    signed_identity: next.identity,
                }],
                outer,
                admission,
                Some(deadline),
            ) {
                Err(error @ Error::PathUnavailable(_)) => {
                    for &id in locator.path {
                        self.check_vertex(probe, self.vertex(id)?)?;
                    }
                    loss = error;
                    continue;
                }
                other => other?,
            };
            let mut reported_loss = false;
            let result = with_fixed_endpoint_io(probe, &route, hop, |c, io| {
                let result = exchange(locator.path, c, io);
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
                    for &id in locator.path {
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
        let left = probe.accept_until(
            incoming,
            self.vertex(path[pos - 1])?.identity,
            outer.0,
            admission,
            Some(deadline),
        )?;
        let deadline = route.deadline(probe, &[&left])?;
        let right = probe.dial_classified(
            &[Candidate {
                target: outgoing,
                signed_identity: self.vertex(path[pos + 1])?.identity,
            }],
            outer.1,
            admission,
            Some(deadline),
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
        let left = probe.accept_until(
            incoming,
            self.vertex(path[path.len() - 2])?.identity,
            outer,
            admission,
            Some(deadline),
        )?;
        with_fixed_endpoint_io(probe, &route, left, exchange)
    }
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
