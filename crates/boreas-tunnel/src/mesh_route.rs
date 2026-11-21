//! Bounded Core graph profile for dedicated E2E circuits. Trust inputs are
//! local policy, status, signed identities and signed LSAs, not a peer's path
//! assertion. The caller provisions the graph snapshot and dedicated listeners;
//! this module is not discovery, LSA flooding, or a shared listener dispatcher.

use std::collections::BTreeMap;

use boreas_pki::management::VerifiedObject;
use boreas_proto::{messages::PathRole, objects::ObjectBody};

use crate::{
    mesh_probe::{Core, Error, MeshProbe},
    mesh_relay::FixedRoute,
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
        if local.identity.peer_identity() != self.local() {
            return Err(Error::Identity);
        }
        let mut vertices = BTreeMap::from([(
            local.id,
            Vertex {
                core: local,
                identity: local_identity,
                lsa: self.local_lsa().clone(),
            },
        )]);
        for raw in others {
            let core = self.verified_core(raw.identity)?;
            // Verify before rejecting duplicate IDs so a signed fork poisons
            // the replay slot in the long-lived owner, not merely this import.
            let lsa = self.verified_lsa(&core, raw.lsa)?;
            if vertices.contains_key(&core.id) {
                return Err(Error::Lsa);
            }
            vertices.insert(core.id, Vertex { core, identity: raw.identity, lsa });
        }
        for v in vertices.values() {
            self.route_lsa_deadline(&v.core, v.lsa.object_id(), v.lsa.valid_until())?;
        }
        Ok(VerifiedGraph { local: self.local(), vertices })
    }
}

impl VerifiedGraph<'_> {
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
    pub fn authorize_path(&self, probe: &mut MeshProbe<'_>, ids: &[u8]) -> Result<FixedRoute, Error> {
        self.owner(probe)?;
        if !(3..=MAX_ROUTE_CORES).contains(&ids.len())
            || ids.windows(2).any(|pair| self.edge(pair[0], pair[1]).is_none())
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
        if members[0].identity.node_id() >= members[ids.len() - 1].identity.node_id() {
            return Err(Error::NoRoute);
        }
        let position = members
            .iter()
            .position(|m| m.identity.peer_identity() == self.local)
            .ok_or(Error::Identity)?;
        Ok(FixedRoute { members, position, advertisements })
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
