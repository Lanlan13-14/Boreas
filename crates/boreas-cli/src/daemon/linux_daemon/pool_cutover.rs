//! Explicit operator approval for a stopped, direct two-node migration.

use super::{AuthenticatedPeer, CfgRole, Config, Mode, auth_slot};
use boreas_pki::{
    VerifiedNetworkPolicy,
    management::VerifiedObject,
    network_policy_store::{CutoverAction, PoolCutoverAnchors},
    provisioning::VerifiedPoolMigrationBundle,
};
use boreas_proto::objects::ObjectBody;
use std::{os::unix::ffi::OsStrExt, path::Path};

pub(super) struct Plan {
    source_policy: (u64, [u8; 32]),
    target_policy: [u8; 32],
    source_identities: [[u8; 32]; 2],
    pub(super) minimum_status: u64,
    pub(super) original_status_state: [u8; 32],
    pub(super) root: [u8; 32],
    pub(super) action: CutoverAction,
}

impl Plan {
    pub(super) fn parse(text: &str, action: CutoverAction) -> Result<Self, String> {
        let invalid = || "daemon: --pool-cutover expects SOURCE_SEQ:SOURCE_POLICY_SHA256:TARGET_POLICY_SHA256:CORE_SOURCE_SHA256:EDGE_SOURCE_SHA256:MIN_STATUS_SEQ:ROOT_FINGERPRINT:LOCAL_STATUS_STATE_SHA256".to_string();
        let fields: Vec<_> = text.split(':').take(9).collect();
        let [seq, source, target, core, edge, status, root, original_status_state] = fields.as_slice() else {
            return Err(invalid());
        };
        let number = |s: &str| {
            if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
                return Err(invalid());
            }
            s.parse::<u64>().ok().filter(|n| *n != 0).ok_or_else(invalid)
        };
        let digest = |s: &str| {
            if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            let mut out = [0; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| invalid())?;
            }
            Ok(out)
        };
        Ok(Self {
            source_policy: (number(seq)?, digest(source)?),
            target_policy: digest(target)?,
            source_identities: [digest(core)?, digest(edge)?],
            minimum_status: number(status)?,
            root: digest(root)?,
            original_status_state: digest(original_status_state)?,
            action,
        })
    }

    pub(super) fn bind_material(
        &self,
        material: &VerifiedPoolMigrationBundle,
        policy: &VerifiedNetworkPolicy,
        config: &Config,
        mode: Mode,
    ) -> Result<BoundPlan, String> {
        if config.paths.roots.len() != 1 || config.uplinks.backup.is_some()
            || config.uplinks.paths != 1 || config.uplinks.probe_paths != 0 || config.dns.is_some()
            || config.limits != crate::config::LimitsConfig::default()
        {
            return Err("daemon: pool cutover requires one root bundle, one direct path, and no DNS, standby or routing options".into());
        }
        let local = &material.bundle.local;
        let peer = material.bundle.peer.as_ref().ok_or("daemon: migration peer missing")?;
        let (source, target) = if mode == Mode::Serve {
            ([&material.local_source, &material.peer_source], [local, peer])
        } else {
            ([&material.peer_source, &material.local_source], [peer, local])
        };
        let (ObjectBody::NodeIdentity(core), ObjectBody::NodeIdentity(edge)) =
            (&target[0].object().body, &target[1].object().body)
        else {
            return Err("daemon: migration endpoints are not signed node identities".into());
        };
        use boreas_proto::objects::NodeRole;
        let local_body = if mode == Mode::Serve { core } else { edge };
        if core.role != NodeRole::Core
            || edge.role != NodeRole::Edge
            || !matches!((config.identity.role, local_body.role),
                (CfgRole::Core, NodeRole::Core) | (CfgRole::Edge, NodeRole::Edge))
            || local_body.node_id != config.identity.node_id
            || local_body.identity_generation != config.identity.identity_generation
            || config.network.overlay_prefix.base() != policy.overlay_base()
            || policy.policy_digest() != self.target_policy
            || source.map(VerifiedObject::object_id) != self.source_identities
        {
            return Err("daemon: migration material does not match the approved pair and policy".into());
        }
        let source_slot = |object: &VerifiedObject| {
            let ObjectBody::NodeIdentity(body) = &object.object().body else {
                return Err("daemon: migration source is not a node identity".into());
            };
            auth_slot(body.net_id, body.node_id, body.identity_generation)
        };
        Ok(BoundPlan {
            sources: [source_slot(source[0])?, source_slot(source[1])?],
            target_ids: target.map(VerifiedObject::object_id),
        })
    }

    pub(super) fn anchors(
        &self,
        bound: &BoundPlan,
        canonical_status: &Path,
        status_sequence: u64,
    ) -> PoolCutoverAnchors {
        PoolCutoverAnchors {
            source_policy: self.source_policy,
            target_policy: self.target_policy,
            source_identities: self.source_identities,
            target_identities: bound.target_ids,
            status_path_hash: openssl::sha::sha256(canonical_status.as_os_str().as_bytes()),
            status_sequence,
            approval_digest: self.status_marker(bound, canonical_status),
        }
    }

    /// Same on both nodes; local status images deliberately differ.
    pub(super) fn ceremony_digest(&self, bound: &BoundPlan) -> [u8; 32] {
        let mut h = openssl::sha::Sha256::new();
        h.update(b"Boreas direct IPv4 cutover approval v1\0");
        h.update(&self.root);
        h.update(&self.source_policy.0.to_be_bytes());
        h.update(&self.source_policy.1);
        h.update(&self.target_policy);
        for id in self.source_identities.into_iter().chain(bound.target_ids) {
            h.update(&id);
        }
        h.update(&self.minimum_status.to_be_bytes());
        h.finish()
    }

    pub(super) fn status_marker(&self, bound: &BoundPlan, canonical_status: &Path) -> [u8; 32] {
        let mut h = openssl::sha::Sha256::new();
        h.update(b"Boreas local status continuity v1\0");
        h.update(&self.ceremony_digest(bound));
        h.update(&self.original_status_state);
        h.update(canonical_status.as_os_str().as_bytes());
        h.finish()
    }
}

pub(super) struct BoundPlan {
    pub(super) sources: [AuthenticatedPeer; 2],
    target_ids: [[u8; 32]; 2],
}
