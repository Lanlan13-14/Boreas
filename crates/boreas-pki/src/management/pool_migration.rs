//! Offline staging only: no published identity, replay update, or runtime token.

use super::{Error, IdentityAuthority, ManagementTrust, VerifiedObject};
use crate::root_authorization::VerifiedIssuerAuthorization;
use crate::{Authority, NodeRole, OverlayPrefix, VerifiedNetworkPolicy};
use boreas_proto::objects::{
    Extension, NodeIdentity, NodeRole as ObjectNodeRole, OFFLINE_IPV4_POOL_MIGRATION_EXTENSION,
    ObjectBody,
};

impl IdentityAuthority {
    /// Stage a dual-signed Core/Edge identity for a different, verified IPv4
    /// pool. The source must be an active legacy identity under this same
    /// root-authorized issuer. This does not update any live policy or ledger.
    /// The caller must check source revocation and current generation before
    /// selecting a source; signature verification alone cannot establish either.
    pub fn stage_ipv4_pool_migration(
        &self,
        legacy_signed: &[u8],
        policy: &VerifiedNetworkPolicy,
        issuer: &VerifiedIssuerAuthorization,
        now_us: u64,
    ) -> Result<Vec<u8>, Error> {
        let (trust, overlay) = migration_trust(policy, issuer, now_us)?;
        let record = issuer.issuer_record();
        if self.net_id != policy.net_id() || self.issuer_record(record.scope.clone())? != record {
            return Err(Error::InvalidPoolMigration);
        }
        let source = trust.authenticate_at(legacy_signed, now_us, now_us, None)?;
        let body = migrated_identity(&source, policy, issuer, overlay)?;
        self.sign_node_identity_in_overlay(body, overlay, vec![evidence(&source, policy)])?
            .encode_for_overlay(overlay.base())
            .map_err(|_| Error::MalformedSignedObject)
    }
}

/// Verify a staged identity and its legacy source under the same root-authorized
/// issuer, checking exact signed bytes and the allowed transformation. Returns
/// inspection data only, not a runtime identity, revocation check, or watermark.
pub fn verify_ipv4_pool_migration(
    legacy_signed: &[u8],
    staged_signed: &[u8],
    policy: &VerifiedNetworkPolicy,
    issuer: &VerifiedIssuerAuthorization,
    now_us: u64,
) -> Result<NodeIdentity, Error> {
    let (_, staged) = verify_migration_objects(legacy_signed, staged_signed, policy, issuer, now_us)?;
    let ObjectBody::NodeIdentity(body) = staged.object().body.clone() else {
        return Err(Error::InvalidPoolMigration);
    };
    Ok(body)
}

pub(crate) fn verify_migration_objects(
    legacy_signed: &[u8],
    staged_signed: &[u8],
    policy: &VerifiedNetworkPolicy,
    issuer: &VerifiedIssuerAuthorization,
    now_us: u64,
) -> Result<(VerifiedObject, VerifiedObject), Error> {
    let (trust, overlay) = migration_trust(policy, issuer, now_us)?;
    let source = trust.authenticate_at(legacy_signed, now_us, now_us, None)?;
    let staged = trust.authenticate_in_overlay(staged_signed, now_us, now_us, None, overlay)?;
    let expected = migrated_identity(&source, policy, issuer, overlay)?;
    if staged.object().body != ObjectBody::NodeIdentity(expected)
        || staged.object().extensions.as_slice() != [evidence(&source, policy)]
    {
        return Err(Error::InvalidPoolMigration);
    }
    Ok((source, staged))
}

fn migration_trust(
    policy: &VerifiedNetworkPolicy,
    issuer: &VerifiedIssuerAuthorization,
    now_us: u64,
) -> Result<(ManagementTrust, OverlayPrefix), Error> {
    let overlay = OverlayPrefix::new(policy.overlay_base(), OverlayPrefix::PREFIX_LEN)
        .map_err(|_| Error::InvalidPoolMigration)?;
    let (start, end) = policy.validity();
    if overlay == OverlayPrefix::DEFAULT
        || policy.net_id() != issuer.net_id()
        || policy.root_key_fingerprint() != issuer.root_fingerprint()
        || issuer.authority() != Authority::IdentityAuthority
        || !(start..end).contains(&now_us)
    {
        return Err(Error::InvalidPoolMigration);
    }
    let mut trust = ManagementTrust::new(policy.net_id());
    trust.add_verified_issuer(issuer)?;
    Ok((trust, overlay))
}

fn migrated_identity(
    source: &VerifiedObject,
    policy: &VerifiedNetworkPolicy,
    issuer: &VerifiedIssuerAuthorization,
    overlay: OverlayPrefix,
) -> Result<NodeIdentity, Error> {
    let ObjectBody::NodeIdentity(body) = &source.object().body else {
        return Err(Error::InvalidPoolMigration);
    };
    let role = match body.role {
        ObjectNodeRole::Edge => NodeRole::Edge,
        ObjectNodeRole::Core => NodeRole::Core,
        ObjectNodeRole::EnrollmentService => return Err(Error::InvalidPoolMigration),
    };
    let (policy_start, policy_end) = policy.validity();
    // The same source+policy must never produce different TBS at the same generation
    // merely because an offline staging command was retried later.
    let issued_at = body.not_before.max(policy_start).max(issuer.validity().0);
    let expires = source.valid_until().min(policy_end);
    if body.vip6 != [0; 16] || !source.object().extensions.is_empty() || issued_at >= expires {
        return Err(Error::InvalidPoolMigration);
    }
    let mut migrated = body.clone();
    migrated.vip = overlay
        .vip(body.home_core_id, body.vip[3], role)
        .map_err(|_| Error::InvalidPoolMigration)?;
    migrated.identity_generation = body
        .identity_generation
        .checked_add(1)
        .ok_or(Error::InvalidPoolMigration)?;
    migrated.not_before = issued_at;
    migrated.expires = expires;
    Ok(migrated)
}

fn evidence(source: &VerifiedObject, policy: &VerifiedNetworkPolicy) -> Extension {
    Extension {
        id: OFFLINE_IPV4_POOL_MIGRATION_EXTENSION,
        critical: true,
        value: [policy.policy_digest(), source.object_id()].concat(),
    }
}

#[cfg(test)]
mod tests;
