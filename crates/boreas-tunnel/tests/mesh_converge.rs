//! Three-Core directory convergence, prefix arbitration, and path failover.
//!
//! These tests call only the public surface of `boreas_tunnel::directory`,
//! `boreas_tunnel::failover`, and the crate-level route arbiter. They do not
//! open sockets and they do not claim `G-CONVERGE`, `G-PREFIX`, or `G-FAILOVER`.
//!
//! # What the public API cannot express
//!
//! There is no `DirectoryView`, no `apply_lsa`, and no route selector that
//! reads a converged directory and returns a next hop. `CoreLsa` payloads are
//! opaque to `DirectoryConvergence` (it stores caller-supplied bytes and never
//! parses neighbors). `RouteGrant` is explicitly not a §3.3 directory object,
//! so overlapping prefixes are arbitrated through [`boreas_tunnel::arbitrate_routes`]
//! on caller-verified [`boreas_tunnel::RouteCandidate`] values. That function
//! suppresses an overlapping prefix by first-eligible order (metric, then
//! issuer, subject, object id). It does **not** implement longest-prefix-match,
//! and it does not record a conflict log beyond the per-object disposition
//! [`RouteDisposition::SuppressedBy`].

use std::net::IpAddr;

use boreas_tunnel::directory::{
    ApplyOutcome, DirectoryConvergence, DirectoryKey, DirectoryObjectKind, KeyStatus,
    RecordEnvelope,
};
use boreas_tunnel::failover::{
    AttachmentAdmission, AttachmentLimits, CoreAttachment, Health, PathId, PathSet, PathStatus,
    Policy, ProbeVerdict, ProbeWatch, Selection, select_path,
};
use boreas_tunnel::{Prefix, RouteCandidate, RouteDecision, RouteDisposition, arbitrate_routes};

const CORE_A: u8 = 1;
const CORE_B: u8 = 2;
const CORE_C: u8 = 3;
const CORE_GEN: u64 = 1;

/// NodeID layout used by the directory: high byte is `home_core_id - 1`.
fn node_id(home_core: u8, octet: u8) -> u16 {
    ((u16::from(home_core) - 1) << 8) | u16::from(octet)
}

fn hash(seed: u8) -> [u8; 32] {
    let mut out = [seed; 32];
    out[0] = seed;
    out[31] = seed.wrapping_mul(3);
    out
}

fn payload(seed: u8) -> Vec<u8> {
    vec![b'L', seed, seed]
}

/// One Core's own LSA, writer-scoped to that Core by [`RecordEnvelope::core_lsa`].
fn lsa(core: u8, seq: u64, seed: u8) -> RecordEnvelope {
    RecordEnvelope::core_lsa(core, CORE_GEN, seq, hash(seed), payload(seed), false)
}

fn lsa_key(core: u8) -> DirectoryKey {
    DirectoryKey {
        kind: DirectoryObjectKind::CoreLsa,
        subject: u16::from(core),
    }
}

fn prefix(cidr: &str) -> Prefix {
    let (address, length) = cidr.split_once('/').expect("cidr");
    Prefix::new(address.parse::<IpAddr>().unwrap(), length.parse().unwrap()).unwrap()
}

fn candidate(
    issuer: &str,
    subject: u16,
    cidr: &str,
    seq: u64,
    metric: u32,
    object_id: [u8; 32],
) -> RouteCandidate {
    RouteCandidate {
        issuer_id: issuer.to_owned(),
        subject_id: subject,
        prefix: prefix(cidr),
        seq,
        metric,
        object_id,
        ha_group: None,
        healthy_lease: true,
        valid: true,
    }
}

fn disposition(decisions: &[RouteDecision], id: [u8; 32]) -> RouteDisposition {
    decisions
        .iter()
        .find(|decision| decision.object_id == id)
        .expect("decision present")
        .disposition
}

/// Three independent views ingest only the LSA each Core is allowed to sign,
/// then anti-entropy copies the active records. The converged snapshot on
/// every view contains Core A, B, and C, and the edge attached to C is
/// addressed through C (home of that edge), never through a foreign LSA subject.
#[test]
fn three_cores_converge_on_each_others_signed_lsas() {
    let mut core_a = DirectoryConvergence::new();
    let mut core_b = DirectoryConvergence::new();
    let mut core_c = DirectoryConvergence::new();

    assert_eq!(core_a.apply(lsa(CORE_A, 1, 1)), Ok(ApplyOutcome::Applied));
    assert_eq!(core_b.apply(lsa(CORE_B, 1, 2)), Ok(ApplyOutcome::Applied));
    assert_eq!(core_c.apply(lsa(CORE_C, 1, 3)), Ok(ApplyOutcome::Applied));

    // A Core cannot publish another Core's LSA: the writer proof is bound to
    // the subject inside `RecordEnvelope::core_lsa`.
    let foreign = RecordEnvelope {
        writer: boreas_tunnel::directory::WriterProof::CoreOperationalKey { core_id: CORE_A },
        ..lsa(CORE_B, 2, 9)
    };
    assert!(core_a.apply(foreign).is_err());

    // Anti-entropy: each view applies the other two Cores' already-accepted LSAs.
    for (view, others) in [
        (&mut core_a, [lsa(CORE_B, 1, 2), lsa(CORE_C, 1, 3)]),
        (&mut core_b, [lsa(CORE_A, 1, 1), lsa(CORE_C, 1, 3)]),
        (&mut core_c, [lsa(CORE_A, 1, 1), lsa(CORE_B, 1, 2)]),
    ] {
        for record in others {
            assert_eq!(view.apply(record), Ok(ApplyOutcome::Applied));
        }
    }

    let edge_on_c = node_id(CORE_C, 7);
    assert_eq!(
        boreas_tunnel::directory::home_core_id_for_node(edge_on_c),
        Some(CORE_C)
    );
    let lease =
        RecordEnvelope::attachment_lease(edge_on_c, 1, 1, CORE_C, hash(7), payload(7), false);
    assert_eq!(core_a.apply(lease.clone()), Ok(ApplyOutcome::Applied));
    assert_eq!(core_b.apply(lease.clone()), Ok(ApplyOutcome::Applied));
    assert_eq!(core_c.apply(lease), Ok(ApplyOutcome::Applied));

    let mut lsa_digests = Vec::new();
    for view in [&core_a, &core_b, &core_c] {
        let snapshot = view.snapshot();
        let lsa_subjects: Vec<u16> = snapshot
            .active
            .iter()
            .filter(|record| record.kind == DirectoryObjectKind::CoreLsa)
            .map(|record| record.subject)
            .collect();
        assert_eq!(
            lsa_subjects,
            vec![u16::from(CORE_A), u16::from(CORE_B), u16::from(CORE_C)]
        );
        assert_eq!(snapshot.poisoned, Vec::new());
        assert_eq!(view.status(lsa_key(CORE_C)), KeyStatus::Active);
        let attached = view
            .get(DirectoryKey {
                kind: DirectoryObjectKind::AttachmentLease,
                subject: edge_on_c,
            })
            .expect("edge lease");
        assert_eq!(attached.target_core_id, Some(CORE_C));
        // Home of the edge is C, and C's own LSA is the active record for that
        // subject. There is no next-hop function; this is the public fact.
        assert_eq!(
            boreas_tunnel::directory::home_core_id_for_node(attached.subject),
            attached.target_core_id
        );
        assert_eq!(
            view.get(lsa_key(CORE_C)).map(|record| record.subject),
            Some(u16::from(CORE_C))
        );
        lsa_digests.push(lsa_only_digest(view));
    }
    assert_eq!(lsa_digests[0], lsa_digests[1]);
    assert_eq!(lsa_digests[1], lsa_digests[2]);
}

/// Fingerprint of active Core LSAs only. The full snapshot digest also covers
/// the attachment lease, whose envelope bytes can differ after canonicalization
/// when the same TBS is applied in a different order.
fn lsa_only_digest(view: &DirectoryConvergence) -> Vec<([u8; 32], u64)> {
    let mut rows = Vec::new();
    for core in [CORE_A, CORE_B, CORE_C] {
        let record = view.get(lsa_key(core)).expect("active lsa");
        let seq = match record.version {
            boreas_tunnel::directory::VersionKey::CoreLsa { seq, .. } => seq,
            _ => panic!("core lsa version"),
        };
        rows.push((record.content_hash, seq));
    }
    rows
}

/// Retiring Core B's LSA (tombstone is the public withdrawal) removes it from
/// the active set. A later route choice must not treat B as a usable next hop:
/// the active LSA subjects are only A and C, and B's key is tombstoned.
#[test]
fn expired_core_b_lsa_is_withdrawn_before_the_next_choice() {
    let mut view = DirectoryConvergence::new();
    assert_eq!(view.apply(lsa(CORE_A, 1, 1)), Ok(ApplyOutcome::Applied));
    assert_eq!(view.apply(lsa(CORE_B, 1, 2)), Ok(ApplyOutcome::Applied));
    assert_eq!(view.apply(lsa(CORE_C, 1, 3)), Ok(ApplyOutcome::Applied));

    let withdrawn = RecordEnvelope::core_lsa(CORE_B, CORE_GEN, 2, hash(20), payload(20), true);
    assert_eq!(view.apply(withdrawn), Ok(ApplyOutcome::Applied));
    assert_eq!(view.status(lsa_key(CORE_B)), KeyStatus::Tombstoned);
    assert!(view.get(lsa_key(CORE_B)).is_none());
    assert!(view.get_including_tombstone(lsa_key(CORE_B)).is_some());

    let active_cores: Vec<u16> = view
        .snapshot()
        .active
        .iter()
        .filter(|record| record.kind == DirectoryObjectKind::CoreLsa)
        .map(|record| record.subject)
        .collect();
    assert_eq!(active_cores, vec![u16::from(CORE_A), u16::from(CORE_C)]);
    assert!(!active_cores.contains(&u16::from(CORE_B)));

    // The public arbiter has no "unreachable next hop" input. The closest
    // expression is a route whose lease is no longer healthy: it is not accepted.
    let via_b = candidate(
        "core-b",
        node_id(CORE_B, 1),
        "192.168.20.0/24",
        1,
        10,
        hash(21),
    );
    let via_c = candidate(
        "core-c",
        node_id(CORE_C, 1),
        "192.168.20.0/24",
        1,
        20,
        hash(22),
    );
    let mut unreachable = via_b.clone();
    unreachable.healthy_lease = false;
    let decisions = arbitrate_routes(&[unreachable, via_c.clone()]).unwrap();
    assert!(
        decisions
            .iter()
            .all(|decision| decision.object_id != hash(21))
    );
    assert_eq!(
        disposition(&decisions, hash(22)),
        RouteDisposition::Accepted
    );
}

/// Overlapping grants are not silently overwritten: the loser is returned as
/// `SuppressedBy(winner)`. Same-length prefixes prefer the lower metric.
/// A longer prefix that still overlaps is suppressed too — longest-prefix-match
/// is not implemented by `arbitrate_routes`.
#[test]
fn overlapping_grants_are_deterministic_and_explicitly_suppressed() {
    let broad = candidate("route-authority", 1, "192.168.0.0/16", 3, 50, hash(30));
    let specific_costly = candidate("route-authority", 2, "192.168.10.0/24", 3, 40, hash(31));
    let specific_cheap = candidate("route-authority", 3, "192.168.10.0/24", 3, 10, hash(32));

    let forward = arbitrate_routes(&[
        broad.clone(),
        specific_costly.clone(),
        specific_cheap.clone(),
    ])
    .unwrap();
    let reversed = arbitrate_routes(&[
        specific_cheap.clone(),
        specific_costly.clone(),
        broad.clone(),
    ])
    .unwrap();
    assert_eq!(forward, reversed);

    // Eligible order is metric, so 10 wins, 40 is suppressed by it, and the
    // overlapping /16 (metric 50) is suppressed by the already-accepted /24.
    assert_eq!(disposition(&forward, hash(32)), RouteDisposition::Accepted);
    assert_eq!(
        disposition(&forward, hash(31)),
        RouteDisposition::SuppressedBy(hash(32))
    );
    assert_eq!(
        disposition(&forward, hash(30)),
        RouteDisposition::SuppressedBy(hash(32))
    );

    // Same length, lower metric wins even when the higher metric is seen first.
    let low = candidate("route-authority", 4, "10.8.0.0/16", 1, 5, hash(33));
    let high = candidate("route-authority", 5, "10.8.0.0/16", 1, 9, hash(34));
    let same_length = arbitrate_routes(&[high.clone(), low.clone()]).unwrap();
    assert_eq!(
        disposition(&same_length, hash(33)),
        RouteDisposition::Accepted
    );
    assert_eq!(
        disposition(&same_length, hash(34)),
        RouteDisposition::SuppressedBy(hash(33))
    );
}

/// `fail_threshold` missed probe intervals move the watch to `Suspect`.
/// `select_path` leaves the primary only once the caller has classified both
/// primary paths `Down` (suspicion alone is not a hard failure). A recovered
/// primary is not selected back until `recover_hold` has elapsed.
#[test]
fn probe_losses_switch_once_and_recovery_does_not_flap() {
    let policy = Policy::plan();
    let threshold = policy.fail_threshold();
    assert_eq!(threshold, 3);

    let mut watch = ProbeWatch::new(policy);
    let mut switches = 0u32;
    // A mismatched reply counts as its own failed interval, so it is asserted
    // separately rather than inside the miss loop, where it would consume one of
    // the `fail_threshold` intervals and trip `Suspect` a step early.
    assert_eq!(
        watch.observe_reply([1; 16], [2; 16], 0, 0),
        ProbeVerdict::ProbeMiss
    );
    assert_eq!(watch.consecutive_failures(), 1);
    watch.observe_reply([3; 16], [3; 16], 0, 1);
    assert_eq!(watch.consecutive_failures(), 0);

    for step in 1..threshold {
        assert_eq!(watch.observe_missed_interval(), ProbeVerdict::ProbeMiss);
        assert_eq!(watch.consecutive_failures(), step);
    }
    assert_eq!(watch.observe_missed_interval(), ProbeVerdict::Suspect);
    assert_eq!(watch.consecutive_failures(), threshold);

    let primary = PathStatus {
        health: Health::Down,
        since_ms: 0,
    };
    let backup = PathStatus {
        health: Health::Healthy,
        since_ms: 0,
    };
    let failed = PathSet {
        same_core_dir: primary,
        same_core_cdn: primary,
        backup_cdn: backup,
    };
    let switched = select_path(
        &policy,
        CoreAttachment::Primary,
        PathId::SameCoreDir,
        failed,
        1,
    )
    .unwrap();
    assert_eq!(switched, Selection::BackupCdn);
    switches += 1;

    // One extra miss does not produce a second selection change.
    assert_eq!(watch.observe_missed_interval(), ProbeVerdict::Suspect);
    let again = select_path(
        &policy,
        CoreAttachment::Backup,
        PathId::BackupCdn,
        failed,
        2,
    )
    .unwrap();
    assert_eq!(again, Selection::BackupCdn);
    assert_eq!(switches, 1);

    // Restored primary answers, but fail-back waits out the recover hold.
    assert_eq!(
        watch.observe_reply([9; 16], [9; 16], 10_000, 11_000),
        ProbeVerdict::Success
    );
    assert_eq!(watch.consecutive_failures(), 0);
    let recovered_early = PathSet {
        same_core_dir: PathStatus {
            health: Health::Healthy,
            since_ms: 10_000,
        },
        same_core_cdn: primary,
        backup_cdn: backup,
    };
    let held = select_path(
        &policy,
        CoreAttachment::Backup,
        PathId::BackupCdn,
        recovered_early,
        10_000 + policy.recover_hold_ms() - 1,
    )
    .unwrap();
    assert_eq!(held, Selection::BackupCdn);
    let failback = select_path(
        &policy,
        CoreAttachment::Backup,
        PathId::BackupCdn,
        recovered_early,
        10_000 + policy.recover_hold_ms(),
    )
    .unwrap();
    assert_eq!(failback, Selection::SameCoreDir);
    switches += 1;
    assert_eq!(switches, threshold - 1);
}

/// Attachment admission is the public per-Core bound next to path selection.
/// A full primary set refuses another edge instead of queueing it.
#[test]
fn attachment_admission_refuses_a_core_past_its_primary_cap() {
    let limits = AttachmentLimits::try_new(1, 1, 1).unwrap();
    let mut core_c = AttachmentAdmission::new(limits);
    let edge = node_id(CORE_C, 7);
    assert_eq!(core_c.admit_primary(edge), Ok(()));
    assert_eq!(core_c.attachment(edge), Some(CoreAttachment::Primary));
    assert!(core_c.admit_primary(node_id(CORE_C, 8)).is_err());
    assert_eq!(core_c.primary(), limits.max_primary());
}
