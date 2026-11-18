//! Pure failover decision machine for master-plan §8.5.
//!
//! This module does not open a socket, send a probe, read a clock, or sleep.
//! Callers pass monotonic milliseconds. Nothing here passes `G-FAILOVER`:
//! [`estimate_switch_floor`] is an arithmetic lower bound for a real test,
//! not a measured P99 and not a proof that a failover finished within 10s.
//!
//! Decision order used by [`select_path`]:
//! 1. Prefer a healthy `SameCoreDir`, then a healthy `SameCoreCdn`.
//! 2. Newly select `BackupCdn` only if both primary paths are [`Health::Down`].
//!    [`Health::Suspect`] alone is not proof that a primary path has failed.
//!    An already-selected backup is retained until a fail-back is eligible.
//! 3. A down current path switches to an eligible healthy path immediately;
//!    recovery hysteresis must not impose a 120s outage on hard failover.
//! 4. A suspect current path may switch after the configured degrade hold.
//! 5. A healthy current path fails back to a better healthy path only after
//!    that target has met the configured recover hold. Otherwise keep it.
//! 6. If no eligible healthy path exists and the current path is down, return
//!    [`Selection::StayDown`].
//!
//! The caller classifies health, supplies trustworthy monotonic timestamps and
//! one outcome per probe interval, and enforces authentication, authorization,
//! directory freshness and resource admission separately. A selection is not
//! permission to skip those checks or a measurement of completed recovery.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

/// Initial probe interval from §8.5, in caller-supplied milliseconds; not a floor.
pub const PROBE_INTERVAL: u64 = 2_000;
/// Initial number of consecutive failed probe intervals; not a floor.
pub const FAIL_THRESHOLD: u32 = 3;
/// Plan ceiling for configured backoff. Not a connection-time guarantee.
pub const BACKOFF_MAX: u64 = 1_000;
/// Initial quality-degradation hysteresis. Configurable, not a minimum.
pub const DEGRADE_HOLD: u64 = 30_000;
/// Initial stable-recovery hysteresis for fail-back. Configurable, not a minimum.
pub const RECOVER_HOLD: u64 = 120_000;

/// Preference among paths. [`Selection::StayDown`] is the absence of a path, not an entry.
pub const PATH_PREFERENCE: [PathId; 3] =
    [PathId::SameCoreDir, PathId::SameCoreCdn, PathId::BackupCdn];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailoverError {
    /// A probe interval or failed-interval threshold was zero.
    InvalidProbePolicy,
    /// The explicit components overflowed `u64`.
    BudgetOverflow,
    /// `attachment` does not own `current`.
    AttachmentMismatch,
    /// A circuit cap was outside `1..=4`.
    CircuitCapOutOfRange,
    /// Backup accepted more circuits than primary.
    BackupCapExceedsPrimary,
    /// One of the §3.1 attachment limits was zero.
    InvalidAttachmentLimits,
}

/// Tunable detection and hysteresis with the initial values from §8.5.
///
/// Probe intervals and failure thresholds must be nonzero. Holds may be shorter
/// or longer than the initial 30s/120s, including zero to disable hysteresis.
/// Tuning needs deployment measurements; no setting proves the P99 target or
/// changes authentication, cryptographic policy, or resource budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    probe_interval_ms: u64,
    fail_threshold: u32,
    degrade_hold_ms: u64,
    recover_hold_ms: u64,
}

impl Policy {
    /// The plan's initial settings, not a measured performance guarantee.
    pub const fn plan() -> Self {
        Self {
            probe_interval_ms: PROBE_INTERVAL,
            fail_threshold: FAIL_THRESHOLD,
            degrade_hold_ms: DEGRADE_HOLD,
            recover_hold_ms: RECOVER_HOLD,
        }
    }

    pub const fn try_new(
        probe_interval_ms: u64,
        fail_threshold: u32,
        degrade_hold_ms: u64,
        recover_hold_ms: u64,
    ) -> Result<Self, FailoverError> {
        if probe_interval_ms == 0 || fail_threshold == 0 {
            return Err(FailoverError::InvalidProbePolicy);
        }
        Ok(Self {
            probe_interval_ms,
            fail_threshold,
            degrade_hold_ms,
            recover_hold_ms,
        })
    }

    pub const fn probe_interval_ms(self) -> u64 {
        self.probe_interval_ms
    }
    pub const fn fail_threshold(self) -> u32 {
        self.fail_threshold
    }
    pub const fn degrade_hold_ms(self) -> u64 {
        self.degrade_hold_ms
    }
    pub const fn recover_hold_ms(self) -> u64 {
        self.recover_hold_ms
    }
}

/// Result of one caller-reported probe interval.
///
/// [`ProbeVerdict::ProbeMiss`] is a missed or unmatched probe interval.
/// [`ProbeVerdict::PathLoss`] is a different fact. No function in this module
/// returns `PathLoss`, and none turns misses into a loss percentage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeVerdict {
    /// Matching reply with `sent_at <= now <= sent_at + probe_interval`. Clears the streak.
    Success,
    /// This interval had no matching timely reply. Not a public loss sample.
    ProbeMiss,
    /// Matching reply outside the interval, including backwards time. Does not clear the streak.
    Late,
    /// `fail_threshold` consecutive failed intervals. Not a loss percentage.
    Suspect,
    /// Real path loss would be a separate measurement. Probe misses are not this.
    PathLoss,
}

/// Consecutive failed probe intervals. One outcome per interval, from the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeWatch {
    policy: Policy,
    consecutive_failures: u32,
}

impl ProbeWatch {
    pub const fn new(policy: Policy) -> Self {
        Self {
            policy,
            consecutive_failures: 0,
        }
    }

    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Match one reply against the challenge that was sent for that interval.
    ///
    /// The caller must generate a fresh unpredictable challenge and associate
    /// each reply with its outstanding interval; this helper does neither.
    /// A mismatched challenge is [`ProbeVerdict::ProbeMiss`]. It does not clear
    /// the streak. A match outside `sent_at <= now <= sent_at + probe_interval`
    /// is [`ProbeVerdict::Late`] and does not clear the streak (including an
    /// invalid backwards timestamp). A timely match clears it. The interval
    /// that reaches `fail_threshold` returns [`ProbeVerdict::Suspect`] instead
    /// of `ProbeMiss` or `Late`. Repeated calls are not deduplicated.
    pub fn observe_reply(
        &mut self,
        sent_challenge: [u8; 16],
        reply_challenge: [u8; 16],
        sent_at_ms: u64,
        now_ms: u64,
    ) -> ProbeVerdict {
        if sent_challenge != reply_challenge {
            return self.fail_interval(ProbeVerdict::ProbeMiss);
        }
        if reply_is_timely(sent_at_ms, now_ms, self.policy.probe_interval_ms()) {
            self.consecutive_failures = 0;
            return ProbeVerdict::Success;
        }
        self.fail_interval(ProbeVerdict::Late)
    }

    /// One probe interval closed with no matching timely reply.
    ///
    /// This is not a public packet-loss sample and it is not [`ProbeVerdict::PathLoss`].
    pub fn observe_missed_interval(&mut self) -> ProbeVerdict {
        self.fail_interval(ProbeVerdict::ProbeMiss)
    }

    fn fail_interval(&mut self, below_threshold: ProbeVerdict) -> ProbeVerdict {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.policy.fail_threshold() {
            ProbeVerdict::Suspect
        } else {
            below_threshold
        }
    }
}

fn reply_is_timely(sent_at_ms: u64, now_ms: u64, probe_interval_ms: u64) -> bool {
    if now_ms < sent_at_ms {
        return false;
    }
    match sent_at_ms.checked_add(probe_interval_ms) {
        Some(deadline) => now_ms <= deadline,
        None => true,
    }
}

/// Which core the current path is attached to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreAttachment {
    Primary,
    Backup,
}

/// Health of one path, as already classified by the caller.
///
/// Probe suspicion does not automatically become a hard failure here; the
/// caller must apply its failure policy before reporting `Down`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Healthy,
    /// Quality degradation or probe suspicion, not a declared path failure.
    Suspect,
    /// Declared failed/unusable, not merely a quality-degradation timer.
    Down,
}

/// A path the selector can be on. Backup is not an attachment-neutral alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathId {
    SameCoreDir,
    SameCoreCdn,
    BackupCdn,
}

/// Caller-supplied health. `since_ms` is when this health began, monotonic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathStatus {
    pub health: Health,
    pub since_ms: u64,
}

/// The three paths §8.5 selects among.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathSet {
    pub same_core_dir: PathStatus,
    pub same_core_cdn: PathStatus,
    pub backup_cdn: PathStatus,
}

impl PathSet {
    fn get(self, path: PathId) -> PathStatus {
        match path {
            PathId::SameCoreDir => self.same_core_dir,
            PathId::SameCoreCdn => self.same_core_cdn,
            PathId::BackupCdn => self.backup_cdn,
        }
    }
}

/// Output of [`select_path`]. `StayDown` means no path is eligible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    SameCoreDir,
    SameCoreCdn,
    BackupCdn,
    StayDown,
}

impl Selection {
    fn path(path: PathId) -> Self {
        match path {
            PathId::SameCoreDir => Self::SameCoreDir,
            PathId::SameCoreCdn => Self::SameCoreCdn,
            PathId::BackupCdn => Self::BackupCdn,
        }
    }
}

/// Select a path. See the module docs for the order.
///
/// `now_ms` is the caller's monotonic clock. This function does not read `Instant`.
pub fn select_path(
    policy: &Policy,
    attachment: CoreAttachment,
    current: PathId,
    paths: PathSet,
    now_ms: u64,
) -> Result<Selection, FailoverError> {
    if !attachment_matches(attachment, current) {
        return Err(FailoverError::AttachmentMismatch);
    }
    for target in PATH_PREFERENCE {
        if target == PathId::BackupCdn && !primary_failed(paths) {
            continue;
        }
        let status = paths.get(target);
        if status.health != Health::Healthy || status.since_ms > now_ms {
            continue;
        }
        if target == current || may_switch(policy, current, target, paths, now_ms) {
            return Ok(Selection::path(target));
        }
    }
    if paths.get(current).health == Health::Down {
        Ok(Selection::StayDown)
    } else {
        Ok(Selection::path(current))
    }
}

fn attachment_matches(attachment: CoreAttachment, current: PathId) -> bool {
    matches!(
        (attachment, current),
        (
            CoreAttachment::Primary,
            PathId::SameCoreDir | PathId::SameCoreCdn
        ) | (CoreAttachment::Backup, PathId::BackupCdn)
    )
}

fn primary_failed(paths: PathSet) -> bool {
    paths.same_core_dir.health == Health::Down && paths.same_core_cdn.health == Health::Down
}

fn may_switch(
    policy: &Policy,
    current: PathId,
    target: PathId,
    paths: PathSet,
    now_ms: u64,
) -> bool {
    match paths.get(current).health {
        Health::Down => true,
        Health::Suspect => held_for(paths.get(current), now_ms, policy.degrade_hold_ms()),
        Health::Healthy => {
            rank(target) < rank(current)
                && held_for(paths.get(target), now_ms, policy.recover_hold_ms())
        }
    }
}

fn rank(path: PathId) -> u8 {
    match path {
        PathId::SameCoreDir => 0,
        PathId::SameCoreCdn => 1,
        PathId::BackupCdn => 2,
    }
}

fn held_for(status: PathStatus, now_ms: u64, hold_ms: u64) -> bool {
    now_ms
        .checked_sub(status.since_ms)
        .is_some_and(|elapsed| elapsed >= hold_ms)
}

/// Partial lower-bound estimate `detect + backoff + rtt * rounds`.
///
/// All representable sums are returned, whether below, at, or above 10s. The
/// 10s value is a measured P99 *target*, not a minimum or an arithmetic pass
/// condition. A smaller lower bound does not prove the target is achievable.
/// Configured backoff must separately respect [`BACKOFF_MAX`]. This arithmetic
/// does not enforce that configuration: a supplied delay above the ceiling is
/// counted in full, never clamped away to conceal a budget overrun.
///
/// The explicit components omit scheduling drift, authorization/freshness
/// checks, route/circuit reconstruction, and the first successful round trip
/// unless the caller included them in its inputs. `handshake_round_trips` must
/// account for the required TCP/TLS/WSS/innerTLS setup, not a fixed loopback
/// 2ms handshake or 100ms cross-continent LSA. Neither this partial sum nor
/// `Ok` measures recovery or decides `G-FAILOVER`; real tests must time each
/// stage under the plan's RTT/loss/failure injections.
pub fn estimate_switch_floor(
    detect_ms: u64,
    backoff_ms: u64,
    rtt_ms: u64,
    handshake_round_trips: u32,
) -> Result<u64, FailoverError> {
    let trips = u64::from(handshake_round_trips);
    let rtt_total = rtt_ms
        .checked_mul(trips)
        .ok_or(FailoverError::BudgetOverflow)?;
    let sum = detect_ms
        .checked_add(backoff_ms)
        .and_then(|partial| partial.checked_add(rtt_total))
        .ok_or(FailoverError::BudgetOverflow)?;
    Ok(sum)
}

/// Accepted circuits on primary and backup.
///
/// §8.5 lets backup accept fewer circuits. It does not let backup pick a weaker
/// suite. This struct is not generic, has no suite or crypto-policy field, and
/// [`CircuitCaps::new`] takes no such argument. These per-path limits are not
/// aggregate admission control: the caller must still account for backup
/// expansion, transient connections, memory and handshake budgets (§8.1–8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitCaps {
    primary_circuit_cap: u8,
    backup_circuit_cap: u8,
}

impl CircuitCaps {
    pub const fn new(
        primary_circuit_cap: u8,
        backup_circuit_cap: u8,
    ) -> Result<Self, FailoverError> {
        if !in_cap_range(primary_circuit_cap) || !in_cap_range(backup_circuit_cap) {
            return Err(FailoverError::CircuitCapOutOfRange);
        }
        if backup_circuit_cap > primary_circuit_cap {
            return Err(FailoverError::BackupCapExceedsPrimary);
        }
        Ok(Self {
            primary_circuit_cap,
            backup_circuit_cap,
        })
    }

    pub const fn primary_circuit_cap(self) -> u8 {
        self.primary_circuit_cap
    }
    pub const fn backup_circuit_cap(self) -> u8 {
        self.backup_circuit_cap
    }
}

const fn in_cap_range(cap: u8) -> bool {
    cap >= 1 && cap <= 4
}

// --- §3.1 bounded attachment admission ---------------------------------------
//
// §3.1 requires every Core to cap three separate Edge loads: active Primary
// attachments (`P_max`), hot-standby Backup attachments (`B_max`) and the
// transient increment admitted while a failover is converging. Those caps are
// hard acceptance limits, not targets: a Core that has reached one refuses the
// next Edge instead of queueing it, so a failover storm cannot pile up
// unbounded state. This model only counts; it does not authenticate the Edge,
// check its lease, or decide a path.

/// §3.1 per-Core attachment limits. All three must be non-zero: a zero cap is a
/// configuration error, not "unlimited".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentLimits {
    max_primary: u32,
    max_backup: u32,
    max_transient: u32,
}

impl AttachmentLimits {
    pub const fn try_new(
        max_primary: u32,
        max_backup: u32,
        max_transient: u32,
    ) -> Result<Self, FailoverError> {
        if max_primary == 0 || max_backup == 0 || max_transient == 0 {
            return Err(FailoverError::InvalidAttachmentLimits);
        }
        Ok(Self {
            max_primary,
            max_backup,
            max_transient,
        })
    }

    pub const fn max_primary(self) -> u32 {
        self.max_primary
    }
    pub const fn max_backup(self) -> u32 {
        self.max_backup
    }
    pub const fn max_transient(self) -> u32 {
        self.max_transient
    }
}

/// Why an attachment was refused. None of these is a reason to skip a lease
/// check, a source-address check or any cryptographic policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentReject {
    /// `NodeID` 0 is not an encodable subject (§3.2).
    InvalidNode,
    /// This Edge already holds a slot on this Core.
    Duplicate,
    PrimaryFull,
    BackupFull,
    TransientFull,
}

/// Which slot [`AttachmentAdmission::release`] freed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Released {
    Primary,
    Backup,
    Transient,
}

/// Bounded per-Core attachment accounting for the three §3.1 loads.
#[derive(Clone, Debug)]
pub struct AttachmentAdmission {
    limits: AttachmentLimits,
    primary: u32,
    backup: u32,
    transient: u32,
    stable: BTreeMap<u16, CoreAttachment>,
    transient_peers: BTreeMap<u16, ()>,
}

impl AttachmentAdmission {
    pub fn new(limits: AttachmentLimits) -> Self {
        Self {
            limits,
            primary: 0,
            backup: 0,
            transient: 0,
            stable: BTreeMap::new(),
            transient_peers: BTreeMap::new(),
        }
    }

    pub fn limits(&self) -> AttachmentLimits {
        self.limits
    }

    pub fn primary(&self) -> u32 {
        self.primary
    }

    pub fn backup_count(&self) -> u32 {
        self.backup
    }

    pub fn transient(&self) -> u32 {
        self.transient
    }

    /// Accepted attachments of all three kinds, bounded by the limits.
    pub fn total(&self) -> u32 {
        self.primary
            .saturating_add(self.backup)
            .saturating_add(self.transient)
    }

    /// The stable (Primary/Backup) attachment of one Edge, if any.
    pub fn attachment(&self, node_id: u16) -> Option<CoreAttachment> {
        self.stable.get(&node_id).copied()
    }

    /// Whether the Edge currently occupies a transient failover slot.
    pub fn is_transient(&self, node_id: u16) -> bool {
        self.transient_peers.contains_key(&node_id)
    }

    pub fn admit_primary(&mut self, node_id: u16) -> Result<(), AttachmentReject> {
        self.admit_stable(node_id, CoreAttachment::Primary)
    }

    /// A Backup attachment is a stable slot: §3.3 forbids signing an active
    /// `AttachmentLease` for a standby connection, but the acceptance slot is
    /// still bounded by `B_max`.
    pub fn admit_backup(&mut self, node_id: u16) -> Result<(), AttachmentReject> {
        self.admit_stable(node_id, CoreAttachment::Backup)
    }

    fn admit_stable(&mut self, node_id: u16, unit: CoreAttachment) -> Result<(), AttachmentReject> {
        if node_id == 0 {
            return Err(AttachmentReject::InvalidNode);
        }
        if self.transient_peers.contains_key(&node_id) {
            return Err(AttachmentReject::Duplicate);
        }
        match self.stable.entry(node_id) {
            Entry::Occupied(_) => Err(AttachmentReject::Duplicate),
            Entry::Vacant(slot) => match unit {
                CoreAttachment::Primary => {
                    if self.primary >= self.limits.max_primary {
                        return Err(AttachmentReject::PrimaryFull);
                    }
                    self.primary += 1;
                    slot.insert(CoreAttachment::Primary);
                    Ok(())
                }
                CoreAttachment::Backup => {
                    if self.backup >= self.limits.max_backup {
                        return Err(AttachmentReject::BackupFull);
                    }
                    self.backup += 1;
                    slot.insert(CoreAttachment::Backup);
                    Ok(())
                }
            },
        }
    }

    /// Admit one Edge beyond the steady caps while a failover converges. Bounded
    /// by the transient increment alone, and refused for an Edge that already
    /// holds a slot.
    pub fn admit_transient(&mut self, node_id: u16) -> Result<(), AttachmentReject> {
        if node_id == 0 {
            return Err(AttachmentReject::InvalidNode);
        }
        if self.stable.contains_key(&node_id) {
            return Err(AttachmentReject::Duplicate);
        }
        match self.transient_peers.entry(node_id) {
            Entry::Occupied(_) => Err(AttachmentReject::Duplicate),
            Entry::Vacant(slot) => {
                if self.transient >= self.limits.max_transient {
                    return Err(AttachmentReject::TransientFull);
                }
                self.transient += 1;
                slot.insert(());
                Ok(())
            }
        }
    }

    /// Release whatever slot the Edge holds, reporting which kind it was.
    pub fn release(&mut self, node_id: u16) -> Option<Released> {
        if let Some(unit) = self.stable.remove(&node_id) {
            match unit {
                CoreAttachment::Primary => {
                    self.primary = self.primary.saturating_sub(1);
                    return Some(Released::Primary);
                }
                CoreAttachment::Backup => {
                    self.backup = self.backup.saturating_sub(1);
                    return Some(Released::Backup);
                }
            }
        }
        if self.transient_peers.remove(&node_id).is_some() {
            self.transient = self.transient.saturating_sub(1);
            return Some(Released::Transient);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn status(health: Health, since_ms: u64) -> PathStatus {
        PathStatus { health, since_ms }
    }

    fn held(now_ms: u64) -> PathStatus {
        status(Health::Healthy, now_ms - RECOVER_HOLD)
    }

    fn down() -> PathStatus {
        status(Health::Down, 0)
    }

    fn paths(dir: PathStatus, cdn: PathStatus, backup: PathStatus) -> PathSet {
        PathSet {
            same_core_dir: dir,
            same_core_cdn: cdn,
            backup_cdn: backup,
        }
    }

    fn choose(current: PathId, set: PathSet, now_ms: u64) -> Selection {
        let attachment = match current {
            PathId::BackupCdn => CoreAttachment::Backup,
            PathId::SameCoreDir | PathId::SameCoreCdn => CoreAttachment::Primary,
        };
        select_path(&Policy::plan(), attachment, current, set, now_ms).unwrap()
    }

    #[test]
    fn policy_initial_values_are_defaults_not_floors() {
        let initial = Policy::plan();
        assert_eq!(initial.probe_interval_ms(), 2_000);
        assert_eq!(initial.fail_threshold(), 3);
        assert_eq!(initial.degrade_hold_ms(), 30_000);
        assert_eq!(initial.recover_hold_ms(), 120_000);

        let shorter = Policy::try_new(1_000, 2, 5_000, 10_000).unwrap();
        assert_eq!(shorter.probe_interval_ms(), 1_000);
        assert_eq!(shorter.fail_threshold(), 2);
        assert_eq!(shorter.degrade_hold_ms(), 5_000);
        assert_eq!(shorter.recover_hold_ms(), 10_000);
        assert!(Policy::try_new(1, 1, 0, 0).is_ok());
        assert!(Policy::try_new(u64::MAX, u32::MAX, u64::MAX, u64::MAX).is_ok());
        assert_eq!(
            Policy::try_new(0, FAIL_THRESHOLD, DEGRADE_HOLD, RECOVER_HOLD),
            Err(FailoverError::InvalidProbePolicy)
        );
        assert_eq!(
            Policy::try_new(PROBE_INTERVAL, 0, DEGRADE_HOLD, RECOVER_HOLD),
            Err(FailoverError::InvalidProbePolicy)
        );

        let raised = Policy::try_new(5_000, 4, 31_000, 121_000).unwrap();
        let sent = [9u8; 16];
        let mut watch = ProbeWatch::new(raised);
        assert_eq!(
            watch.observe_reply(sent, sent, 0, 5_000),
            ProbeVerdict::Success
        );
        let mut initial_watch = ProbeWatch::new(initial);
        assert_eq!(
            initial_watch.observe_reply(sent, sent, 0, 5_000),
            ProbeVerdict::Late
        );
    }

    #[test]
    fn wrong_challenge_does_not_clear_failures_and_three_misses_are_suspect() {
        let sent = [0x11u8; 16];
        let wrong = [0x22u8; 16];
        let mut watch = ProbeWatch::new(Policy::plan());

        assert_eq!(watch.observe_missed_interval(), ProbeVerdict::ProbeMiss);
        assert_eq!(watch.consecutive_failures(), 1);
        assert_eq!(
            watch.observe_reply(sent, wrong, 2_000, 2_100),
            ProbeVerdict::ProbeMiss
        );
        assert_eq!(watch.consecutive_failures(), 2);
        assert_eq!(watch.observe_missed_interval(), ProbeVerdict::Suspect);
        assert_eq!(watch.consecutive_failures(), 3);
        assert_ne!(ProbeVerdict::ProbeMiss, ProbeVerdict::PathLoss);

        let mut clean = ProbeWatch::new(Policy::plan());
        assert_eq!(
            clean.observe_reply(sent, wrong, 0, 100),
            ProbeVerdict::ProbeMiss
        );
        assert_eq!(
            clean.observe_reply(sent, wrong, 2_000, 2_100),
            ProbeVerdict::ProbeMiss
        );
        assert_eq!(
            clean.observe_reply(sent, wrong, 4_000, 4_100),
            ProbeVerdict::Suspect
        );
        assert_ne!(clean.consecutive_failures(), 0);

        assert_eq!(
            clean.observe_reply(sent, sent, 8_000, 8_100),
            ProbeVerdict::Success
        );
        assert_eq!(clean.consecutive_failures(), 0);
        assert_eq!(clean.observe_missed_interval(), ProbeVerdict::ProbeMiss);
    }

    #[test]
    fn late_match_does_not_clear_the_failure_streak() {
        let sent = [0xABu8; 16];
        let mut watch = ProbeWatch::new(Policy::plan());
        assert_eq!(
            watch.observe_reply(sent, [0xCD; 16], 0, 100),
            ProbeVerdict::ProbeMiss
        );
        assert_eq!(watch.consecutive_failures(), 1);

        let late = watch.observe_reply(sent, sent, 2_000, 2_000 + PROBE_INTERVAL + 1);
        assert_eq!(late, ProbeVerdict::Late);
        assert_eq!(watch.consecutive_failures(), 2);
        assert_ne!(late, ProbeVerdict::Success);
        assert_ne!(late, ProbeVerdict::PathLoss);

        assert_eq!(
            watch.observe_reply(sent, sent, 10_000, 10_000 + PROBE_INTERVAL),
            ProbeVerdict::Success
        );
        assert_eq!(watch.consecutive_failures(), 0);
        assert_eq!(
            watch.observe_reply(sent, sent, 20_000, 20_000 + PROBE_INTERVAL + 1),
            ProbeVerdict::Late
        );
        assert_eq!(watch.consecutive_failures(), 1);
    }

    #[test]
    fn probe_deadline_overflow_and_backwards_time_are_handled_without_wraparound() {
        let sent = [0x55; 16];
        let mut watch = ProbeWatch::new(Policy::plan());
        // The mathematical deadline exceeds u64::MAX; representable times
        // after send are still within the interval, not wrapped deadlines.
        assert_eq!(
            watch.observe_reply(sent, sent, u64::MAX - 1_000, u64::MAX),
            ProbeVerdict::Success
        );
        assert_eq!(watch.observe_reply(sent, sent, 10, 9), ProbeVerdict::Late);
        assert_eq!(watch.consecutive_failures(), 1);
        assert_eq!(
            watch.observe_reply(sent, sent, 0, PROBE_INTERVAL),
            ProbeVerdict::Success
        );
    }

    #[test]
    fn probe_failure_counter_saturates_instead_of_wrapping() {
        let mut watch = ProbeWatch {
            policy: Policy::try_new(1, u32::MAX, 0, 0).unwrap(),
            consecutive_failures: u32::MAX - 1,
        };
        assert_eq!(watch.observe_missed_interval(), ProbeVerdict::Suspect);
        assert_eq!(watch.observe_missed_interval(), ProbeVerdict::Suspect);
        assert_eq!(watch.consecutive_failures(), u32::MAX);
    }

    #[test]
    fn healthy_dir_is_preferred_over_cdn_and_cdn_over_backup() {
        assert_eq!(
            PATH_PREFERENCE,
            [PathId::SameCoreDir, PathId::SameCoreCdn, PathId::BackupCdn]
        );
        let picked = choose(
            PathId::SameCoreCdn,
            paths(held(NOW), held(NOW), held(NOW)),
            NOW,
        );
        assert_eq!(picked, Selection::SameCoreDir);

        let cdn = choose(
            PathId::SameCoreDir,
            paths(down(), held(NOW), held(NOW)),
            NOW,
        );
        assert_eq!(cdn, Selection::SameCoreCdn);
        assert_ne!(cdn, Selection::BackupCdn);
    }

    #[test]
    fn backup_is_not_chosen_while_dir_is_healthy() {
        let on_dead_cdn = choose(
            PathId::SameCoreCdn,
            paths(held(NOW), down(), held(NOW)),
            NOW,
        );
        assert_eq!(on_dead_cdn, Selection::SameCoreDir);
        assert_ne!(on_dead_cdn, Selection::BackupCdn);

        // A healthy DIR is immediately usable when the current CDN is down;
        // the recover hold protects fail-back, not hard-failure availability.
        let blocked = choose(
            PathId::SameCoreCdn,
            paths(status(Health::Healthy, NOW - 1_000), down(), held(NOW)),
            NOW,
        );
        assert_eq!(blocked, Selection::SameCoreDir);
        assert_ne!(blocked, Selection::BackupCdn);
    }

    #[test]
    fn backup_requires_both_primary_paths_down_not_merely_suspect() {
        let suspect = status(Health::Suspect, NOW - DEGRADE_HOLD);
        for set in [
            paths(suspect, down(), held(NOW)),
            paths(down(), suspect, held(NOW)),
            paths(suspect, suspect, held(NOW)),
        ] {
            assert_ne!(choose(PathId::SameCoreDir, set, NOW), Selection::BackupCdn);
        }
        let recently_healthy_backup = status(Health::Healthy, NOW);
        assert_eq!(
            choose(
                PathId::SameCoreDir,
                paths(down(), down(), recently_healthy_backup),
                NOW,
            ),
            Selection::BackupCdn
        );
        assert_eq!(
            choose(PathId::SameCoreDir, paths(down(), down(), suspect), NOW),
            Selection::StayDown
        );
    }

    #[test]
    fn suspect_for_29s_does_not_switch_and_30s_does() {
        let cdn_ready = paths(status(Health::Suspect, NOW - 29_000), held(NOW), held(NOW));
        assert_eq!(
            choose(PathId::SameCoreDir, cdn_ready, NOW),
            Selection::SameCoreDir
        );

        let just_under = paths(status(Health::Suspect, NOW - 29_999), held(NOW), down());
        assert_eq!(
            choose(PathId::SameCoreDir, just_under, NOW),
            Selection::SameCoreDir
        );

        let open = paths(
            status(Health::Suspect, NOW - DEGRADE_HOLD),
            held(NOW),
            held(NOW),
        );
        assert_eq!(
            choose(PathId::SameCoreDir, open, NOW),
            Selection::SameCoreCdn
        );

        let raised = Policy::try_new(PROBE_INTERVAL, FAIL_THRESHOLD, 31_000, RECOVER_HOLD).unwrap();
        let still_held = select_path(
            &raised,
            CoreAttachment::Primary,
            PathId::SameCoreDir,
            open,
            NOW,
        )
        .unwrap();
        assert_eq!(still_held, Selection::SameCoreDir);
    }

    #[test]
    fn healthy_current_path_fails_back_at_120s_not_119s() {
        let too_soon = paths(status(Health::Healthy, NOW - 119_000), held(NOW), down());
        assert_eq!(
            choose(PathId::SameCoreCdn, too_soon, NOW),
            Selection::SameCoreCdn
        );
        assert_ne!(
            choose(PathId::SameCoreCdn, too_soon, NOW),
            Selection::SameCoreDir
        );

        let boundary = paths(status(Health::Healthy, NOW - 119_999), held(NOW), down());
        assert_eq!(
            choose(PathId::SameCoreCdn, boundary, NOW),
            Selection::SameCoreCdn
        );

        let ready = paths(
            status(Health::Healthy, NOW - RECOVER_HOLD),
            held(NOW),
            down(),
        );
        assert_eq!(
            choose(PathId::SameCoreCdn, ready, NOW),
            Selection::SameCoreDir
        );

        // Fail-back off a healthy backup waits for the same hold, then prefers DIR.
        let early = paths(status(Health::Healthy, NOW - 119_000), down(), held(NOW));
        assert_eq!(choose(PathId::BackupCdn, early, NOW), Selection::BackupCdn);
        let failback = paths(
            status(Health::Healthy, NOW - RECOVER_HOLD),
            down(),
            held(NOW),
        );
        assert_eq!(
            choose(PathId::BackupCdn, failback, NOW),
            Selection::SameCoreDir
        );
    }

    #[test]
    fn hard_failure_uses_healthy_same_core_path_without_recovery_hold() {
        let just_healthy = status(Health::Healthy, NOW);
        assert_eq!(
            choose(
                PathId::SameCoreDir,
                paths(down(), just_healthy, held(NOW)),
                NOW,
            ),
            Selection::SameCoreCdn
        );
        assert_eq!(
            choose(
                PathId::SameCoreCdn,
                paths(just_healthy, down(), held(NOW)),
                NOW,
            ),
            Selection::SameCoreDir
        );
        assert_eq!(
            choose(PathId::BackupCdn, paths(down(), just_healthy, down()), NOW),
            Selection::SameCoreCdn
        );
    }

    #[test]
    fn failback_considers_the_next_stable_primary_path() {
        // DIR is preferred but has not stabilized; that must not hide a
        // stable same-core CDN when moving back from a healthy backup.
        assert_eq!(
            choose(
                PathId::BackupCdn,
                paths(status(Health::Healthy, NOW), held(NOW), held(NOW)),
                NOW,
            ),
            Selection::SameCoreCdn
        );
        assert_eq!(
            choose(
                PathId::SameCoreDir,
                paths(held(NOW), held(NOW), held(NOW)),
                NOW,
            ),
            Selection::SameCoreDir
        );
    }

    #[test]
    fn shorter_holds_apply_at_the_configured_boundaries() {
        let policy = Policy::try_new(PROBE_INTERVAL, FAIL_THRESHOLD, 5_000, 10_000).unwrap();
        for (elapsed, expected) in [
            (4_999, Selection::SameCoreDir),
            (5_000, Selection::SameCoreCdn),
        ] {
            assert_eq!(
                select_path(
                    &policy,
                    CoreAttachment::Primary,
                    PathId::SameCoreDir,
                    paths(status(Health::Suspect, NOW - elapsed), held(NOW), down()),
                    NOW,
                ),
                Ok(expected)
            );
        }
        for (elapsed, expected) in [
            (9_999, Selection::SameCoreCdn),
            (10_000, Selection::SameCoreDir),
        ] {
            assert_eq!(
                select_path(
                    &policy,
                    CoreAttachment::Primary,
                    PathId::SameCoreCdn,
                    paths(status(Health::Healthy, NOW - elapsed), held(NOW), down()),
                    NOW,
                ),
                Ok(expected)
            );
        }
    }

    #[test]
    fn hold_checks_reject_future_timestamps_even_with_zero_hysteresis() {
        let policy = Policy::try_new(PROBE_INTERVAL, FAIL_THRESHOLD, 0, 0).unwrap();
        let future = status(Health::Healthy, NOW + 1);
        assert_eq!(
            select_path(
                &policy,
                CoreAttachment::Primary,
                PathId::SameCoreCdn,
                paths(future, down(), down()),
                NOW,
            ),
            Ok(Selection::StayDown)
        );
        assert_eq!(
            select_path(
                &policy,
                CoreAttachment::Primary,
                PathId::SameCoreDir,
                paths(status(Health::Suspect, NOW + 1), held(NOW), down()),
                NOW,
            ),
            Ok(Selection::SameCoreDir)
        );
        assert!(!held_for(status(Health::Healthy, 1), 0, 0));
        assert!(!held_for(status(Health::Healthy, 1), u64::MAX, u64::MAX));
        assert!(held_for(status(Health::Healthy, 0), u64::MAX, u64::MAX));
        assert!(held_for(status(Health::Healthy, NOW), NOW, 0));
        for (current, set) in [
            (
                PathId::SameCoreCdn,
                paths(status(Health::Healthy, NOW), held(NOW), down()),
            ),
            (
                PathId::SameCoreCdn,
                paths(
                    status(Health::Healthy, NOW),
                    status(Health::Suspect, NOW),
                    down(),
                ),
            ),
        ] {
            assert_eq!(
                select_path(&policy, CoreAttachment::Primary, current, set, NOW),
                Ok(Selection::SameCoreDir)
            );
        }
    }

    #[test]
    fn estimate_returns_partial_arithmetic_on_both_sides_of_the_p99_target() {
        // None of these Ok values is a measured P99 or a gate pass.
        for (rtt, sum) in [(50, 7_200), (200, 7_800), (400, 8_600)] {
            assert_eq!(estimate_switch_floor(6_000, 1_000, rtt, 4), Ok(sum));
        }
        assert_eq!(estimate_switch_floor(8_999, BACKOFF_MAX, 0, 0), Ok(9_999));
        assert_eq!(estimate_switch_floor(9_000, BACKOFF_MAX, 0, 0), Ok(10_000));
        assert_eq!(estimate_switch_floor(9_001, BACKOFF_MAX, 0, 0), Ok(10_001));
        assert_eq!(estimate_switch_floor(0, 0, 0, 0), Ok(0));
        // Zero rounds must not overflow even with a large RTT input.
        assert_eq!(estimate_switch_floor(0, 0, u64::MAX, 0), Ok(0));
        // An over-ceiling delay is counted honestly, not hidden by a clamp.
        // Returning its sum does not approve the backoff configuration.
        assert_eq!(estimate_switch_floor(8_000, 5_000, 0, 0), Ok(13_000));
        assert_eq!(estimate_switch_floor(0, u64::MAX, 0, 0), Ok(u64::MAX));
    }

    #[test]
    fn estimate_checks_multiplication_and_each_addition_without_saturating() {
        assert_eq!(
            estimate_switch_floor(0, 0, u64::MAX, 2),
            Err(FailoverError::BudgetOverflow)
        );
        assert_eq!(
            estimate_switch_floor(u64::MAX, 1, 0, 0),
            Err(FailoverError::BudgetOverflow)
        );
        assert_eq!(
            estimate_switch_floor(u64::MAX - 1, 1, 1, 1),
            Err(FailoverError::BudgetOverflow)
        );
        assert_eq!(estimate_switch_floor(u64::MAX, 0, 0, 0), Ok(u64::MAX));
        assert_eq!(estimate_switch_floor(u64::MAX - 1, 0, 1, 1), Ok(u64::MAX));
        assert_eq!(estimate_switch_floor(0, 0, u64::MAX, 1), Ok(u64::MAX));
    }

    #[test]
    fn backup_circuit_cap_can_shrink_and_cannot_name_a_suite() {
        let caps = CircuitCaps::new(4, 1).unwrap();
        assert_eq!(caps.primary_circuit_cap(), 4);
        assert_eq!(caps.backup_circuit_cap(), 1);
        assert!(caps.backup_circuit_cap() <= caps.primary_circuit_cap());
        assert_eq!(CircuitCaps::new(4, 4).unwrap().backup_circuit_cap(), 4);
        assert_eq!(CircuitCaps::new(1, 1).unwrap().primary_circuit_cap(), 1);
        assert_eq!(
            CircuitCaps::new(2, 3),
            Err(FailoverError::BackupCapExceedsPrimary)
        );
        assert_eq!(
            CircuitCaps::new(0, 1),
            Err(FailoverError::CircuitCapOutOfRange)
        );
        assert_eq!(
            CircuitCaps::new(5, 1),
            Err(FailoverError::CircuitCapOutOfRange)
        );
        assert_eq!(
            CircuitCaps::new(1, 0),
            Err(FailoverError::CircuitCapOutOfRange)
        );
    }

    #[test]
    fn attachment_must_own_the_current_path() {
        let set = paths(down(), down(), down());
        assert_eq!(
            select_path(
                &Policy::plan(),
                CoreAttachment::Primary,
                PathId::BackupCdn,
                set,
                NOW
            ),
            Err(FailoverError::AttachmentMismatch)
        );
        assert_eq!(
            select_path(
                &Policy::plan(),
                CoreAttachment::Backup,
                PathId::SameCoreDir,
                set,
                NOW
            ),
            Err(FailoverError::AttachmentMismatch)
        );
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    fn limits(primary: u32, backup: u32, transient: u32) -> AttachmentLimits {
        AttachmentLimits::try_new(primary, backup, transient).expect("non-zero limits")
    }

    #[test]
    fn zero_limits_are_a_configuration_error() {
        assert_eq!(
            AttachmentLimits::try_new(0, 1, 1),
            Err(FailoverError::InvalidAttachmentLimits)
        );
        assert_eq!(
            AttachmentLimits::try_new(1, 0, 1),
            Err(FailoverError::InvalidAttachmentLimits)
        );
        assert_eq!(
            AttachmentLimits::try_new(1, 1, 0),
            Err(FailoverError::InvalidAttachmentLimits)
        );
    }

    #[test]
    fn primary_and_backup_caps_are_hard() {
        let mut admission = AttachmentAdmission::new(limits(1, 1, 1));
        assert_eq!(admission.admit_primary(0x0102), Ok(()));
        assert_eq!(admission.attachment(0x0102), Some(CoreAttachment::Primary));
        // A second Primary Edge is refused, not queued.
        assert_eq!(
            admission.admit_primary(0x0103),
            Err(AttachmentReject::PrimaryFull)
        );
        // The same Edge cannot hold two slots on one Core.
        assert_eq!(
            admission.admit_backup(0x0102),
            Err(AttachmentReject::Duplicate)
        );
        assert_eq!(admission.admit_backup(0x0203), Ok(()));
        assert_eq!(
            admission.admit_backup(0x0204),
            Err(AttachmentReject::BackupFull)
        );
        assert_eq!(admission.primary(), 1);
        assert_eq!(admission.backup_count(), 1);
        assert_eq!(admission.total(), 2);
        assert_eq!(
            admission.admit_primary(0),
            Err(AttachmentReject::InvalidNode)
        );
    }

    #[test]
    fn failover_transient_increment_is_separately_bounded() {
        let mut admission = AttachmentAdmission::new(limits(1, 1, 2));
        assert_eq!(admission.admit_primary(0x0102), Ok(()));
        // A converging failover admits Edges beyond the steady caps.
        assert_eq!(admission.admit_transient(0x0103), Ok(()));
        assert_eq!(admission.admit_transient(0x0104), Ok(()));
        assert!(admission.is_transient(0x0103));
        // The transient budget is its own hard cap.
        assert_eq!(
            admission.admit_transient(0x0105),
            Err(AttachmentReject::TransientFull)
        );
        // A transient Edge is not a stable attachment and cannot double-book.
        assert_eq!(admission.attachment(0x0103), None);
        assert_eq!(
            admission.admit_primary(0x0103),
            Err(AttachmentReject::Duplicate)
        );
        assert_eq!(admission.total(), 3);
        assert_eq!(admission.release(0x0103), Some(Released::Transient));
        assert_eq!(admission.transient(), 1);
        assert_eq!(admission.admit_transient(0x0105), Ok(()));
    }

    #[test]
    fn release_frees_exactly_one_slot() {
        let mut admission = AttachmentAdmission::new(limits(2, 2, 1));
        admission.admit_primary(0x0102).expect("primary");
        admission.admit_backup(0x0203).expect("backup");
        admission.admit_transient(0x0304).expect("transient");
        assert_eq!(admission.total(), 3);
        assert_eq!(admission.release(0x0203), Some(Released::Backup));
        assert_eq!(admission.backup_count(), 1);
        assert_eq!(admission.attachment(0x0203), None);
        assert_eq!(admission.release(0x0203), None);
        assert_eq!(admission.release(0x0102), Some(Released::Primary));
        assert_eq!(admission.primary(), 0);
        assert_eq!(admission.release(0x0304), Some(Released::Transient));
        assert_eq!(admission.total(), 0);
        // The freed slots are usable again.
        assert_eq!(admission.admit_primary(0x0105), Ok(()));
        assert_eq!(admission.admit_primary(0x0106), Ok(()));
        assert_eq!(
            admission.admit_primary(0x0107),
            Err(AttachmentReject::PrimaryFull)
        );
    }
}
