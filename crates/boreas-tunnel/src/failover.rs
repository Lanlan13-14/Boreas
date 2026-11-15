//! Pure failover decision machine for master-plan §8.5.
//!
//! This module does not open a socket, send a probe, read a clock, or sleep.
//! Callers pass monotonic milliseconds. Nothing here passes `G-FAILOVER`:
//! [`estimate_switch_floor`] is an arithmetic lower bound for a real test,
//! not a measured P99 and not a proof that a failover finished within 10s.
//!
//! Decision order used by [`select_path`]:
//! 1. `SameCoreDir` if it has been [`Health::Healthy`] for at least the recover hold.
//! 2. Else `SameCoreCdn` under that same hold.
//! 3. Else `BackupCdn` under that hold, and only when neither same-core path is
//!    [`Health::Healthy`]. [`Health::Suspect`] is not healthy and does not block backup.
//! 4. A move onto a strictly better path that already passed steps 1–2 is a
//!    restore. It happens once that path meets the recover hold, even if the
//!    current path is still healthy. That is the fail-back the 120s hold exists for.
//! 5. Any other move, including every move onto backup, waits until the current
//!    path is [`Health::Down`] or has been [`Health::Suspect`] for the degrade hold.
//!    Until then the current path is kept. Keeping an already-selected healthy
//!    backup while a same-core path is healthy but not yet adoptable is that
//!    gate, not a new choice of backup.
//! 6. If nothing is adoptable and the current path is down, the result is
//!    [`Selection::StayDown`].

/// Plan floor for the probe interval. Two seconds, in caller-supplied milliseconds.
pub const PROBE_INTERVAL: u64 = 2_000;
/// Plan floor for consecutive failed probe intervals.
pub const FAIL_THRESHOLD: u32 = 3;
/// Plan ceiling on the backoff term inside [`estimate_switch_floor`]. One second.
pub const BACKOFF_MAX: u64 = 1_000;
/// Plan floor before a non-restoring switch away from a suspect path. Thirty seconds.
pub const DEGRADE_HOLD: u64 = 30_000;
/// Plan floor before a recovered path may be used. One hundred twenty seconds.
pub const RECOVER_HOLD: u64 = 120_000;

/// A sum below this is an incomplete budget, not a passing failover.
const INCOMPLETE_BELOW_MS: u64 = 10_000;

/// Preference among paths. [`Selection::StayDown`] is the absence of a path, not an entry.
pub const PATH_PREFERENCE: [PathId; 3] =
    [PathId::SameCoreDir, PathId::SameCoreCdn, PathId::BackupCdn];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailoverError {
    /// A policy asked to go below a plan floor.
    PolicyBelowFloor,
    /// `detect + clamped backoff + rtt * rounds` is under 10s. Not a pass.
    FloorBelowTarget { sum_ms: u64 },
    /// The explicit components overflowed `u64`.
    BudgetOverflow,
    /// `attachment` does not own `current`.
    AttachmentMismatch,
    /// A circuit cap was outside `1..=4`.
    CircuitCapOutOfRange,
    /// Backup accepted more circuits than primary.
    BackupCapExceedsPrimary,
}

/// Floors from §8.5. Construction can raise them and cannot lower them.
///
/// There is no setter. A value below [`PROBE_INTERVAL`], [`FAIL_THRESHOLD`],
/// [`DEGRADE_HOLD`], or [`RECOVER_HOLD`] is [`FailoverError::PolicyBelowFloor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    probe_interval_ms: u64,
    fail_threshold: u32,
    degrade_hold_ms: u64,
    recover_hold_ms: u64,
}

impl Policy {
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
        if probe_interval_ms < PROBE_INTERVAL
            || fail_threshold < FAIL_THRESHOLD
            || degrade_hold_ms < DEGRADE_HOLD
            || recover_hold_ms < RECOVER_HOLD
        {
            return Err(FailoverError::PolicyBelowFloor);
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
    /// Matching reply with `now <= sent_at + probe_interval`. Clears the streak.
    Success,
    /// This interval had no matching timely reply. Not a public loss sample.
    ProbeMiss,
    /// Matching reply after the interval already expired. Does not clear the streak.
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
    /// A mismatched challenge is [`ProbeVerdict::ProbeMiss`]. It does not clear
    /// the streak. A match with `now > sent_at + probe_interval` is
    /// [`ProbeVerdict::Late`] and does not clear the streak. A timely match is
    /// [`ProbeVerdict::Success`] and clears it. The interval that reaches
    /// `fail_threshold` returns [`ProbeVerdict::Suspect`] instead of `ProbeMiss`
    /// or `Late`.
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Healthy,
    Suspect,
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
    if let Some(target) = preferred(policy, paths, now_ms) {
        if target == current || may_switch(policy, current, target, paths, now_ms) {
            return Ok(Selection::path(target));
        }
    } else if paths.get(current).health == Health::Down {
        return Ok(Selection::StayDown);
    }
    Ok(Selection::path(current))
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

fn preferred(policy: &Policy, paths: PathSet, now_ms: u64) -> Option<PathId> {
    PATH_PREFERENCE.into_iter().find(|path| {
        if *path == PathId::BackupCdn && same_core_healthy(paths) {
            return false;
        }
        adoptable(policy, paths.get(*path), now_ms)
    })
}

fn same_core_healthy(paths: PathSet) -> bool {
    paths.same_core_dir.health == Health::Healthy || paths.same_core_cdn.health == Health::Healthy
}

fn adoptable(policy: &Policy, status: PathStatus, now_ms: u64) -> bool {
    status.health == Health::Healthy && dwell(status.since_ms, now_ms) >= policy.recover_hold_ms()
}

fn may_switch(
    policy: &Policy,
    current: PathId,
    target: PathId,
    paths: PathSet,
    now_ms: u64,
) -> bool {
    if rank(target) < rank(current) {
        return true;
    }
    degrade_ready(policy, paths.get(current), now_ms)
}

fn degrade_ready(policy: &Policy, status: PathStatus, now_ms: u64) -> bool {
    match status.health {
        Health::Down => true,
        Health::Suspect => dwell(status.since_ms, now_ms) >= policy.degrade_hold_ms(),
        Health::Healthy => false,
    }
}

fn rank(path: PathId) -> u8 {
    match path {
        PathId::SameCoreDir => 0,
        PathId::SameCoreCdn => 1,
        PathId::BackupCdn => 2,
    }
}

fn dwell(since_ms: u64, now_ms: u64) -> u64 {
    now_ms.saturating_sub(since_ms)
}

/// Lower bound `detect + min(backoff, BACKOFF_MAX) + rtt * round_trips`.
///
/// The components are the only inputs. This does not add a 2ms handshake or a
/// 100ms cross-continent LSA. `Ok(sum)` means the sum is at least 10s and is
/// an input to a real test, not a measured P99. A smaller sum is
/// [`FailoverError::FloorBelowTarget`], an incomplete budget, not a pass.
/// `G-FAILOVER` is not decided here.
pub fn estimate_switch_floor(
    detect_ms: u64,
    backoff_ms: u64,
    rtt_ms: u64,
    handshake_round_trips: u32,
) -> Result<u64, FailoverError> {
    let backoff = backoff_ms.min(BACKOFF_MAX);
    let trips = u64::from(handshake_round_trips);
    let rtt_total = rtt_ms
        .checked_mul(trips)
        .ok_or(FailoverError::BudgetOverflow)?;
    let sum = detect_ms
        .checked_add(backoff)
        .and_then(|partial| partial.checked_add(rtt_total))
        .ok_or(FailoverError::BudgetOverflow)?;
    if sum < INCOMPLETE_BELOW_MS {
        Err(FailoverError::FloorBelowTarget { sum_ms: sum })
    } else {
        Ok(sum)
    }
}

/// Accepted circuits on primary and backup.
///
/// §8.5 lets backup accept fewer circuits. It does not let backup pick a weaker
/// suite. This struct is not generic, has no suite or crypto-policy field, and
/// [`CircuitCaps::new`] takes no such argument.
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
    fn policy_below_the_floors_is_rejected_and_a_longer_probe_is_accepted() {
        assert_eq!(
            Policy::try_new(
                PROBE_INTERVAL - 1,
                FAIL_THRESHOLD,
                DEGRADE_HOLD,
                RECOVER_HOLD
            ),
            Err(FailoverError::PolicyBelowFloor)
        );
        assert_eq!(
            Policy::try_new(
                PROBE_INTERVAL,
                FAIL_THRESHOLD - 1,
                DEGRADE_HOLD,
                RECOVER_HOLD
            ),
            Err(FailoverError::PolicyBelowFloor)
        );
        assert_eq!(
            Policy::try_new(
                PROBE_INTERVAL,
                FAIL_THRESHOLD,
                DEGRADE_HOLD - 1,
                RECOVER_HOLD
            ),
            Err(FailoverError::PolicyBelowFloor)
        );
        assert_eq!(
            Policy::try_new(
                PROBE_INTERVAL,
                FAIL_THRESHOLD,
                DEGRADE_HOLD,
                RECOVER_HOLD - 1
            ),
            Err(FailoverError::PolicyBelowFloor)
        );
        let raised = Policy::try_new(5_000, 4, DEGRADE_HOLD, RECOVER_HOLD).unwrap();
        assert_eq!(raised.probe_interval_ms(), 5_000);
        assert_eq!(raised.fail_threshold(), 4);

        let sent = [9u8; 16];
        let mut watch = ProbeWatch::new(raised);
        assert_eq!(
            watch.observe_reply(sent, sent, 0, 5_000),
            ProbeVerdict::Success
        );
        let mut floor = ProbeWatch::new(Policy::plan());
        assert_eq!(
            floor.observe_reply(sent, sent, 0, 5_000),
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

        // DIR has been healthy for 1s, so it is not adoptable yet, and it still
        // blocks backup. The dead current path cannot stay up, so the result
        // is StayDown rather than BackupCdn.
        let blocked = choose(
            PathId::SameCoreCdn,
            paths(status(Health::Healthy, NOW - 1_000), down(), held(NOW)),
            NOW,
        );
        assert_eq!(blocked, Selection::StayDown);
        assert_ne!(blocked, Selection::BackupCdn);

        // Suspect is not Healthy, so it does not block backup once the degrade hold is open.
        let suspect_dir = status(Health::Suspect, NOW - DEGRADE_HOLD);
        let backup = choose(
            PathId::SameCoreDir,
            paths(suspect_dir, down(), held(NOW)),
            NOW,
        );
        assert_eq!(backup, Selection::BackupCdn);
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
    fn recovered_path_is_not_used_at_119s_and_is_used_at_120s() {
        let too_soon = paths(status(Health::Healthy, NOW - 119_000), down(), down());
        assert_eq!(
            choose(PathId::SameCoreCdn, too_soon, NOW),
            Selection::StayDown
        );
        assert_ne!(
            choose(PathId::SameCoreCdn, too_soon, NOW),
            Selection::SameCoreDir
        );

        let boundary = paths(status(Health::Healthy, NOW - 119_999), down(), down());
        assert_eq!(
            choose(PathId::SameCoreCdn, boundary, NOW),
            Selection::StayDown
        );

        let ready = paths(status(Health::Healthy, NOW - RECOVER_HOLD), down(), down());
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
    fn estimate_under_10s_is_an_incomplete_budget_not_a_pass() {
        // 6_000 + min(1_000, BACKOFF_MAX) + 50 * 4 = 7_200.
        // FloorBelowTarget is not Ok. This does not claim a failover finished within 10s.
        assert_eq!(
            estimate_switch_floor(6_000, 1_000, 50, 4),
            Err(FailoverError::FloorBelowTarget { sum_ms: 7_200 })
        );
        // Backoff above the plan ceiling is clamped. 8_000 + 1_000 = 9_000, not 13_000.
        assert_eq!(
            estimate_switch_floor(8_000, 5_000, 0, 0),
            Err(FailoverError::FloorBelowTarget { sum_ms: 9_000 })
        );
        assert_eq!(
            estimate_switch_floor(8_999, BACKOFF_MAX, 0, 0),
            Err(FailoverError::FloorBelowTarget { sum_ms: 9_999 })
        );
        // The Ok value is the sum, a lower bound to feed a real test, not a measured P99.
        let sum = estimate_switch_floor(6_000, 1_000, 400, 8).unwrap();
        assert_eq!(sum, 6_000 + 1_000 + 400 * 8);
        assert!(sum >= 10_000);
        assert_eq!(estimate_switch_floor(9_000, 1_000, 0, 0), Ok(10_000));
        assert_eq!(
            estimate_switch_floor(u64::MAX, 0, u64::MAX, 2),
            Err(FailoverError::BudgetOverflow)
        );
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
