//! Queue freeze and device-offload ownership for §9.1.
//!
//! Plans how many TUN queues a worker count may use, which `IFF_*` bits that
//! count requires, and the queue-0 offload degrade log. Nothing here opens a
//! device, issues an ioctl, or installs a route. This is not the `G-TUN` gate.

use std::fmt;

use super::{OffloadCaps, VirtioNetHeader, parse_virtio_frame};

/// Linux `include/uapi/linux/if_tun.h` bits. Stored here so queue planning does
/// not call `ioctl` or depend on the OS adapter.
const IFF_TUN_BITS: u16 = 0x0001;
const IFF_MULTI_QUEUE_BITS: u16 = 0x0100;
const IFF_NO_PI_BITS: u16 = 0x1000;
const IFF_VNET_HDR_BITS: u16 = 0x4000;

/// `virtio_net_hdr.gso_type` value for TCPv4, with the ECN bit masked off the
/// same way [`parse_virtio_frame`] does.
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Set of TUN interface flags. Absence of a required bit is rejected by
/// [`check_flags`]; nothing in this module adds the missing bit back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flags(u16);

impl Flags {
    pub const IFF_TUN: Self = Self(IFF_TUN_BITS);
    pub const IFF_MULTI_QUEUE: Self = Self(IFF_MULTI_QUEUE_BITS);
    pub const IFF_NO_PI: Self = Self(IFF_NO_PI_BITS);
    pub const IFF_VNET_HDR: Self = Self(IFF_VNET_HDR_BITS);

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Why a queue plan, flag check, or offload-log update was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// `plan_queues(0)` is not a single-worker device.
    NoWorkers,
    /// More than 4 workers. Not clamped down to 4.
    TooManyQueues,
    /// `required_flags` / `check_flags` saw a count outside `1..=4`.
    InvalidQueueCount,
    /// At least one required `IFF_*` bit is absent. Not filled in.
    MissingFlags,
    /// A bit outside the required set is present (for one queue, that includes
    /// `IFF_MULTI_QUEUE`).
    UnexpectedFlags,
    /// Device offload was offered to a queue other than 0.
    NotOwner,
    /// The degrade ladder was jumped. The log is left unchanged.
    SkippedStep,
    /// The per-step attempt counter would not fit in `u32`.
    TooManyAttempts,
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoWorkers => "worker count is zero",
            Self::TooManyQueues => "worker count exceeds 4 queues",
            Self::InvalidQueueCount => "queue count must be 1..=4",
            Self::MissingFlags => "required TUN flags are missing",
            Self::UnexpectedFlags => "TUN flags include a bit this queue count forbids",
            Self::NotOwner => "device offload is owned by queue 0",
            Self::SkippedStep => "offload degrade skipped a step",
            Self::TooManyAttempts => "offload attempt counter overflowed",
        })
    }
}

impl std::error::Error for QueueError {}

/// Queue count for `workers`. One worker uses one queue. Two, three, or four
/// workers use that many queues. Zero is rejected. Five or more is rejected and
/// is not clamped to 4.
pub const fn plan_queues(workers: u16) -> Result<u8, QueueError> {
    match workers {
        0 => Err(QueueError::NoWorkers),
        1 => Ok(1),
        2 => Ok(2),
        3 => Ok(3),
        4 => Ok(4),
        _ => Err(QueueError::TooManyQueues),
    }
}

/// Flags a device with `queues` must be created with.
///
/// One queue requires `IFF_TUN`, `IFF_NO_PI`, and `IFF_VNET_HDR`, and does not
/// include `IFF_MULTI_QUEUE`. Two to four queues require those three plus
/// `IFF_MULTI_QUEUE`. Any other count is an error.
pub const fn required_flags(queues: u8) -> Result<Flags, QueueError> {
    let base = Flags::IFF_TUN
        .union(Flags::IFF_NO_PI)
        .union(Flags::IFF_VNET_HDR);
    match queues {
        1 => Ok(base),
        2..=4 => Ok(base.union(Flags::IFF_MULTI_QUEUE)),
        _ => Err(QueueError::InvalidQueueCount),
    }
}

/// Fail if `present` is not exactly [`required_flags`]. Missing bits stay
/// missing; this does not return a repaired set.
pub const fn check_flags(present: Flags, queues: u8) -> Result<(), QueueError> {
    let required = match required_flags(queues) {
        Ok(flags) => flags,
        Err(error) => return Err(error),
    };
    if present.0 & required.0 != required.0 {
        return Err(QueueError::MissingFlags);
    }
    if present.0 & !required.0 != 0 {
        return Err(QueueError::UnexpectedFlags);
    }
    Ok(())
}

/// Device `TUNSETOFFLOAD` degrade order: full capability, then TCP GSO, then off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadStep {
    Full,
    TcpGso,
    Disabled,
}

/// One recorded attempt. `ioctl_attempt` counts tries of this step on queue 0.
/// Writing the record does not perform an ioctl.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffloadAttempt {
    pub queue_id: u8,
    pub step: OffloadStep,
    pub ioctl_attempt: u32,
}

/// Queue-0 offload attempts, in the order they were accepted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OffloadLog {
    attempts: Vec<OffloadAttempt>,
}

impl OffloadLog {
    pub fn attempts(&self) -> &[OffloadAttempt] {
        &self.attempts
    }
}

const fn degrade_rank(step: OffloadStep) -> u8 {
    match step {
        OffloadStep::Full => 0,
        OffloadStep::TcpGso => 1,
        OffloadStep::Disabled => 2,
    }
}

fn transition_allowed(previous: Option<OffloadStep>, next: OffloadStep) -> bool {
    match previous {
        None => matches!(next, OffloadStep::Full),
        Some(current) => {
            let current_rank = degrade_rank(current);
            let next_rank = degrade_rank(next);
            next_rank == current_rank || next_rank == current_rank + 1
        }
    }
}

/// Append an offload attempt for `queue`, or leave `log` unchanged on error.
///
/// Only queue 0 is the device owner. The same step may be recorded again after
/// a failed try. The next new step must be the immediate degrade
/// (`Full` → `TcpGso` → `Disabled`). `Disabled` while the last recorded step is
/// still `Full` is [`QueueError::SkippedStep`].
pub fn record_attempt(
    log: &mut OffloadLog,
    queue: u8,
    step: OffloadStep,
) -> Result<(), QueueError> {
    if queue != 0 {
        return Err(QueueError::NotOwner);
    }
    let previous = log.attempts.last().map(|attempt| attempt.step);
    if !transition_allowed(previous, step) {
        return Err(QueueError::SkippedStep);
    }
    let prior = log
        .attempts
        .iter()
        .filter(|attempt| attempt.step == step)
        .count();
    let ioctl_attempt = u32::try_from(prior)
        .map_err(|_| QueueError::TooManyAttempts)?
        .checked_add(1)
        .ok_or(QueueError::TooManyAttempts)?;
    log.attempts.push(OffloadAttempt {
        queue_id: queue,
        step,
        ioctl_attempt,
    });
    Ok(())
}

/// Queue-0 attempt counts, in degrade order. Steps that were not recorded are
/// omitted. Attempts that are not queue 0 are not counted; [`record_attempt`]
/// refuses those before they can be stored.
pub fn owner_attempts(log: &OffloadLog) -> Vec<(OffloadStep, u32)> {
    let mut full = 0u32;
    let mut tcp_gso = 0u32;
    let mut disabled = 0u32;
    for attempt in &log.attempts {
        if attempt.queue_id != 0 {
            continue;
        }
        match attempt.step {
            OffloadStep::Full => full = full.saturating_add(1),
            OffloadStep::TcpGso => tcp_gso = tcp_gso.saturating_add(1),
            OffloadStep::Disabled => disabled = disabled.saturating_add(1),
        }
    }
    let mut counts = Vec::new();
    if full > 0 {
        counts.push((OffloadStep::Full, full));
    }
    if tcp_gso > 0 {
        counts.push((OffloadStep::TcpGso, tcp_gso));
    }
    if disabled > 0 {
        counts.push((OffloadStep::Disabled, disabled));
    }
    counts
}

/// Whether this crate treats the TLS path as zero-copy.
///
/// Always `false`. A raw AEAD API does not prove the TLS stack avoids a copy.
/// Copies inside the TLS engine have to be profiled on their own.
pub const fn tls_path_is_zero_copy() -> bool {
    false
}

/// `true` only when negotiation included TSO4 and the header says TCP4 GSO.
///
/// A header that says TCP4 GSO while negotiation did not include TSO4 is
/// `false`. This function does not pass the header to a kernel.
pub const fn foreign_gso_type_is_kernel_safe(negotiated_tso4: bool, header_gso_tcp4: bool) -> bool {
    negotiated_tso4 && header_gso_tcp4
}

fn header_claims_tcp4_gso(header: &VirtioNetHeader) -> bool {
    header.gso_type & !VIRTIO_NET_HDR_GSO_ECN == VIRTIO_NET_HDR_GSO_TCPV4
}

/// Run [`foreign_gso_type_is_kernel_safe`] on a frame [`parse_virtio_frame`]
/// accepted. Parse refuses every super-packet, so a TCP4 GSO header never
/// becomes a kernel write from here. A rejected frame is not kernel-safe.
pub fn parsed_foreign_gso_is_kernel_safe(
    frame: &[u8],
    local: OffloadCaps,
    peer: OffloadCaps,
) -> bool {
    let caps = local.intersection(peer);
    match parse_virtio_frame(frame, caps) {
        Ok((header, _payload)) => {
            foreign_gso_type_is_kernel_safe(caps.tso4, header_claims_tcp4_gso(&header))
        }
        Err(_error) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Flags, OffloadLog, OffloadStep, QueueError, VIRTIO_NET_HDR_GSO_ECN,
        VIRTIO_NET_HDR_GSO_TCPV4, check_flags, foreign_gso_type_is_kernel_safe, owner_attempts,
        parsed_foreign_gso_is_kernel_safe, plan_queues, record_attempt, required_flags,
        tls_path_is_zero_copy,
    };
    use crate::{OffloadCaps, VirtioNetHeader, parse_virtio_frame};

    /// Keeps assert arguments out of const-eval so clippy does not treat a
    /// `const fn` result as an assertion on a constant.
    fn hold<T>(value: T) -> T {
        value
    }

    #[test]
    fn workers_zero_and_five_are_rejected() {
        assert_eq!(hold(plan_queues(0)), Err(QueueError::NoWorkers));
        assert_eq!(hold(plan_queues(5)), Err(QueueError::TooManyQueues));
        assert_eq!(hold(plan_queues(8)), Err(QueueError::TooManyQueues));
        assert_ne!(hold(plan_queues(8)), Ok(4));
    }

    #[test]
    fn workers_one_and_four_are_accepted() {
        assert_eq!(hold(plan_queues(1)), Ok(1));
        assert_eq!(hold(plan_queues(2)), Ok(2));
        assert_eq!(hold(plan_queues(3)), Ok(3));
        assert_eq!(hold(plan_queues(4)), Ok(4));
    }

    #[test]
    fn single_queue_flags_exclude_multi_queue() {
        let single = required_flags(1).unwrap();
        assert!(single.contains(Flags::IFF_TUN));
        assert!(single.contains(Flags::IFF_NO_PI));
        assert!(single.contains(Flags::IFF_VNET_HDR));
        assert!(!single.contains(Flags::IFF_MULTI_QUEUE));
        assert_eq!(single.bits() & Flags::IFF_MULTI_QUEUE.bits(), 0);
        assert_eq!(hold(check_flags(single, 1)), Ok(()));

        let missing_tun = Flags(single.bits() & !Flags::IFF_TUN.bits());
        assert_eq!(
            hold(check_flags(missing_tun, 1)),
            Err(QueueError::MissingFlags)
        );
        assert_eq!(
            hold(check_flags(single.union(Flags::IFF_MULTI_QUEUE), 1)),
            Err(QueueError::UnexpectedFlags)
        );

        let multi = required_flags(4).unwrap();
        assert!(multi.contains(Flags::IFF_MULTI_QUEUE));
        assert!(multi.contains(Flags::IFF_TUN));
        assert!(multi.contains(Flags::IFF_NO_PI));
        assert!(multi.contains(Flags::IFF_VNET_HDR));
        assert_eq!(hold(check_flags(multi, 4)), Ok(()));
        assert_eq!(hold(required_flags(0)), Err(QueueError::InvalidQueueCount));
        assert_eq!(hold(required_flags(5)), Err(QueueError::InvalidQueueCount));
    }

    #[test]
    fn queue_one_cannot_record() {
        let mut log = OffloadLog::default();
        assert_eq!(
            record_attempt(&mut log, 1, OffloadStep::Full),
            Err(QueueError::NotOwner)
        );
        assert!(log.attempts().is_empty());
        assert!(owner_attempts(&log).is_empty());
    }

    #[test]
    fn full_retries_then_tcp_gso_are_counted_on_queue_zero() {
        let mut log = OffloadLog::default();
        record_attempt(&mut log, 0, OffloadStep::Full).unwrap();
        record_attempt(&mut log, 0, OffloadStep::Full).unwrap();
        record_attempt(&mut log, 0, OffloadStep::TcpGso).unwrap();
        let saved = log.clone();
        assert_eq!(
            record_attempt(&mut log, 1, OffloadStep::Disabled),
            Err(QueueError::NotOwner)
        );
        assert_eq!(log, saved);
        assert_eq!(
            owner_attempts(&log),
            vec![(OffloadStep::Full, 2), (OffloadStep::TcpGso, 1)]
        );
        assert!(log.attempts().iter().all(|attempt| attempt.queue_id == 0));
        assert_eq!(log.attempts()[0].ioctl_attempt, 1);
        assert_eq!(log.attempts()[1].ioctl_attempt, 2);
        assert_eq!(log.attempts()[2].ioctl_attempt, 1);
    }

    #[test]
    fn skipping_tcp_gso_is_rejected() {
        let mut log = OffloadLog::default();
        record_attempt(&mut log, 0, OffloadStep::Full).unwrap();
        let saved = log.clone();
        assert_eq!(
            record_attempt(&mut log, 0, OffloadStep::Disabled),
            Err(QueueError::SkippedStep)
        );
        assert_eq!(log, saved);
        record_attempt(&mut log, 0, OffloadStep::TcpGso).unwrap();
        record_attempt(&mut log, 0, OffloadStep::Disabled).unwrap();
        assert_eq!(
            owner_attempts(&log),
            vec![
                (OffloadStep::Full, 1),
                (OffloadStep::TcpGso, 1),
                (OffloadStep::Disabled, 1),
            ]
        );
    }

    #[test]
    fn foreign_gso_without_negotiated_tso4_is_rejected() {
        let header = VirtioNetHeader {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1400,
            csum_start: 0,
            csum_offset: 0,
        };
        let header_gso_tcp4 = header.gso_type & !VIRTIO_NET_HDR_GSO_ECN == VIRTIO_NET_HDR_GSO_TCPV4;
        assert!(hold(header_gso_tcp4));
        assert!(!hold(foreign_gso_type_is_kernel_safe(
            false,
            header_gso_tcp4
        )));
        assert!(hold(foreign_gso_type_is_kernel_safe(true, true)));
        assert!(!hold(foreign_gso_type_is_kernel_safe(true, false)));
        assert!(!hold(foreign_gso_type_is_kernel_safe(false, false)));

        let mut gso_frame = vec![0u8; 10 + 40];
        gso_frame[1] = VIRTIO_NET_HDR_GSO_TCPV4;
        gso_frame[2] = 40;
        gso_frame[4] = 0x78;
        gso_frame[5] = 0x05;
        let caps = OffloadCaps {
            tso4: true,
            ..OffloadCaps::default()
        };
        assert!(parse_virtio_frame(&gso_frame, caps).is_err());
        assert!(!parsed_foreign_gso_is_kernel_safe(&gso_frame, caps, caps));

        let packet = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x66, 0xc0, 0x0a, 0x14,
            0x00, 0x01, 0x0a, 0x14, 0x00, 0x02,
        ];
        let mut plain = vec![0u8; 10];
        plain.extend_from_slice(&packet);
        assert!(parse_virtio_frame(&plain, caps).is_ok());
        assert!(!parsed_foreign_gso_is_kernel_safe(&plain, caps, caps));
    }

    #[test]
    fn tls_path_is_not_zero_copy() {
        assert!(!hold(tls_path_is_zero_copy()));
    }
}
