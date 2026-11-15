//! Inner path-MTU decisions. Outer TCP segmentation does not replace them.
//!
//! This module does not send ICMP and does not open a TUN device. G-MTU is not passed.

/// Default overlay MTU. Jumbo frames are explicit, never implied.
pub const DEFAULT_MTU: u16 = 1500;

/// What to do with an IPv4 packet that has DF clear and exceeds the path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonDfPolicy {
    /// Caller may fragment. This module does not fragment.
    Fragment,
    /// Drop and report. Never silently discard without the error.
    Refuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    V4 { df: bool },
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmtuAction {
    Forward,
    FragmentationNeeded { mtu: u16 },
    PacketTooBig { mtu: u16 },
    Refuse { mtu: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmtuError {
    ZeroMtu,
    ZeroLength,
}

/// Outer TCP segmentation is not a reason to skip inner PTB.
pub const fn outer_tcp_replaces_inner_pmtu() -> bool {
    false
}

/// E2E checks the exit MTU only after decrypt. A forwarder must not look inside.
pub const fn forwarder_may_inspect_e2e() -> bool {
    false
}

pub fn decide(
    family: Family,
    packet_len: u16,
    path_mtu: u16,
    non_df: NonDfPolicy,
) -> Result<PmtuAction, PmtuError> {
    if path_mtu == 0 {
        return Err(PmtuError::ZeroMtu);
    }
    if packet_len == 0 {
        return Err(PmtuError::ZeroLength);
    }
    if packet_len <= path_mtu {
        return Ok(PmtuAction::Forward);
    }
    Ok(match family {
        Family::V6 => PmtuAction::PacketTooBig { mtu: path_mtu },
        Family::V4 { df: true } => PmtuAction::FragmentationNeeded { mtu: path_mtu },
        Family::V4 { df: false } => match non_df {
            NonDfPolicy::Fragment => PmtuAction::FragmentationNeeded { mtu: path_mtu },
            NonDfPolicy::Refuse => PmtuAction::Refuse { mtu: path_mtu },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_drops_are_signalled() {
        assert!(!outer_tcp_replaces_inner_pmtu());
        assert!(!forwarder_may_inspect_e2e());
        assert_eq!(
            decide(Family::V4 { df: true }, 1500, 1280, NonDfPolicy::Refuse).unwrap(),
            PmtuAction::FragmentationNeeded { mtu: 1280 }
        );
        assert_eq!(
            decide(Family::V6, 9000, 1500, NonDfPolicy::Fragment).unwrap(),
            PmtuAction::PacketTooBig { mtu: 1500 }
        );
        assert_eq!(
            decide(Family::V4 { df: false }, 1500, 1280, NonDfPolicy::Refuse).unwrap(),
            PmtuAction::Refuse { mtu: 1280 }
        );
        assert_eq!(
            decide(Family::V4 { df: true }, 1280, 1500, NonDfPolicy::Refuse).unwrap(),
            PmtuAction::Forward
        );
        assert!(decide(Family::V6, 1, 0, NonDfPolicy::Refuse).is_err());
    }
}
