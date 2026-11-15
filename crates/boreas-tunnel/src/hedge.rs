//! First-release duplicate suppression. §6.4 cancels arbitrary SYN/DNS
//! double-send. A later hedge needs a session id and a 64-bit sequence.
//!
//! This module does not send packets. G-PERF and G-DATA are not passed.

/// A hedge identity. The 64-bit sequence is not a 32-bit counter that wraps
/// back to zero without a new session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HedgeId {
    pub session: [u8; 16],
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeError {
    Empty,
    Duplicate,
    SequenceWrapped,
    Window,
}

/// Copying one TLS record onto two sessions is forbidden.
pub const fn tls_record_may_be_copied() -> bool {
    false
}

/// A 32-bit sequence restart without a new session is not a new message.
pub const fn sequence32_restart_is_new_message() -> bool {
    false
}

/// Accept a message once inside `window` of the highest accepted sequence.
/// A repeat of an accepted id is `Duplicate`, not a second delivery.
pub fn observe(seen: &mut Vec<HedgeId>, id: HedgeId, window: u64) -> Result<(), HedgeError> {
    if window == 0 {
        return Err(HedgeError::Window);
    }
    if seen.contains(&id) {
        return Err(HedgeError::Duplicate);
    }
    if let Some(high) = seen
        .iter()
        .filter(|old| old.session == id.session)
        .map(|old| old.sequence)
        .max()
        && id.sequence < high.saturating_sub(window)
    {
        return Err(HedgeError::SequenceWrapped);
    }
    seen.push(id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seq: u64) -> HedgeId {
        HedgeId {
            session: [7; 16],
            sequence: seq,
        }
    }

    #[test]
    fn a_copy_is_not_a_second_message() {
        assert!(!tls_record_may_be_copied());
        assert!(!sequence32_restart_is_new_message());
        let mut seen = Vec::new();
        observe(&mut seen, id(1), 8).unwrap();
        assert_eq!(observe(&mut seen, id(1), 8), Err(HedgeError::Duplicate));
        observe(&mut seen, id(2), 8).unwrap();
        assert_eq!(seen.len(), 2);
    }
}
