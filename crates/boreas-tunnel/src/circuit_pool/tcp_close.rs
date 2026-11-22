//! Passive TCP close evidence, not a TCP firewall or socket state oracle.

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
// RFC 7323: fewer than 2^30 bytes may be outstanding even with scaling.
const MAX_FLIGHT: u32 = (1 << 30) - 1;

#[derive(Clone, Copy, Debug)]
pub(super) struct Segment {
    pub seq: u32,
    pub ack: u32,
    pub data: u32,
    pub flags: u8,
    pub outbound: bool,
    pub checksum_ok: bool,
}

impl Segment {
    pub(super) fn opening(self) -> bool {
        self.flags & (SYN | ACK | FIN | RST) == SYN
    }

    fn control(self) -> u8 {
        self.flags & (SYN | ACK | FIN | RST)
    }

    fn direction(self) -> usize {
        usize::from(self.outbound)
    }

    fn end(self) -> u32 {
        self.seq
            .wrapping_add(self.data + u32::from(self.flags & FIN != 0))
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Close {
    Untracked,
    Syn { from: usize, next: u32 },
    SynAck { from: usize, next: [u32; 2] },
    Open([Tx; 2]),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Tx {
    acked: u32,
    high: u32,
    fin: Option<Finish>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Finish {
    end: u32, // FIN consumes one sequence number
    ack: u32,
    data: u32,
}

impl Tx {
    fn new(next: u32) -> Self {
        Self {
            acked: next,
            high: next,
            fin: None,
        }
    }
}

impl Close {
    pub(super) fn new(s: Segment) -> Self {
        if s.checksum_ok && s.data == 0 {
            Self::Syn {
                from: s.direction(),
                next: s.seq.wrapping_add(1),
            }
        } else {
            Self::Untracked
        }
    }

    /// Observe only lane-validated traffic. Sequence arithmetic is anchored
    /// at each sender's cumulative ACK, not a raw integer ordering of u32s.
    /// Observing packet I/O is not proof of delivery: a FIN alone only marks
    /// a candidate, and only the opposite sender can acknowledge it.
    pub(super) fn observe(&mut self, s: Segment) -> Option<[Finish; 2]> {
        if !s.checksum_ok || s.flags & RST != 0 {
            return None;
        }
        let dir = s.direction();
        let other = 1 - dir;
        match *self {
            Self::Syn { from, next }
                if from == other && s.control() == (SYN | ACK) && s.ack == next && s.data == 0 =>
            {
                let mut both = [next; 2];
                both[dir] = s.seq.wrapping_add(1);
                *self = Self::SynAck { from, next: both };
                return None;
            }
            Self::SynAck { from, next }
                if from == dir
                    && s.flags & (SYN | ACK) == ACK
                    && s.seq == next[dir]
                    && s.ack == next[other] =>
            {
                *self = Self::Open(next.map(Tx::new));
            }
            _ => {}
        }
        let Self::Open(mut tx) = *self else {
            return None;
        };
        if s.flags & (SYN | ACK) != ACK {
            return None;
        }

        let progress = s.ack.wrapping_sub(tx[other].acked);
        let valid_ack = progress <= tx[other].high.wrapping_sub(tx[other].acked);
        let sent = &mut tx[dir];
        let flight = sent.high.wrapping_sub(sent.acked);
        let start = s.seq.wrapping_sub(sent.acked);
        let end = s.end().wrapping_sub(sent.acked);
        // Exclude positions behind the cumulative ACK, or implausibly far
        // ahead. A pure ACK cannot extend the observed sequence boundary.
        // Accept partial overlap with already ACKed bytes (retransmissions).
        let length = s.data + u32::from(s.flags & FIN != 0);
        if end > MAX_FLIGHT
            || (start > MAX_FLIGHT && length <= end)
            || (length == 0 && start > flight)
        {
            return None;
        }
        if s.flags & FIN != 0
            && (!valid_ack || (end < flight && !sent.fin.is_some_and(|fin| fin.end == s.end())))
        {
            return None;
        }
        if end > flight {
            // Data beyond an alleged FIN contradicts it. Demand new evidence.
            if sent.fin.is_some() {
                *self = Self::Untracked;
                return None;
            }
            sent.high = s.end();
            if s.flags & FIN != 0 {
                sent.fin = Some(Finish {
                    end: s.end(),
                    ack: s.ack,
                    data: s.data,
                });
            }
        }
        // ACKs beyond observed transmissions do not count. Duplicate or
        // regressing ACKs cannot roll the boundary backward.
        let received = &mut tx[other];
        if valid_ack {
            received.acked = s.ack;
        }
        *self = Self::Open(tx);
        let [Some(a), Some(b)] = tx.map(|t| t.fin.filter(|fin| fin.end == t.acked)) else {
            return None;
        };
        Some([a, b])
    }
}

/// Retained only during quarantine. Preserve retries at the same FIN/ACK
/// boundaries after a queue drop, without permitting a new bind or new data.
pub(super) fn close_retry(s: Segment, fins: [Finish; 2]) -> bool {
    let dir = s.direction();
    let (own, peer) = (fins[dir], fins[1 - dir]);
    s.checksum_ok
        && match s.control() {
            ACK => s.data == 0 && s.seq == own.end && s.ack == peer.end,
            flags if flags == (FIN | ACK) => {
                s.end() == own.end && s.data <= own.data && (s.ack == own.ack || s.ack == peer.end)
            }
            _ => false,
        }
}

/// IPv4 pseudo-header checksum. `addresses` is exactly 8 bytes (src + dst).
pub(super) fn tcp_checksum(addresses: &[u8], tcp: &[u8]) -> u16 {
    let (words, tail) = tcp.as_chunks::<2>();
    let (ip_words, _) = addresses.as_chunks::<2>();
    let mut sum = 6 + tcp.len() as u32;
    for &word in ip_words.iter().chain(words) {
        sum += u32::from(u16::from_be_bytes(word));
    }
    if let Some(&last) = tail.first() {
        sum += u32::from(last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
