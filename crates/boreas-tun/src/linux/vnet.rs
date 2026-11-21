//! Local Linux TUN VNET framing. Never used to decode peer traffic.
use super::{LinuxTunError, inspect_at_mtu, read_fd};
use crate::{
    Error, InspectedPacket, IpVersion, PacketInfo, checksum,
    gso::{MAX_OUTPUT_BYTES, MAX_SUPERPACKET, segment_linux_tcpv4},
    virtio::{GSO_NONE, GSO_TCPV4, VIRTIO_HDR_LEN},
};
use std::{io, os::fd::RawFd};

const NEEDS_CSUM: u8 = 1;
const DATA_VALID: u8 = 2;
const TCP: u8 = 6;
const UDP: u8 = 17;

/// One reusable frame and one reusable segmented output. Pending segments
/// are consumed before the next fd read, including across forwarding turns.
pub(super) struct Reader {
    frame: Vec<u8>,
    output: Vec<u8>,
    pending: std::ops::Range<usize>,
    stride: usize,
    read_syscalls: u64,
    delivered_segments: u64,
}

impl Reader {
    pub(super) fn new(mtu: usize) -> Self {
        // The sentinel byte rejects a truncated oversize frame (TUN read can
        // return exactly the supplied capacity). Ordinary IP still gets MTU.
        Self {
            frame: vec![0; VIRTIO_HDR_LEN + MAX_SUPERPACKET.max(mtu) + 1],
            output: vec![0; MAX_OUTPUT_BYTES],
            pending: 0..0,
            stride: 0,
            read_syscalls: 0,
            delivered_segments: 0,
        }
    }

    pub(super) fn read_counts(&self) -> (u64, u64) {
        (self.read_syscalls, self.delivered_segments)
    }

    pub(super) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(super) fn read<'buf>(
        &mut self,
        fd: RawFd,
        mtu: usize,
        scratch: &'buf mut [u8],
        allow_empty: bool,
    ) -> Result<Option<InspectedPacket<'buf>>, LinuxTunError> {
        if scratch.len() <= mtu {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        if !self.has_pending() {
            self.read_syscalls = self.read_syscalls.saturating_add(1);
            let n = match read_fd(fd, &mut self.frame) {
                Ok(0) => return Ok(None),
                Ok(n) => n,
                Err(LinuxTunError::Io(err))
                    if allow_empty && err.kind() == io::ErrorKind::WouldBlock =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
            if n >= self.frame.len() {
                return Err(Error::VirtioInvalid.into());
            }
            let frame = &mut self.frame[..n];
            let (&[flags, gso, h0, h1, m0, m1, s0, s1, o0, o1], packet) = frame
                .split_first_chunk_mut::<VIRTIO_HDR_LEN>()
                .map(|(header, body)| (&*header, body))
                .ok_or(Error::VirtioHeaderTruncated)?;
            match gso {
                GSO_NONE => {
                    if [h0, h1, m0, m1] != [0; 4] {
                        return Err(Error::VirtioInvalid.into());
                    }
                    let info = inspect_at_mtu(packet, mtu)?.info();
                    match flags {
                        0 | DATA_VALID if [s0, s1, o0, o1] == [0; 4] => {}
                        NEEDS_CSUM => complete_partial(
                            packet,
                            info,
                            usize::from(u16::from_le_bytes([s0, s1])),
                            usize::from(u16::from_le_bytes([o0, o1])),
                        )?,
                        _ => return Err(Error::VirtioInvalid.into()),
                    }
                    let dst = &mut scratch[..packet.len()];
                    dst.copy_from_slice(packet);
                    // Only transport bytes changed after structural inspection.
                    return Ok(Some(InspectedPacket { bytes: dst, info }));
                }
                GSO_TCPV4 => {
                    let mut segments = segment_linux_tcpv4(frame, mtu, &mut self.output)
                        .map_err(LinuxTunError::Gso)?;
                    let count = segments.len();
                    let stride = segments
                        .next()
                        .expect("GSO has at least two segments")
                        .len();
                    let last = segments
                        .next_back()
                        .expect("GSO has at least two segments")
                        .len();
                    self.pending = 0..(stride * (count - 1) + last);
                    self.stride = stride;
                }
                _ => return Err(Error::VirtioUnsupportedGso.into()),
            }
        }
        let start = self.pending.start;
        let end = (start + self.stride).min(self.pending.end);
        let dst = &mut scratch[..end - start];
        dst.copy_from_slice(&self.output[start..end]);
        let inspected = inspect_at_mtu(dst, mtu)?;
        self.pending.start = end;
        self.delivered_segments = self.delivered_segments.saturating_add(1);
        Ok(Some(inspected))
    }
}

/// Complete an ordinary Linux TCP/UDP CHECKSUM_PARTIAL skb. In particular the
/// checksum field contains the folded *non-complemented* pseudo-header sum,
/// not zero. Verify that seed and kernel offsets before using them. Unsupported
/// partials (fragments, IP options/extensions, other protocols) fail closed.
fn complete_partial(
    packet: &mut [u8],
    info: PacketInfo,
    start: usize,
    offset: usize,
) -> Result<(), Error> {
    let base = match info.version {
        IpVersion::V4 => 20,
        IpVersion::V6 => 40,
    };
    if info.fragment.is_some() || start != info.header_len || start != base {
        return Err(Error::VirtioUnsupportedOffload);
    }
    let len = packet.len() - start;
    let transport = &packet[start..];
    match info.protocol {
        TCP if offset == 16
            && len >= 20
            && (20..=len).contains(&(usize::from(transport[12] >> 4) * 4)) => {}
        UDP if offset == 6
            && len >= 8
            && usize::from(u16::from_be_bytes([transport[4], transport[5]])) == len => {}
        _ => return Err(Error::VirtioUnsupportedOffload),
    }
    let len16 = u16::try_from(len).map_err(|_| Error::VirtioInvalid)?;
    let mut pseudo = [0; 40];
    let pseudo = match info.version {
        IpVersion::V4 => {
            pseudo[..8].copy_from_slice(&packet[12..20]);
            pseudo[9] = info.protocol;
            pseudo[10..12].copy_from_slice(&len16.to_be_bytes());
            &pseudo[..12]
        }
        IpVersion::V6 => {
            pseudo[..32].copy_from_slice(&packet[8..40]);
            pseudo[32..36].copy_from_slice(&u32::from(len16).to_be_bytes());
            pseudo[39] = info.protocol;
            &pseudo[..]
        }
    };
    let seed = u16::from_be_bytes([transport[offset], transport[offset + 1]]);
    if seed != !checksum(pseudo) {
        return Err(Error::InvalidChecksum);
    }
    // This is Linux's ones-complement checksum over csum_start through end,
    // including the seed; CSUM_MANGLED_0 represents a computed zero checksum.
    let value = match checksum(transport) {
        0 => u16::MAX,
        checksum => checksum,
    };
    packet[start + offset..start + offset + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsRawFd, os::unix::net::UnixDatagram};

    fn frame(gso: bool, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let transport_len = (if protocol == TCP { 20 } else { 8 }) + payload.len();
        let len = 20 + transport_len;
        let mut frame = vec![0; VIRTIO_HDR_LEN + len];
        let (meta, ip) = frame.split_at_mut(VIRTIO_HDR_LEN);
        meta[0] = NEEDS_CSUM;
        meta[6] = 20;
        meta[8] = if protocol == TCP { 16 } else { 6 };
        if gso {
            meta[1] = GSO_TCPV4;
            meta[2] = 43; // skb head includes three payload bytes
            meta[4] = 40;
        }
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        let check = checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&check.to_be_bytes());
        let mut pseudo = [0; 12];
        pseudo[..8].copy_from_slice(&ip[12..20]);
        pseudo[9] = protocol;
        pseudo[10..12].copy_from_slice(&(transport_len as u16).to_be_bytes());
        let transport = &mut ip[20..];
        transport[..4].copy_from_slice(&[0, 81, 0, 82]);
        if protocol == TCP {
            transport[12..14].copy_from_slice(&[0x50, 0x19]); // ACK, PSH, FIN
        } else {
            transport[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
        }
        let offset = usize::from(meta[8]);
        transport[offset..offset + 2].copy_from_slice(&(!checksum(&pseudo)).to_be_bytes());
        transport[transport_len - payload.len()..].copy_from_slice(payload);
        frame
    }

    fn transport_checksum(ip: &[u8]) -> u16 {
        let mut oracle = ip[12..20].to_vec();
        oracle.extend([0, ip[9]]);
        oracle.extend(((ip.len() - 20) as u16).to_be_bytes());
        oracle.extend(&ip[20..]);
        checksum(&oracle)
    }

    #[test]
    fn pending_segments_are_fifo_and_do_not_read_the_following_frame() {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        let fd = rx.as_raw_fd();
        let mut reader = Reader::new(80);
        let mut scratch = [0; 81];
        let payload: Vec<_> = (0..83u8).collect();
        tx.send(&frame(true, TCP, &payload)).unwrap();
        tx.send(&frame(false, UDP, &[0xab, 0xcd, 0xef])).unwrap();
        for (i, chunk) in payload.chunks(40).enumerate() {
            let p = reader.read(fd, 80, &mut scratch, true).unwrap().unwrap();
            assert_eq!(&p.bytes()[40..], chunk);
            assert_eq!(p.bytes()[33], if i == 2 { 0x19 } else { 0x10 });
            assert_eq!(transport_checksum(p.bytes()), 0);
            assert_eq!(reader.read_counts(), (1, i as u64 + 1));
        }
        let udp = reader.read(fd, 80, &mut scratch, true).unwrap().unwrap();
        assert_eq!(&udp.bytes()[28..], &[0xab, 0xcd, 0xef]);
        assert_eq!(transport_checksum(udp.bytes()), 0);
        assert_eq!(reader.read_counts(), (2, 3));
        assert!(reader.read(fd, 80, &mut scratch, true).unwrap().is_none());
        assert_eq!(reader.read_counts(), (3, 3));
    }

    #[test]
    fn unknown_gso_wrong_seed_and_oversize_do_not_produce_packets() {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        let fd = rx.as_raw_fd();
        let mut reader = Reader::new(80);
        let mut scratch = [0xa5; 81];
        let mut unknown = frame(true, TCP, &[0; 83]);
        unknown[1] |= 0x80;
        let mut wrong_seed = frame(false, TCP, &[1]);
        wrong_seed[VIRTIO_HDR_LEN + 36] ^= 1;
        let mut distant_too_short_hint = frame(true, TCP, &[0; 83]);
        distant_too_short_hint[2] = 39;
        let mut too_large_hint = frame(true, TCP, &[0; 83]);
        too_large_hint[2] = 124;
        let mut bad_offset = frame(false, UDP, &[0]);
        bad_offset[8] = 5;
        for rejected in [
            unknown,
            wrong_seed,
            distant_too_short_hint,
            too_large_hint,
            bad_offset,
            frame(false, TCP, &[0; 41]),
            vec![0; VIRTIO_HDR_LEN + MAX_SUPERPACKET + 2],
        ] {
            tx.send(&rejected).unwrap();
            assert!(reader.read(fd, 80, &mut scratch, true).is_err());
            assert!(!reader.has_pending());
            assert_eq!(scratch, [0xa5; 81]);
        }
        assert_eq!(reader.read_counts(), (7, 0));
    }
}
