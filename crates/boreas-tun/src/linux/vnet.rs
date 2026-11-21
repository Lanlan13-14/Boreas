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
    ) -> Result<Option<InspectedPacket<'buf>>, LinuxTunError> {
        if scratch.len() <= mtu {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        if !self.has_pending() {
            self.read_syscalls = self.read_syscalls.saturating_add(1);
            let n = match read_fd(fd, &mut self.frame) {
                Ok(0) => return Ok(None),
                Ok(n) => n,
                Err(LinuxTunError::Io(err)) if err.kind() == io::ErrorKind::WouldBlock => {
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
