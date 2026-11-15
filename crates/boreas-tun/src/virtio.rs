//! virtio_net_hdr checks from §9.1. A header is untrusted input.
//!
//! This module does not issue ioctl and does not pass a header to the kernel.
//! G-TUN is not passed.

pub const VIRTIO_HDR_LEN: usize = 10;

pub const GSO_NONE: u8 = 0;
pub const GSO_TCPV4: u8 = 1;
pub const GSO_UDP: u8 = 3;
pub const GSO_TCPV6: u8 = 4;
pub const GSO_UDP_L4: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioError {
    Truncated,
    UnknownGso,
    UsoDisabled,
    GsoSize,
    CsumRange,
    PacketShorterThanHeader,
}

/// USO stays off until a real device test exists.
pub const fn uso_enabled() -> bool {
    false
}

/// `IFF_VNET_HDR` support does not authorize every GSO type.
pub const fn vnet_hdr_allows_any_gso() -> bool {
    false
}

pub fn parse(bytes: &[u8], packet_len: usize) -> Result<VirtioHdr, VirtioError> {
    if bytes.len() < VIRTIO_HDR_LEN {
        return Err(VirtioError::Truncated);
    }
    let hdr = VirtioHdr {
        flags: bytes[0],
        gso_type: bytes[1],
        hdr_len: u16::from_le_bytes([bytes[2], bytes[3]]),
        gso_size: u16::from_le_bytes([bytes[4], bytes[5]]),
        csum_start: u16::from_le_bytes([bytes[6], bytes[7]]),
        csum_offset: u16::from_le_bytes([bytes[8], bytes[9]]),
    };
    check(hdr, packet_len)?;
    Ok(hdr)
}

pub fn check(hdr: VirtioHdr, packet_len: usize) -> Result<(), VirtioError> {
    if packet_len < usize::from(hdr.hdr_len) {
        return Err(VirtioError::PacketShorterThanHeader);
    }
    match hdr.gso_type {
        GSO_NONE => {
            if hdr.gso_size != 0 {
                return Err(VirtioError::GsoSize);
            }
        }
        GSO_TCPV4 | GSO_TCPV6 => {
            if hdr.gso_size < 1 || hdr.hdr_len < 20 {
                return Err(VirtioError::GsoSize);
            }
        }
        GSO_UDP | GSO_UDP_L4 => return Err(VirtioError::UsoDisabled),
        _ => return Err(VirtioError::UnknownGso),
    }
    if usize::from(hdr.csum_start) + usize::from(hdr.csum_offset) >= packet_len {
        return Err(VirtioError::CsumRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uso_and_unknown_types_are_rejected() {
        assert!(!uso_enabled());
        assert!(!vnet_hdr_allows_any_gso());
        let mut raw = [0u8; 10];
        raw[8] = 1;
        assert!(parse(&raw, 64).is_ok());
        raw[1] = GSO_UDP_L4;
        raw[4] = 1;
        raw[2] = 40;
        assert_eq!(parse(&raw, 128), Err(VirtioError::UsoDisabled));
        raw[1] = 9;
        assert_eq!(parse(&raw, 128), Err(VirtioError::UnknownGso));
        assert_eq!(parse(&raw[..9], 128), Err(VirtioError::Truncated));
    }
}
