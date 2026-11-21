//! Startup-only rtnetlink on a newly created, non-persistent TUN.
#![allow(unsafe_code)]

use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::gso::MAX_SEGMENTS;

// Linux UAPI if_link.h. Leave ample headroom for up to 64 copied headers
// within MAX_OUTPUT_BYTES, even for short MSS and long TCP headers.
const LIMIT: u32 = 48_000;
const MAX_SEGS: u32 = MAX_SEGMENTS as u32;
const GSO_MAX_SEGS: u16 = 40;
const GSO_MAX_SIZE: u16 = 41;
const GSO_IPV4_MAX_SIZE: u16 = 63;
const NL_HDR: usize = 16;
const IFINFO_END: usize = NL_HDR + 16;
const LIMITS: [(u16, u32); 3] = [
    (GSO_MAX_SEGS, MAX_SEGS),
    (GSO_MAX_SIZE, LIMIT),
    (GSO_IPV4_MAX_SIZE, LIMIT),
];

pub(super) fn configure(name: &str) -> io::Result<()> {
    let name = CString::new(name).map_err(|_| invalid())?;
    // SAFETY: name is NUL-terminated and this lookup holds no references.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket returns a new owned descriptor; no multicast
    // groups are bound and connection below targets the kernel route socket.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: newly returned descriptor is exclusively owned; zero is valid
    // for sockaddr_nl (integer fields including padding).
    let (fd, mut kernel) = unsafe {
        (
            OwnedFd::from_raw_fd(fd),
            std::mem::zeroed::<libc::sockaddr_nl>(),
        )
    };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let addr_len = std::mem::size_of_val(&kernel) as libc::socklen_t;
    // SAFETY: kernel is initialized and lives through connect.
    if unsafe { libc::connect(fd.as_raw_fd(), std::ptr::from_ref(&kernel).cast(), addr_len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = [0; 8192];
    let mut set = [0; IFINFO_END + 8 * LIMITS.len()];
    header(
        &mut set,
        libc::RTM_SETLINK,
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        1,
        index,
    );
    for (attr, (kind, value)) in set[IFINFO_END..].chunks_exact_mut(8).zip(LIMITS) {
        attr[..2].copy_from_slice(&8u16.to_ne_bytes());
        attr[2..4].copy_from_slice(&kind.to_ne_bytes());
        attr[4..8].copy_from_slice(&value.to_ne_bytes());
    }
    let ack = exchange(&fd, &set, &mut buf, 1)?;
    if word16(ack, 4) != libc::NLMSG_ERROR as u16 || ack.len() < NL_HDR + 4 {
        return Err(invalid());
    }
    let error = i32::from_ne_bytes(ack[NL_HDR..NL_HDR + 4].try_into().unwrap());
    if error != 0 {
        return Err(error
            .checked_neg()
            .filter(|e| *e > 0)
            .map_or_else(invalid, io::Error::from_raw_os_error));
    }

    // Older kernels can silently ignore unknown attributes even with a
    // successful SETLINK acknowledgement. Require the effective readback.
    let mut get = [0; IFINFO_END];
    header(
        &mut get,
        libc::RTM_GETLINK,
        libc::NLM_F_REQUEST as u16,
        2,
        index,
    );
    let reply = exchange(&fd, &get, &mut buf, 2)?;
    if word16(reply, 4) != libc::RTM_NEWLINK
        || reply.len() < IFINFO_END
        || word32(reply, 20) != index
    {
        return Err(invalid());
    }
    let mut attrs = &reply[IFINFO_END..];
    let mut seen = [false; LIMITS.len()];
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(invalid());
        }
        let len = usize::from(word16(attrs, 0));
        if len < 4 || len.next_multiple_of(4) > attrs.len() {
            return Err(invalid());
        }
        if let Some(i) = LIMITS
            .iter()
            .position(|&(kind, _)| word16(attrs, 2) == kind)
        {
            if seen[i] || len != 8 || word32(attrs, 4) != LIMITS[i].1 {
                return Err(invalid());
            }
            seen[i] = true;
        }
        attrs = &attrs[len.next_multiple_of(4)..];
    }
    if seen.into_iter().all(|v| v) {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn header(buf: &mut [u8], kind: u16, flags: u16, seq: u32, index: u32) {
    let len = buf.len() as u32;
    buf[..4].copy_from_slice(&len.to_ne_bytes());
    buf[4..6].copy_from_slice(&kind.to_ne_bytes());
    buf[6..8].copy_from_slice(&flags.to_ne_bytes());
    buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    buf[20..24].copy_from_slice(&index.to_ne_bytes());
}

fn exchange<'a>(fd: &OwnedFd, msg: &[u8], buf: &'a mut [u8], seq: u32) -> io::Result<&'a [u8]> {
    let raw = fd.as_raw_fd();
    // SAFETY: msg is readable; fd is an owned, connected netlink socket.
    let sent = unsafe { libc::send(raw, msg.as_ptr().cast(), msg.len(), libc::MSG_DONTWAIT) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != msg.len() {
        return Err(invalid());
    }
    let mut poll = libc::pollfd {
        fd: raw,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized writable descriptor; startup wait is bounded.
    let ready = unsafe { libc::poll(&mut poll, 1, 1000) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    if ready == 0 {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if poll.revents != libc::POLLIN {
        return Err(invalid());
    }

    // SAFETY: buf is writable; sender and length point to writable storage.
    // MSG_TRUNC reports the full datagram length; never parse a truncated one.
    let mut source = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    let mut source_len = std::mem::size_of_val(&source) as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            raw,
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            std::ptr::from_mut(&mut source).cast(),
            &mut source_len,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = n as usize;
    if source_len as usize != std::mem::size_of_val(&source)
        || source.nl_pid != 0
        || source.nl_groups != 0
        || !(NL_HDR..=buf.len()).contains(&len)
        || word32(buf, 0) as usize != len
        || word32(buf, 8) != seq
    {
        return Err(invalid());
    }
    Ok(&buf[..len])
}

fn word16(b: &[u8], pos: usize) -> u16 {
    u16::from_ne_bytes(b[pos..pos + 2].try_into().unwrap())
}
fn word32(b: &[u8], pos: usize) -> u32 {
    u32::from_ne_bytes(b[pos..pos + 4].try_into().unwrap())
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Linux TUN GSO limits were not verified",
    )
}
