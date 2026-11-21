//! Linux-only TUN device lifecycle and packet queues.
//! Unsafe code is confined to libc syscall ABI boundaries; this module manages no routes.
#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString},
    fs::OpenOptions,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{Arc, Mutex},
    time::Duration,
};

use super::{Error, InspectedPacket, MAX_IP_PACKET, PacketIo};
use crate::{gso::GsoError, virtio::VIRTIO_HDR_LEN};

mod gso_limits;
mod vnet;

const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_VNET_HDR: libc::c_short = 0x4000;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
const IFF_PERSIST: libc::c_short = 0x0800;
const IFF_TUN_EXCL: libc::c_short = 0x8000u16 as libc::c_short;
// ioctl request codes are stored as u32 and cast to libc::Ioctl at the call
// site: glibc defines Ioctl as c_ulong, musl as c_int, so a fixed-width
// c_ulong constant does not compile on musl targets.
const TUNSETIFF: u32 = 0x400454ca;
const TUNGETFEATURES: u32 = 0x800454cf;
const TUNGETIFF: u32 = 0x800454d2;
const TUNSETOFFLOAD: u32 = 0x400454d0;
const TUNGETVNETHDRSZ: u32 = 0x800454d7;
const TUNSETVNETLE: u32 = 0x400454dc;
const TUNGETVNETLE: u32 = 0x800454dd;
const TUN_F_CSUM_TSO4: libc::c_uint = 0x01 | 0x02;

#[repr(C)]
#[derive(Clone, Copy)]
union IfReqData {
    flags: libc::c_short,
    _raw: [u64; 3],
}
#[repr(C)]
#[derive(Clone, Copy)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    data: IfReqData,
}
impl IfReq {
    fn new(name: &CStr, flags: libc::c_short) -> Result<Self, LinuxTunError> {
        let bytes = name.to_bytes_with_nul();
        if bytes.len() > IFNAMSIZ {
            return Err(LinuxTunError::InvalidName);
        }
        let mut req = Self {
            name: [0; IFNAMSIZ],
            data: IfReqData { _raw: [0; 3] },
        };
        req.data.flags = flags;
        for (dst, src) in req.name.iter_mut().zip(bytes) {
            // cast_signed keeps this portable where c_char is u8 (aarch64)
            // without tripping unnecessary_cast where c_char is i8 (x86_64).
            *dst = (*src).cast_signed() as libc::c_char;
        }
        Ok(req)
    }
    fn actual_name(&self) -> Result<String, LinuxTunError> {
        let end = self
            .name
            .iter()
            .position(|c| *c == 0)
            .ok_or(LinuxTunError::InvalidInterface)?;
        String::from_utf8(
            self.name[..end]
                .iter()
                .map(|c| c.to_ne_bytes()[0])
                .collect(),
        )
        .map_err(|_| LinuxTunError::InvalidInterface)
    }
}

#[derive(Debug)]
pub enum LinuxTunError {
    Io(io::Error),
    InvalidName,
    InvalidInterface,
    InvalidConfiguration,
    WrongDevice,
    WrongFlags,
    DeviceNameMismatch,
    QueueConfiguration,
    Packet(Error),
    Gso(GsoError),
    PartialWrite,
}
impl std::fmt::Display for LinuxTunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for LinuxTunError {}
impl From<io::Error> for LinuxTunError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<Error> for LinuxTunError {
    fn from(e: Error) -> Self {
        Self::Packet(e)
    }
}

#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Optional interface name. None asks the kernel to allocate `boreas%d`.
    pub name: Option<String>,
    pub mtu: usize,
    pub multi_queue: bool,
    /// Explicitly enable Linux local TCPv4 GSO and its 10-byte VNET framing.
    /// Requires a single-queue device created by Boreas; defaults to false.
    pub vnet_header: bool,
}
impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: 1500,
            multi_queue: false,
            vnet_header: false,
        }
    }
}

/// Device state and queue-zero management descriptor. All queues are owned fds and non-persistent.
pub struct LinuxTunDevice {
    name: String,
    flags: libc::c_short,
    mtu: usize,
    management: Mutex<OwnedFd>,
}
impl LinuxTunDevice {
    /// Create a real TUN device with `TUNSETIFF`, verify it with `TUNGETIFF`, set MTU and configure
    /// either no offloads (default) or the bounded TCPv4-only profile. Closing all queue and manager descriptors releases this non-persistent fd.
    pub fn create(config: TunConfig) -> Result<(Arc<Self>, LinuxTunQueue), LinuxTunError> {
        if !(68..=MAX_IP_PACKET).contains(&config.mtu) || (config.vnet_header && config.multi_queue)
        {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        let requested = match config.name {
            Some(s) => {
                if s.is_empty() || s.len() >= IFNAMSIZ || s.bytes().any(|b| b == b'/' || b == 0) {
                    return Err(LinuxTunError::InvalidName);
                }
                CString::new(s).map_err(|_| LinuxTunError::InvalidName)?
            }
            None => CString::new("boreas%d").expect("static name has no NUL"),
        };
        let flags = IFF_TUN
            | IFF_NO_PI
            | if config.multi_queue {
                IFF_MULTI_QUEUE
            } else {
                0
            }
            | if config.vnet_header { IFF_VNET_HDR } else { 0 };
        let fd = open_tun()?;
        if config.vnet_header {
            let mut features = 0u32;
            ioctl_word(fd.as_raw_fd(), TUNGETFEATURES, &mut features)?;
            if features & u32::from(flags.cast_unsigned()) != u32::from(flags.cast_unsigned()) {
                return Err(LinuxTunError::WrongFlags);
            }
        }
        let mut req = IfReq::new(&requested, flags | IFF_TUN_EXCL)?;
        ioctl_ifreq(fd.as_raw_fd(), TUNSETIFF, &mut req)?;
        let actual = req.actual_name()?;
        let actual_flags = verify_fd(fd.as_raw_fd(), &actual, flags)?;
        set_mtu_sysfs(&actual, config.mtu)?;
        if config.vnet_header {
            verify_vnet_abi(fd.as_raw_fd(), true)?;
            gso_limits::configure(&actual)?;
            ioctl_scalar(fd.as_raw_fd(), TUNSETOFFLOAD, TUN_F_CSUM_TSO4)?;
        } else {
            ioctl_scalar(fd.as_raw_fd(), TUNSETOFFLOAD, 0)?;
        }
        let manager = Arc::new(Self {
            name: actual,
            flags: actual_flags,
            mtu: config.mtu,
            management: Mutex::new(fd),
        });
        let queue_fd = manager
            .management
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?
            .try_clone()?;
        let queue = LinuxTunQueue {
            device: manager.clone(),
            state: Mutex::new(QueueState {
                fd: queue_fd,
                vnet: config.vnet_header.then(|| vnet::Reader::new(config.mtu)),
            }),
        };
        Ok((manager, queue))
    }
    /// Attach one queue to an administrator-provisioned persistent TUN. This
    /// path never changes interface MTU, addresses, persistence or routes.
    /// The verified service runs without CAP_NET_ADMIN: TUNSETIFF therefore
    /// cannot create an interface and the kernel enforces the owner binding.
    pub fn open_provisioned(
        name: &str,
        mtu: usize,
    ) -> Result<(Arc<Self>, LinuxTunQueue), LinuxTunError> {
        if !(68..=MAX_IP_PACKET).contains(&mtu)
            || name.is_empty()
            || name.len() >= IFNAMSIZ
            || matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        // SAFETY: geteuid reads only this process's credentials.
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        let ifname = CString::new(name).map_err(|_| LinuxTunError::InvalidName)?;
        let flags = IFF_TUN | IFF_NO_PI | IFF_PERSIST;
        let configured_mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))?;
        let owner = std::fs::read_to_string(format!("/sys/class/net/{name}/owner"))?;
        let link_flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))?;
        let tun_flags = std::fs::read_to_string(format!("/sys/class/net/{name}/tun_flags"))?;
        let parse_hex = |s: &str| {
            s.trim()
                .strip_prefix("0x")
                .and_then(|v| u32::from_str_radix(v, 16).ok())
        };
        if configured_mtu.trim().parse::<usize>().ok() != Some(mtu)
            || owner.trim().parse::<u32>().ok() != Some(uid)
            // TUNGETIFF can OR IFF_NOFILTER into the IFF_NO_PI bit. Check
            // the underlying device flags separately before attaching.
            || parse_hex(&tun_flags) != Some(flags as u32)
            || !parse_hex(&link_flags).is_some_and(|v| v & libc::IFF_UP as u32 != 0)
        {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        let fd = open_tun()?;
        let mut req = IfReq::new(&ifname, IFF_TUN | IFF_NO_PI)?;
        ioctl_ifreq(fd.as_raw_fd(), TUNSETIFF, &mut req)?;
        verify_fd(fd.as_raw_fd(), name, flags)?;
        ioctl_scalar(fd.as_raw_fd(), TUNSETOFFLOAD, 0)?;
        let queue_fd = fd.try_clone()?;
        let device = Arc::new(Self {
            name: name.to_owned(),
            flags,
            mtu,
            management: Mutex::new(fd),
        });
        let queue = LinuxTunQueue {
            device: Arc::clone(&device),
            state: Mutex::new(QueueState {
                fd: queue_fd,
                vnet: None,
            }),
        };
        Ok((device, queue))
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn mtu(&self) -> usize {
        self.mtu
    }
    /// Offload mode is frozen at creation. Only a raw device can reaffirm disabled offloads.
    pub fn set_offloads(&self, flags: libc::c_uint) -> Result<(), LinuxTunError> {
        if flags != 0 || self.flags & IFF_VNET_HDR != 0 {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        let fd = self
            .management
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        ioctl_scalar(fd.as_raw_fd(), TUNSETOFFLOAD, 0)
    }
    /// Attach another fd to the same device, only if the device was created multi-queue.
    pub fn attach_queue(self: &Arc<Self>) -> Result<LinuxTunQueue, LinuxTunError> {
        if self.flags & IFF_MULTI_QUEUE == 0 {
            return Err(LinuxTunError::InvalidConfiguration);
        }
        let fd = open_tun()?;
        let name = CString::new(self.name.clone()).map_err(|_| LinuxTunError::InvalidName)?;
        let mut req = IfReq::new(&name, self.flags)?;
        ioctl_ifreq(fd.as_raw_fd(), TUNSETIFF, &mut req)?;
        verify_fd(fd.as_raw_fd(), &self.name, self.flags)?;
        Ok(LinuxTunQueue {
            device: self.clone(),
            state: Mutex::new(QueueState { fd, vnet: None }),
        })
    }
}

/// One verified owned Linux TUN queue. Each API read/write transfers one L3 packet.
/// On TCPv4 GSO queues pending segments are drained in order before reading the fd again.
/// `PacketIo::read_packet` blocks until a packet or fd error; event-loop users should prefer
/// `read_packet_timeout` to integrate bounded polling.
pub struct LinuxTunQueue {
    device: Arc<LinuxTunDevice>,
    state: Mutex<QueueState>,
}

struct QueueState {
    fd: OwnedFd,
    vnet: Option<vnet::Reader>,
}
impl LinuxTunQueue {
    pub fn device_name(&self) -> &str {
        self.device.name()
    }
    pub fn mtu(&self) -> usize {
        self.device.mtu
    }
    /// Borrow the stable queue descriptor for an external event set. The queue
    /// remains owned here; callers must not close or mutate the returned fd.
    pub fn as_raw_fd(&self) -> RawFd {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.fd.as_raw_fd()
    }
    pub fn verify(&self) -> Result<(), LinuxTunError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        let fd = state.fd.as_raw_fd();
        verify_fd(fd, &self.device.name, self.device.flags)?;
        if state.vnet.is_some() {
            verify_vnet_abi(fd, false)?;
        }
        Ok(())
    }
    pub fn read_packet(&self) -> Result<Option<Vec<u8>>, LinuxTunError> {
        self.read_owned(None, false)
    }
    pub fn read_packet_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>, LinuxTunError> {
        self.read_owned(Some(timeout), false)
    }
    fn read_owned(
        &self,
        timeout: Option<Duration>,
        allow_empty: bool,
    ) -> Result<Option<Vec<u8>>, LinuxTunError> {
        let mut packet = vec![0; self.mtu() + 1];
        let Some(inspected) = self.read_into(&mut packet, timeout, allow_empty)? else {
            return Ok(None);
        };
        let len = inspected.bytes().len();
        packet.truncate(len);
        Ok(Some(packet))
    }
    /// VNET diagnostics: actual attempted read syscalls and delivered GSO segments.
    pub fn gso_read_counts(&self) -> Option<(u64, u64)> {
        self.state
            .lock()
            .ok()?
            .vnet
            .as_ref()
            .map(vnet::Reader::read_counts)
    }
    /// Configure `O_NONBLOCK` on this queue descriptor.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), LinuxTunError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        let fd = state.fd.as_raw_fd();
        // SAFETY: `fd` is an owned TUN queue descriptor; `F_GETFL`/`F_SETFL`
        // only update the descriptor's `O_NONBLOCK` status flag.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let next = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if next != flags {
            let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, next) };
            if rc < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    /// Non-blocking read (at most one syscall) with `O_NONBLOCK` enabled.
    pub fn try_read_packet(&self) -> Result<Option<Vec<u8>>, LinuxTunError> {
        self.read_owned(None, true)
    }
    /// Non-blocking read into caller-owned storage when `O_NONBLOCK` is enabled.
    /// Storage shorter than MTU + 1 is rejected before reading. The extra
    /// byte distinguishes an exact-MTU packet from a truncated oversized read;
    /// returned packets never exceed the device MTU.
    pub fn try_read_packet_into<'buf>(
        &self,
        scratch: &'buf mut [u8],
    ) -> Result<Option<&'buf [u8]>, LinuxTunError> {
        self.try_read_inspected_into(scratch)
            .map(|packet| packet.map(InspectedPacket::bytes))
    }

    /// As [`Self::try_read_packet_into`], retaining structural validation.
    pub fn try_read_inspected_into<'buf>(
        &self,
        scratch: &'buf mut [u8],
    ) -> Result<Option<InspectedPacket<'buf>>, LinuxTunError> {
        self.read_into(scratch, None, true)
    }

    fn read_into<'buf>(
        &self,
        scratch: &'buf mut [u8],
        timeout: Option<Duration>,
        allow_empty: bool,
    ) -> Result<Option<InspectedPacket<'buf>>, LinuxTunError> {
        let buf = scratch
            .get_mut(..self.mtu() + 1)
            .ok_or(LinuxTunError::InvalidConfiguration)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        let fd = state.fd.as_raw_fd();
        if let Some(reader) = &mut state.vnet {
            if !reader.has_pending() && !read_ready(fd, timeout)? {
                return Ok(None);
            }
            return reader.read(fd, self.mtu(), buf, allow_empty);
        }
        if !read_ready(fd, timeout)? {
            return Ok(None);
        }
        let n = match read_fd(fd, buf) {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(LinuxTunError::Io(err))
                if allow_empty && err.kind() == io::ErrorKind::WouldBlock =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        inspect_at_mtu(&buf[..n], self.mtu()).map(Some)
    }
    pub fn write_packet(&self, packet: &[u8]) -> Result<(), LinuxTunError> {
        let packet = inspect_at_mtu(packet, self.mtu())?;
        self.write_checked_bytes(packet.bytes())
    }

    /// The immutable proof reuses parsing, not the local device MTU check.
    pub fn write_inspected_packet(&self, packet: InspectedPacket<'_>) -> Result<(), LinuxTunError> {
        let bytes = packet.bytes();
        check_mtu(bytes, self.mtu())?;
        self.write_checked_bytes(bytes)
    }

    fn write_checked_bytes(&self, packet: &[u8]) -> Result<(), LinuxTunError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        let fd = state.fd.as_raw_fd();
        let (n, expected) = if state.vnet.is_some() {
            (write_vnet_fd(fd, packet)?, packet.len() + VIRTIO_HDR_LEN)
        } else {
            (write_fd(fd, packet)?, packet.len())
        };
        if n != expected {
            return Err(LinuxTunError::PartialWrite);
        }
        Ok(())
    }
}
impl PacketIo for LinuxTunQueue {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, Error> {
        LinuxTunQueue::read_packet(self).map_err(queue_error)
    }
    fn write_packet(&self, p: &[u8]) -> Result<(), Error> {
        LinuxTunQueue::write_packet(self, p).map_err(queue_error)
    }

    fn write_inspected_packet(&self, p: InspectedPacket<'_>) -> Result<(), Error> {
        LinuxTunQueue::write_inspected_packet(self, p).map_err(queue_error)
    }
}

fn queue_error(error: LinuxTunError) -> Error {
    match error {
        LinuxTunError::Packet(p) => p,
        LinuxTunError::Gso(_) => Error::VirtioInvalid,
        _ => Error::QueueClosed,
    }
}

fn check_mtu(packet: &[u8], mtu: usize) -> Result<(), LinuxTunError> {
    if packet.len() > mtu {
        return Err(LinuxTunError::Packet(Error::PacketTooLarge { mtu }));
    }
    Ok(())
}

fn inspect_at_mtu(packet: &[u8], mtu: usize) -> Result<InspectedPacket<'_>, LinuxTunError> {
    check_mtu(packet, mtu)?;
    InspectedPacket::new(packet).map_err(LinuxTunError::Packet)
}

fn set_mtu_sysfs(name: &str, mtu: usize) -> Result<(), LinuxTunError> {
    let path = format!("/sys/class/net/{name}/mtu");
    let mut f = OpenOptions::new().write(true).open(path)?;
    write!(f, "{mtu}")?;
    Ok(())
}
fn open_tun() -> Result<OwnedFd, LinuxTunError> {
    let path = CString::new("/dev/net/tun").expect("static path has no NUL");
    // SAFETY: valid NUL-terminated path; successful open returns a fresh exclusively owned fd.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: fd is the unique descriptor just returned by open.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn ioctl_ifreq(fd: RawFd, request: u32, req: &mut IfReq) -> Result<(), LinuxTunError> {
    // SAFETY: req is a fully initialized Linux repr(C) ifreq-compatible object, writable for this call.
    let r = unsafe { libc::ioctl(fd, request as libc::Ioctl, req as *mut IfReq) };
    if r < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn ioctl_scalar(fd: RawFd, request: u32, value: libc::c_uint) -> Result<(), LinuxTunError> {
    // SAFETY: TUNSETOFFLOAD takes an unsigned long scalar bitmask as confirmed by Linux tun.c.
    let r = unsafe { libc::ioctl(fd, request as libc::Ioctl, value as libc::c_ulong) };
    if r < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn verify_fd(
    fd: RawFd,
    expected: &str,
    flags: libc::c_short,
) -> Result<libc::c_short, LinuxTunError> {
    let c = CString::new(expected).map_err(|_| LinuxTunError::InvalidName)?;
    let mut req = IfReq::new(&c, 0)?;
    ioctl_ifreq(fd, TUNGETIFF, &mut req)?;
    if req.actual_name()? != expected {
        return Err(LinuxTunError::DeviceNameMismatch);
    }
    // SAFETY: successful TUNGETIFF initializes the active ifreq flags union member.
    let got = unsafe { req.data.flags };
    if got & 0x0003 != IFF_TUN {
        return Err(LinuxTunError::WrongDevice);
    }
    let required = IFF_TUN | IFF_NO_PI | (flags & (IFF_MULTI_QUEUE | IFF_PERSIST | IFF_VNET_HDR));
    if got != required {
        return Err(LinuxTunError::WrongFlags);
    }
    Ok(got)
}
fn ioctl_word(fd: RawFd, request: u32, word: &mut u32) -> Result<(), LinuxTunError> {
    // SAFETY: these UAPI pointer ioctls read or write exactly one aligned 32-bit word.
    let r = unsafe { libc::ioctl(fd, request as libc::Ioctl, std::ptr::from_mut(word)) };
    if r < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn verify_vnet_abi(fd: RawFd, set_le: bool) -> Result<(), LinuxTunError> {
    let mut size = 0;
    ioctl_word(fd, TUNGETVNETHDRSZ, &mut size)?;
    if size as usize != VIRTIO_HDR_LEN {
        return Err(LinuxTunError::WrongFlags);
    }
    if set_le {
        ioctl_word(fd, TUNSETVNETLE, &mut 1)?;
    }
    let mut le = 0;
    ioctl_word(fd, TUNGETVNETLE, &mut le)?;
    if le != 1 {
        return Err(LinuxTunError::WrongFlags);
    }
    Ok(())
}
fn read_ready(fd: RawFd, timeout: Option<Duration>) -> Result<bool, LinuxTunError> {
    match timeout {
        Some(timeout) => poll_readable(fd, timeout),
        None => Ok(true),
    }
}
fn poll_readable(fd: RawFd, timeout: Duration) -> Result<bool, LinuxTunError> {
    let ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: p is one valid pollfd, writable for the duration of poll.
    let r = unsafe { libc::poll(&mut p, 1, ms) };
    if r < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(r > 0 && p.revents & libc::POLLIN != 0)
}
fn read_fd(fd: RawFd, b: &mut [u8]) -> Result<usize, LinuxTunError> {
    // SAFETY: b is writable for its length; fd is an owned queue verified by TUNGETIFF.
    let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), b.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(n as usize)
}
fn write_fd(fd: RawFd, b: &[u8]) -> Result<usize, LinuxTunError> {
    // SAFETY: b is readable for its length; fd is an owned queue verified by TUNGETIFF.
    let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(n as usize)
}

fn write_vnet_fd(fd: RawFd, packet: &[u8]) -> Result<usize, LinuxTunError> {
    let header = [0u8; VIRTIO_HDR_LEN];
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        },
    ];
    // SAFETY: two initialized iovecs point to immutable readable storage for
    // this one writev. Linux TUN consumes them as a single record.
    let n = unsafe { libc::writev(fd, iov.as_ptr(), 2) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn nonblocking_read_reuses_storage_at_device_mtu() {
        const MTU: usize = 68;
        // A datagram socket preserves packet boundaries and exercises the real
        // read syscall without requiring /dev/net/tun or CAP_NET_ADMIN.
        let (tx, rx) = UnixDatagram::pair().unwrap();
        let queue = LinuxTunQueue {
            device: Arc::new(LinuxTunDevice {
                name: String::new(),
                flags: IFF_TUN | IFF_NO_PI,
                mtu: MTU,
                management: Mutex::new(rx.try_clone().unwrap().into()),
            }),
            state: Mutex::new(QueueState {
                fd: rx.into(),
                vnet: None,
            }),
        };
        queue.set_nonblocking(true).unwrap();
        let mut scratch = [0xa5; MTU + 1];
        let address = scratch.as_ptr();
        assert!(queue.try_read_packet_into(&mut scratch).unwrap().is_none());

        let mut big = [0u8; MTU];
        big[0] = 0x60;
        big[4..6].copy_from_slice(&((MTU - 40) as u16).to_be_bytes());
        // Use an ICMPv6 payload type; No Next Header (59) requires no bytes.
        big[6] = 58;
        tx.send(&big).unwrap();
        assert!(matches!(
            queue.try_read_packet_into(&mut scratch[..MTU - 1]),
            Err(LinuxTunError::InvalidConfiguration)
        ));
        let inspected = queue
            .try_read_inspected_into(&mut scratch)
            .unwrap()
            .unwrap();
        assert_eq!(inspected.bytes().as_ptr(), address);
        assert_eq!(inspected.bytes(), big.as_slice());
        assert_eq!(inspected.info().version, crate::IpVersion::V6);
        assert_eq!(inspected.info().packet_len, MTU);
        queue.write_inspected_packet(inspected).unwrap();
        assert_eq!(scratch[MTU], 0xa5);
        let mut received = [0; MTU + 1];
        tx.set_nonblocking(true).unwrap();
        let n = tx.recv(&mut received).unwrap();
        assert_eq!(&received[..n], big.as_slice());

        let mut one_over_mtu = [0; MTU + 1];
        one_over_mtu[..MTU].copy_from_slice(&big);
        one_over_mtu[4..6].copy_from_slice(&((MTU + 1 - 40) as u16).to_be_bytes());
        assert!(matches!(
            queue.write_inspected_packet(InspectedPacket::new(&one_over_mtu).unwrap()),
            Err(LinuxTunError::Packet(Error::PacketTooLarge { mtu: MTU }))
        ));
        assert_eq!(
            tx.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "over-MTU proof must not reach the device"
        );

        let mut small = [0u8; 40];
        small[0] = 0x60;
        small[6] = 59;
        tx.send(&small).unwrap();
        let packet = queue.try_read_packet_into(&mut scratch).unwrap().unwrap();
        assert_eq!(packet.as_ptr(), address);
        assert_eq!(packet, small.as_slice());
        assert!(queue.try_read_packet_into(&mut scratch).unwrap().is_none());
        tx.send(&[]).unwrap();
        assert!(queue.try_read_packet_into(&mut scratch).unwrap().is_none());

        // The guard byte catches both a one-byte overflow and a truncated
        // longer read. An exact-MTU packet still fits in the same scratch.
        let mut oversized = [0u8; MTU + 2];
        oversized[..MTU].copy_from_slice(&big);
        for bytes in [&oversized[..MTU + 1], oversized.as_slice()] {
            tx.send(bytes).unwrap();
            assert!(matches!(
                queue.try_read_packet_into(&mut scratch),
                Err(LinuxTunError::Packet(Error::PacketTooLarge { mtu: MTU }))
            ));
        }
        tx.send(&big).unwrap();
        assert_eq!(queue.try_read_packet().unwrap(), Some(big.to_vec()));
        tx.send(&oversized).unwrap();
        assert!(matches!(
            queue.read_packet(),
            Err(LinuxTunError::Packet(Error::PacketTooLarge { mtu: MTU }))
        ));
    }
}
