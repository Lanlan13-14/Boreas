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

use super::{Error, InspectedPacket, MAX_IP_PACKET, PacketIo, PacketRead};

const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
const IFF_TUN_EXCL: libc::c_short = 0x8000u16 as libc::c_short;
// ioctl request codes are stored as u32 and cast to libc::Ioctl at the call
// site: glibc defines Ioctl as c_ulong, musl as c_int, so a fixed-width
// c_ulong constant does not compile on musl targets.
const TUNSETIFF: u32 = 0x400454ca;
const TUNGETIFF: u32 = 0x800454d2;
const TUNSETOFFLOAD: u32 = 0x400454d0;

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
    /// Unsupported until the complete VNET header/offload path exists; true is rejected.
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
    /// Create a real TUN device with `TUNSETIFF`, verify it with `TUNGETIFF`, set MTU and disable
    /// device offloads. Closing all queue and manager descriptors releases this non-persistent fd.
    pub fn create(config: TunConfig) -> Result<(Arc<Self>, LinuxTunQueue), LinuxTunError> {
        if !(68..=MAX_IP_PACKET).contains(&config.mtu) || config.vnet_header {
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
            };
        let fd = open_tun()?;
        let mut req = IfReq::new(&requested, flags | IFF_TUN_EXCL)?;
        ioctl_ifreq(fd.as_raw_fd(), TUNSETIFF, &mut req)?;
        let actual = req.actual_name()?;
        let actual_flags = verify_fd(fd.as_raw_fd(), &actual, flags)?;
        set_mtu_sysfs(&actual, config.mtu)?;
        // Linux TUNSETOFFLOAD takes the scalar bitmask in the ioctl argument, not a pointer.
        ioctl_scalar(fd.as_raw_fd(), TUNSETOFFLOAD, 0)?;
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
            fd: Mutex::new(queue_fd),
        };
        Ok((manager, queue))
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn mtu(&self) -> usize {
        self.mtu
    }
    /// Only disabled offloads are currently permitted, managed through the unique queue-zero owner.
    pub fn set_offloads(&self, flags: libc::c_uint) -> Result<(), LinuxTunError> {
        if flags != 0 {
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
            fd: Mutex::new(fd),
        })
    }
}

/// One verified owned Linux TUN queue. Each read/write transfers one L3 packet.
/// `PacketIo::read_packet` blocks until a packet or fd error; event-loop users should prefer
/// `read_packet_timeout` to integrate bounded polling.
pub struct LinuxTunQueue {
    device: Arc<LinuxTunDevice>,
    fd: Mutex<OwnedFd>,
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
        let fd = self
            .fd
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fd.as_raw_fd()
    }
    pub fn verify(&self) -> Result<(), LinuxTunError> {
        let fd = self
            .fd
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        verify_fd(fd.as_raw_fd(), &self.device.name, self.device.flags).map(|_| ())
    }
    pub fn read_packet(&self) -> Result<Option<Vec<u8>>, LinuxTunError> {
        let fd = self
            .fd
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        read_packet_fd(fd.as_raw_fd(), self.device.mtu)
    }
    pub fn read_packet_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>, LinuxTunError> {
        let fd = self
            .fd
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        if !poll_readable(fd.as_raw_fd(), timeout)? {
            return Ok(None);
        }
        read_packet_fd(fd.as_raw_fd(), self.device.mtu)
    }
    /// Configure `O_NONBLOCK` on this queue descriptor.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), LinuxTunError> {
        let fd = self
            .fd
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        // SAFETY: `fd` is an owned TUN queue descriptor; `F_GETFL`/`F_SETFL`
        // only update the descriptor's `O_NONBLOCK` status flag.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let next = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if next != flags {
            let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, next) };
            if rc < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    /// Non-blocking single-syscall read when `O_NONBLOCK` is enabled on the queue.
    pub fn try_read_packet(&self) -> Result<Option<Vec<u8>>, LinuxTunError> {
        let mut packet = vec![0; self.mtu() + 1];
        let len = match self.try_read_packet_into(&mut packet)? {
            Some(bytes) => bytes.len(),
            None => return Ok(None),
        };
        packet.truncate(len);
        Ok(Some(packet))
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
        let buf = scratch
            .get_mut(..self.mtu() + 1)
            .ok_or(LinuxTunError::InvalidConfiguration)?;
        let fd = self
            .fd
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        let n = match read_fd(fd.as_raw_fd(), buf) {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(LinuxTunError::Io(err)) if err.kind() == io::ErrorKind::WouldBlock => {
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
        let fd = self
            .fd
            .lock()
            .map_err(|_| LinuxTunError::QueueConfiguration)?;
        let n = write_fd(fd.as_raw_fd(), packet)?;
        if n != packet.len() {
            return Err(LinuxTunError::PartialWrite);
        }
        Ok(())
    }
}
impl PacketIo for LinuxTunQueue {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, Error> {
        LinuxTunQueue::read_packet(self).map_err(|e| match e {
            LinuxTunError::Packet(p) => p,
            _ => Error::QueueClosed,
        })
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
        _ => Error::QueueClosed,
    }
}

fn read_packet_fd(fd: RawFd, mtu: usize) -> Result<Option<Vec<u8>>, LinuxTunError> {
    let mut b = vec![0; mtu + 1];
    let n = read_fd(fd, &mut b)?;
    if n == 0 {
        return Ok(None);
    }
    b.truncate(n);
    inspect_at_mtu(&b, mtu)?;
    Ok(Some(b))
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
    let required = IFF_TUN | IFF_NO_PI | (flags & IFF_MULTI_QUEUE);
    if got != required {
        return Err(LinuxTunError::WrongFlags);
    }
    Ok(got)
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
            fd: Mutex::new(rx.into()),
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
        let packet = queue.try_read_packet_into(&mut scratch).unwrap().unwrap();
        assert_eq!(packet.as_ptr(), address);
        assert_eq!(packet, big.as_slice());
        assert_eq!(scratch[MTU], 0xa5);

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
