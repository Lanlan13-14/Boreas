//! macOS-only utun control-socket adapter and packet queues.
//!
//! macOS utun is a `PF_SYSTEM`/`SYSPROTO_CONTROL` socket rather than a
//! character device. Each packet carries a four-byte network-order address
//! family header. This module manages only its own utun interface and MTU; it
//! installs no routes or addresses. Unsafe code is confined to libc FFI.
#![allow(unsafe_code)]

use std::{
    fmt, io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Mutex,
    time::{Duration, Instant},
};

use super::{Error, MAX_IP_PACKET, PacketIo, inspect_packet};

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
const UTUN_HEADER_LEN: usize = 4;
const UTUN_NAME_BUFFER: usize = 64;
const MIN_MTU: usize = 1280;
const AF_INET_HEADER: u32 = libc::AF_INET as u32;
const AF_INET6_HEADER: u32 = libc::AF_INET6 as u32;

#[derive(Clone, Debug)]
pub struct UtunConfig {
    /// `None` or `"utun"` lets the kernel choose an unused unit; `"utunN"`
    /// requests that exact unit.
    pub name: Option<String>,
    /// Interface MTU, applied through SIOCSIFMTU.
    pub mtu: usize,
}

impl Default for UtunConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: 1500,
        }
    }
}

impl UtunConfig {
    pub fn validate(&self) -> Result<(), UtunError> {
        if !(MIN_MTU..=MAX_IP_PACKET).contains(&self.mtu) {
            return Err(UtunError::InvalidConfiguration(
                "mtu must be between 1280 and 65535",
            ));
        }
        unit_for(self.name.as_deref())?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum UtunError {
    Io(io::Error),
    PermissionDenied,
    InvalidName,
    InvalidConfiguration(&'static str),
    DeviceNameMismatch {
        expected: String,
        actual: String,
    },
    MtuMismatch {
        expected: usize,
        actual: libc::c_int,
    },
    TruncatedFamilyHeader,
    UnsupportedFamily(u32),
    Poisoned,
    WriteZero,
    PartialWrite {
        expected: usize,
        actual: usize,
    },
    Packet(Error),
}

impl fmt::Display for UtunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::PermissionDenied => formatter
                .write_str("utun creation requires root or the utun control-socket privilege"),
            Self::InvalidName => formatter.write_str("invalid utun name; expected utun or utunN"),
            Self::InvalidConfiguration(reason) => {
                write!(formatter, "invalid configuration: {reason}")
            }
            Self::DeviceNameMismatch { expected, actual } => write!(
                formatter,
                "utun name mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::MtuMismatch { expected, actual } => {
                write!(formatter, "MTU mismatch: expected {expected}, got {actual}")
            }
            Self::TruncatedFamilyHeader => {
                formatter.write_str("utun packet is missing its four-byte family header")
            }
            Self::UnsupportedFamily(family) => {
                write!(formatter, "unsupported utun address family {family}")
            }
            Self::Poisoned => formatter.write_str("utun read lock is poisoned"),
            Self::WriteZero => formatter.write_str("utun write returned zero bytes"),
            Self::PartialWrite { expected, actual } => write!(
                formatter,
                "utun datagram write was partial: expected {expected} bytes, wrote {actual}"
            ),
            Self::Packet(error) => write!(formatter, "packet error: {error}"),
        }
    }
}

impl std::error::Error for UtunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Packet(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for UtunError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Error> for UtunError {
    fn from(error: Error) -> Self {
        Self::Packet(error)
    }
}

pub struct UtunDevice {
    fd: OwnedFd,
    name: String,
    mtu: usize,
    read_lock: Mutex<()>,
}

impl UtunDevice {
    /// Create a real utun interface from an `AF_SYSTEM` control socket. The
    /// interface disappears when this descriptor is closed, so no persistent
    /// device is created.
    pub fn create(config: UtunConfig) -> Result<Self, UtunError> {
        config.validate()?;
        let unit = unit_for(config.name.as_deref())?;
        let fd = open_control_socket()?;
        let mut info: libc::ctl_info = unsafe { mem::zeroed() };
        copy_control_name(&mut info.ctl_name)?;
        let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) };
        if result < 0 {
            return Err(map_io(io::Error::last_os_error()));
        }
        let mut address: libc::sockaddr_ctl = unsafe { mem::zeroed() };
        address.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
        address.sc_family = libc::AF_SYSTEM as u8;
        address.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        address.sc_id = info.ctl_id;
        address.sc_unit = unit;
        // SAFETY: address is a fully initialized sockaddr_ctl for the kernel
        // control named by CTLIOCGINFO; fd is an owned control socket.
        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ctl).cast::<libc::sockaddr>(),
                mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(map_io(io::Error::last_os_error()));
        }
        let name = get_name(fd.as_raw_fd())?;
        if let Some(requested) = config.name.as_deref()
            && requested != "utun"
            && requested != name
        {
            return Err(UtunError::DeviceNameMismatch {
                expected: requested.to_owned(),
                actual: name,
            });
        }
        set_mtu(&name, config.mtu)?;
        let actual = get_mtu(&name)?;
        if actual != config.mtu as libc::c_int {
            return Err(UtunError::MtuMismatch {
                expected: config.mtu,
                actual,
            });
        }
        Ok(Self {
            fd,
            name,
            mtu: config.mtu,
            read_lock: Mutex::new(()),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Re-read the kernel-assigned name and MTU and compare them with the
    /// values published at creation.
    pub fn verify(&self) -> Result<(), UtunError> {
        let actual = get_name(self.fd.as_raw_fd())?;
        if actual != self.name {
            return Err(UtunError::DeviceNameMismatch {
                expected: self.name.clone(),
                actual,
            });
        }
        let actual = get_mtu(&self.name)?;
        if actual != self.mtu as libc::c_int {
            return Err(UtunError::MtuMismatch {
                expected: self.mtu,
                actual,
            });
        }
        Ok(())
    }

    /// Block until one validated packet is available. `Ok(None)` means the
    /// socket reached EOF.
    pub fn read_packet(&self) -> Result<Option<Vec<u8>>, UtunError> {
        let _read = self.read_lock.lock().map_err(|_| UtunError::Poisoned)?;
        self.read_locked()
    }

    /// Wait at most `timeout` for a packet, including time spent waiting for
    /// another reader to release the single-reader lock. `Ok(None)` means the
    /// deadline expired, the socket reached EOF, or the descriptor had no data.
    pub fn read_packet_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>, UtunError> {
        let start = Instant::now();
        let _read = loop {
            match self.read_lock.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(UtunError::Poisoned),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let remaining = timeout.saturating_sub(start.elapsed());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        };
        let remaining = timeout.saturating_sub(start.elapsed());
        if !poll_readable(self.fd.as_raw_fd(), remaining)? {
            return Ok(None);
        }
        self.read_locked()
    }

    /// Validate and write one complete L3 packet with its utun family header.
    pub fn write_packet(&self, packet: &[u8]) -> Result<(), UtunError> {
        if packet.len() > self.mtu {
            return Err(UtunError::Packet(Error::PacketTooLarge { mtu: self.mtu }));
        }
        inspect_packet(packet)?;
        let family = match packet[0] >> 4 {
            4 => AF_INET_HEADER,
            6 => AF_INET6_HEADER,
            _ => return Err(UtunError::Packet(Error::InvalidVersion)),
        };
        let mut framed = Vec::with_capacity(UTUN_HEADER_LEN + packet.len());
        framed.extend_from_slice(&family.to_be_bytes());
        framed.extend_from_slice(packet);
        write_frame(self.fd.as_raw_fd(), &framed)
    }

    fn read_locked(&self) -> Result<Option<Vec<u8>>, UtunError> {
        let mut buffer = vec![0u8; self.mtu + UTUN_HEADER_LEN + 1];
        let length = read_fd(self.fd.as_raw_fd(), &mut buffer)?;
        if length == 0 {
            return Ok(None);
        }
        if length >= buffer.len() {
            return Err(UtunError::Packet(Error::PacketTooLarge { mtu: self.mtu }));
        }
        if length < UTUN_HEADER_LEN {
            return Err(UtunError::TruncatedFamilyHeader);
        }
        let family = u32::from_be_bytes(
            buffer[..UTUN_HEADER_LEN]
                .try_into()
                .expect("four-byte utun family header"),
        );
        let packet = &buffer[UTUN_HEADER_LEN..length];
        if packet.is_empty() {
            return Err(UtunError::Packet(Error::EmptyPacket));
        }
        if packet.len() > self.mtu {
            return Err(UtunError::Packet(Error::PacketTooLarge { mtu: self.mtu }));
        }
        match (family, packet[0] >> 4) {
            (AF_INET_HEADER, 4) | (AF_INET6_HEADER, 6) => {}
            (AF_INET_HEADER, _) | (AF_INET6_HEADER, _) => {
                return Err(UtunError::Packet(Error::InvalidVersion));
            }
            (other, _) => return Err(UtunError::UnsupportedFamily(other)),
        }
        inspect_packet(packet)?;
        Ok(Some(packet.to_vec()))
    }
}

impl PacketIo for UtunDevice {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, Error> {
        UtunDevice::read_packet(self).map_err(packet_error)
    }

    fn write_packet(&self, packet: &[u8]) -> Result<(), Error> {
        UtunDevice::write_packet(self, packet).map_err(packet_error)
    }
}

fn packet_error(error: UtunError) -> Error {
    match error {
        UtunError::Packet(packet) => packet,
        _ => Error::QueueClosed,
    }
}

fn unit_for(name: Option<&str>) -> Result<u32, UtunError> {
    match name {
        None | Some("utun") => Ok(0),
        Some(requested) => {
            let digits = requested
                .strip_prefix("utun")
                .filter(|digits| !digits.is_empty())
                .ok_or(UtunError::InvalidName)?;
            if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(UtunError::InvalidName);
            }
            let index: u32 = digits.parse().map_err(|_| UtunError::InvalidName)?;
            index.checked_add(1).ok_or(UtunError::InvalidName)
        }
    }
}

fn open_control_socket() -> Result<OwnedFd, UtunError> {
    // SAFETY: socket returns a new owned descriptor or -1.
    let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    // SAFETY: fd is the unique descriptor just returned by socket.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(fd)?;
    Ok(owned)
}

fn ioctl_socket() -> Result<OwnedFd, UtunError> {
    // A TCP (not UDP/RAW) socket is used only as an ifreq ioctl handle for
    // SIOCSIFMTU/SIOCGIFMTU; it is never connected and carries no packets. This
    // keeps the adapter inside the project's 0-UDP boundary.
    // SAFETY: socket returns a new owned descriptor or -1.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    // SAFETY: fd is the unique descriptor just returned by socket.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(fd)?;
    Ok(owned)
}

fn set_cloexec(fd: RawFd) -> Result<(), UtunError> {
    // SAFETY: fd is a live socket descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    // SAFETY: fd is live and the flag value came from F_GETFD.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    Ok(())
}

fn copy_control_name(destination: &mut [libc::c_char]) -> Result<(), UtunError> {
    if UTUN_CONTROL_NAME.len() > destination.len() {
        return Err(UtunError::InvalidConfiguration(
            "utun control name does not fit ctl_info",
        ));
    }
    for (target, source) in destination.iter_mut().zip(UTUN_CONTROL_NAME) {
        *target = *source as libc::c_char;
    }
    Ok(())
}

fn get_name(fd: RawFd) -> Result<String, UtunError> {
    let mut buffer = [0u8; UTUN_NAME_BUFFER];
    let mut length = buffer.len() as libc::socklen_t;
    // SAFETY: buffer is writable for `length` bytes and fd is a live utun
    // control socket; the kernel writes a NUL-terminated interface name.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    let length = length as usize;
    if length == 0 || length > buffer.len() {
        return Err(UtunError::InvalidConfiguration(
            "utun interface name has an invalid length",
        ));
    }
    let end = buffer[..length]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(length);
    if end == 0 {
        return Err(UtunError::InvalidConfiguration(
            "utun interface name is empty",
        ));
    }
    let name = std::str::from_utf8(&buffer[..end])
        .map_err(|_| UtunError::InvalidConfiguration("utun name is not valid UTF-8"))?;
    if !name.starts_with("utun") {
        return Err(UtunError::InvalidConfiguration(
            "kernel returned a non-utun interface name",
        ));
    }
    Ok(name.to_owned())
}

fn make_ifreq(name: &str) -> Result<libc::ifreq, UtunError> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(UtunError::InvalidName);
    }
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    for (target, source) in request.ifr_name.iter_mut().zip(name.as_bytes()) {
        *target = *source as libc::c_char;
    }
    Ok(request)
}

fn set_mtu(name: &str, mtu: usize) -> Result<(), UtunError> {
    let socket = ioctl_socket()?;
    let mut request = make_ifreq(name)?;
    // Current libc exposes this union member as a safe field assignment.
    request.ifr_ifru.ifru_mtu = mtu as libc::c_int;
    // SAFETY: request is a valid ifreq whose name identifies the utun
    // interface; the ioctl reads the mtu member.
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCSIFMTU,
            &request as *const libc::ifreq,
        )
    };
    if result < 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    Ok(())
}

fn get_mtu(name: &str) -> Result<libc::c_int, UtunError> {
    let socket = ioctl_socket()?;
    let mut request = make_ifreq(name)?;
    // SAFETY: request is a valid ifreq; SIOCGIFMTU writes the mtu union member.
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCGIFMTU,
            &mut request as *mut libc::ifreq,
        )
    };
    if result < 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    // SAFETY: successful SIOCGIFMTU initialized the mtu union member.
    Ok(unsafe { request.ifr_ifru.ifru_mtu })
}

fn read_fd(fd: RawFd, buffer: &mut [u8]) -> Result<usize, UtunError> {
    loop {
        // SAFETY: buffer is writable for its length and fd is an owned utun
        // control socket.
        let result =
            unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<libc::c_void>(), buffer.len()) };
        if result >= 0 {
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(map_io(error));
    }
}

fn write_frame(fd: RawFd, data: &[u8]) -> Result<(), UtunError> {
    loop {
        // SAFETY: data is readable for its length and fd is an owned utun
        // socket. A utun write transfers exactly one datagram; a short result
        // must not be retried as a second packet.
        let result = unsafe { libc::write(fd, data.as_ptr().cast::<libc::c_void>(), data.len()) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(map_io(error));
        }
        if result == 0 {
            return Err(UtunError::WriteZero);
        }
        let actual = result as usize;
        if actual != data.len() {
            return Err(UtunError::PartialWrite {
                expected: data.len(),
                actual,
            });
        }
        return Ok(());
    }
}

fn poll_readable(fd: RawFd, timeout: Duration) -> Result<bool, UtunError> {
    let start = Instant::now();
    loop {
        let remaining = timeout.saturating_sub(start.elapsed());
        let milliseconds = remaining.as_millis().min((libc::c_int::MAX - 1) as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is one valid pollfd writable for this call.
        let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                if start.elapsed() >= timeout {
                    return Ok(false);
                }
                continue;
            }
            return Err(map_io(error));
        }
        if result == 0 {
            return Ok(false);
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(UtunError::InvalidConfiguration("utun fd is invalid"));
        }
        return Ok(descriptor.revents & libc::POLLIN != 0);
    }
}

fn map_io(error: io::Error) -> UtunError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        UtunError::PermissionDenied
    } else {
        UtunError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_unit_selection_and_name_validation() {
        assert_eq!(unit_for(None).expect("auto unit"), 0);
        assert_eq!(unit_for(Some("utun")).expect("auto utun"), 0);
        assert_eq!(unit_for(Some("utun7")).expect("unit 7"), 8);
        assert!(unit_for(Some("boreas0")).is_err());
        assert!(unit_for(Some("utun-1")).is_err());
        assert!(unit_for(Some("utun4294967295")).is_err());
    }

    #[test]
    fn config_rejects_unbounded_mtu_and_foreign_names() {
        assert!(
            UtunConfig {
                name: None,
                mtu: 1279
            }
            .validate()
            .is_err()
        );
        assert!(
            UtunConfig {
                name: None,
                mtu: MAX_IP_PACKET + 1
            }
            .validate()
            .is_err()
        );
        assert!(
            UtunConfig {
                name: None,
                mtu: 1400
            }
            .validate()
            .is_ok()
        );
        assert!(
            UtunConfig {
                name: Some("boreas0".to_owned()),
                mtu: 1400
            }
            .validate()
            .is_err()
        );
    }
}
