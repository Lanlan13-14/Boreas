//! Windows-only Wintun adapter lifecycle and packet queues.
//!
//! `wintun.dll` is loaded only from an absolute caller-supplied path whose
//! SHA-256 matches the caller-supplied digest. This module never searches
//! `PATH`, never ships or deletes the Wintun driver, and installs no routes or
//! addresses. Unsafe code is confined to Win32/Wintun FFI boundaries.
#![allow(unsafe_code)]

use std::{
    collections::HashMap,
    ffi::CString,
    fmt,
    fmt::Write as _,
    fs::OpenOptions,
    io::{self, Read, Write},
    mem,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS,
        ERROR_NOT_FOUND, FreeLibrary, GetLastError, HANDLE, HMODULE, NO_ERROR, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, GetIpInterfaceEntry,
            MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    Security::Cryptography::{
        BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_OBJECT_LENGTH, BCRYPT_SHA256_ALGORITHM,
        BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
        BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider,
    },
    System::{
        LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        Threading::WaitForSingleObject,
    },
};

use super::{Error, MAX_IP_PACKET, PacketIo, inspect_packet};

const MAX_DLL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ADAPTER_NAME_UTF16: usize = 127;
const MIN_MTU: usize = 1280;
const MIN_RING_CAPACITY: u32 = 0x0002_0000;
const MAX_RING_CAPACITY: u32 = 0x0400_0000;
const DEFAULT_RING_CAPACITY: u32 = 0x0004_0000;
const IF_MAX_STRING_SIZE: usize = 256;
const MAX_CACHED_DRIVERS: usize = 4;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static API_CACHE: OnceLock<Mutex<HashMap<(PathBuf, [u8; 32]), Arc<WintunApi>>>> = OnceLock::new();

type AdapterHandle = *mut core::ffi::c_void;
type SessionHandle = *mut core::ffi::c_void;

#[repr(C)]
#[allow(dead_code)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const Guid) -> AdapterHandle;
type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
type GetAdapterLuidFn = unsafe extern "system" fn(AdapterHandle, *mut NET_LUID_LH);
type StartSessionFn = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
type EndSessionFn = unsafe extern "system" fn(SessionHandle);
type GetReadWaitEventFn = unsafe extern "system" fn(SessionHandle) -> HANDLE;
type ReceivePacketFn = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
type ReleaseReceivePacketFn = unsafe extern "system" fn(SessionHandle, *const u8);
type AllocateSendPacketFn = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(SessionHandle, *const u8);

struct WintunApi {
    /// Kept loaded for the process lifetime; see `WintunApi::load`.
    _module: HMODULE,
    _temp: Option<TempDll>,
    create_adapter: CreateAdapterFn,
    close_adapter: CloseAdapterFn,
    get_adapter_luid: GetAdapterLuidFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    get_read_wait_event: GetReadWaitEventFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceivePacketFn,
    allocate_send_packet: AllocateSendPacketFn,
    send_packet: SendPacketFn,
}

impl WintunApi {
    /// Load and cache a verified Wintun image.
    ///
    /// The module is intentionally retained for the process lifetime:
    /// `WintunCloseAdapter` queues cleanup work whose callback lives in the
    /// DLL. Unloading immediately after the last adapter closes could execute
    /// an unmapped callback, so the cache keeps images loaded and bounded to
    /// `MAX_CACHED_DRIVERS` distinct path/digest pairs.
    fn load(config: &WintunConfig) -> Result<Arc<Self>, WintunError> {
        config.validate()?;
        let path = std::path::absolute(&config.dll_path)?;
        let key = (path.clone(), config.dll_sha256);
        let cache = API_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut cache = cache.lock().map_err(|_| WintunError::Poisoned)?;
        if let Some(api) = cache.get(&key) {
            return Ok(Arc::clone(api));
        }
        if cache.len() >= MAX_CACHED_DRIVERS {
            return Err(WintunError::DriverCacheFull);
        }
        let api = Arc::new(Self::load_uncached(config, &path)?);
        cache.insert(key, Arc::clone(&api));
        Ok(api)
    }

    fn load_uncached(config: &WintunConfig, path: &Path) -> Result<Self, WintunError> {
        let file = OpenOptions::new().read(true).open(path)?;
        let length = file.metadata()?.len();
        if length == 0 || length > MAX_DLL_BYTES {
            return Err(WintunError::InvalidConfiguration(
                "wintun.dll size is outside the permitted range",
            ));
        }
        let mut bytes = Vec::with_capacity(length as usize);
        let mut limited = file.take(MAX_DLL_BYTES + 1);
        limited.read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_DLL_BYTES {
            return Err(WintunError::InvalidConfiguration(
                "wintun.dll changed size while being read",
            ));
        }
        let actual = sha256_bytes(&bytes)?;
        if actual != config.dll_sha256 {
            return Err(WintunError::DriverHashMismatch {
                expected: config.dll_sha256,
                actual,
            });
        }
        // Stage the exact bytes that were hashed. This removes the source-path
        // replacement window; the staging directory is per-user and is not an
        // isolation boundary against a hostile same-user process.
        let temp = TempDll::create(&bytes)?;
        let wide = wide_path(&temp.path)?;
        // SAFETY: `wide` is a NUL-terminated absolute path to the staged image.
        // Only System32 is searched for dependent DLLs, never the staging or
        // caller-selected directory.
        let module = unsafe {
            LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32)
        };
        if module.is_null() {
            return Err(last_error("LoadLibraryExW"));
        }
        // SAFETY: the module was just loaded and remains owned by this function
        // until `Self` takes responsibility for it.
        match unsafe { Self::resolve(module) } {
            Ok(mut api) => {
                api._temp = Some(temp);
                Ok(api)
            }
            Err(error) => {
                // SAFETY: module is non-null and not yet owned by a WintunApi.
                unsafe { FreeLibrary(module) };
                Err(error)
            }
        }
    }

    unsafe fn resolve(module: HMODULE) -> Result<Self, WintunError> {
        Ok(Self {
            _module: module,
            _temp: None,
            // SAFETY: all export names below are the documented Wintun ABI.
            create_adapter: unsafe { symbol(module, "WintunCreateAdapter")? },
            close_adapter: unsafe { symbol(module, "WintunCloseAdapter")? },
            get_adapter_luid: unsafe { symbol(module, "WintunGetAdapterLUID")? },
            start_session: unsafe { symbol(module, "WintunStartSession")? },
            end_session: unsafe { symbol(module, "WintunEndSession")? },
            get_read_wait_event: unsafe { symbol(module, "WintunGetReadWaitEvent")? },
            receive_packet: unsafe { symbol(module, "WintunReceivePacket")? },
            release_receive_packet: unsafe { symbol(module, "WintunReleaseReceivePacket")? },
            allocate_send_packet: unsafe { symbol(module, "WintunAllocateSendPacket")? },
            send_packet: unsafe { symbol(module, "WintunSendPacket")? },
        })
    }
}

// SAFETY: the module handle is process-wide and the documented Wintun session
// operations used here are thread-safe for one reader plus one writer. The
// cached image stays loaded for the process lifetime.
unsafe impl Send for WintunApi {}
unsafe impl Sync for WintunApi {}

struct TempDll {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDll {
    fn create(bytes: &[u8]) -> Result<Self, WintunError> {
        let base = std::env::temp_dir();
        for _ in 0..16 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = base.join(format!("boreas-wintun-{}-{sequence}", std::process::id()));
            match std::fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
            let path = directory.join("wintun.dll");
            if let Err(error) = write_staged(&path, bytes) {
                let _ = std::fs::remove_dir_all(&directory);
                return Err(error);
            }
            return Ok(Self { directory, path });
        }
        Err(WintunError::InvalidConfiguration(
            "could not create a private staging directory for wintun.dll",
        ))
    }
}

impl Drop for TempDll {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn write_staged(path: &Path, bytes: &[u8]) -> Result<(), WintunError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

unsafe fn symbol<T: Copy>(module: HMODULE, name: &'static str) -> Result<T, WintunError> {
    let name_c = CString::new(name).expect("static Wintun export has no NUL");
    // SAFETY: module is a live image handle and name_c is a NUL-terminated
    // symbol name valid for the duration of the call.
    let procedure = unsafe { GetProcAddress(module, name_c.as_ptr().cast::<u8>()) };
    match procedure {
        Some(procedure) => {
            // SAFETY: each Wintun export is transmuted to the exact signature
            // declared by wintun.h; the caller resolves only known names.
            Ok(unsafe { mem::transmute_copy(&procedure) })
        }
        None => Err(WintunError::MissingExport(name)),
    }
}

#[derive(Clone, Debug)]
pub struct WintunConfig {
    /// Adapter display/alias name. Creation pre-checks that no interface with
    /// this alias exists. Callers must use a unique name; Wintun itself may
    /// suffix a colliding foreign adapter name, so the pre-check is not a
    /// substitute for a namespaced naming policy under a concurrent race.
    pub name: String,
    /// Wintun tunnel type label, at most 127 UTF-16 code units.
    pub tunnel_type: String,
    /// Interface MTU applied to both IPv4 and IPv6 interface rows.
    pub mtu: usize,
    /// Wintun ring capacity; power of two in [128 KiB, 64 MiB].
    pub ring_capacity: u32,
    /// Absolute path to a caller-trusted `wintun.dll`.
    pub dll_path: PathBuf,
    /// SHA-256 of the exact DLL bytes. The expected value must be provisioned
    /// out-of-band by the caller; this is an integrity pin, not Authenticode
    /// verification. Loading fails closed on mismatch.
    pub dll_sha256: [u8; 32],
}

impl WintunConfig {
    pub fn new(
        name: impl Into<String>,
        dll_path: impl Into<PathBuf>,
        dll_sha256: [u8; 32],
    ) -> Self {
        Self {
            name: name.into(),
            tunnel_type: "Boreas".to_owned(),
            mtu: 1500,
            ring_capacity: DEFAULT_RING_CAPACITY,
            dll_path: dll_path.into(),
            dll_sha256,
        }
    }

    pub fn validate(&self) -> Result<(), WintunError> {
        validate_adapter_name(&self.name)?;
        if self.tunnel_type.is_empty()
            || self.tunnel_type.encode_utf16().count() > MAX_ADAPTER_NAME_UTF16
            || self
                .tunnel_type
                .chars()
                .any(|character| character.is_control())
        {
            return Err(WintunError::InvalidConfiguration("invalid tunnel type"));
        }
        if !(MIN_MTU..=MAX_IP_PACKET).contains(&self.mtu) {
            return Err(WintunError::InvalidConfiguration(
                "mtu must be between 1280 and 65535",
            ));
        }
        if !(MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&self.ring_capacity)
            || !self.ring_capacity.is_power_of_two()
        {
            return Err(WintunError::InvalidConfiguration(
                "ring capacity must be a power of two in [128 KiB, 64 MiB]",
            ));
        }
        if !self.dll_path.is_absolute() {
            return Err(WintunError::InvalidConfiguration(
                "wintun.dll path must be absolute",
            ));
        }
        let extension_ok = self
            .dll_path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"));
        if !extension_ok {
            return Err(WintunError::InvalidConfiguration(
                "wintun driver path must name a .dll file",
            ));
        }
        if self.dll_sha256.iter().all(|byte| *byte == 0) {
            return Err(WintunError::InvalidConfiguration(
                "wintun.dll SHA-256 must be supplied",
            ));
        }
        Ok(())
    }
}

fn validate_adapter_name(name: &str) -> Result<(), WintunError> {
    if name.is_empty()
        || name.encode_utf16().count() > MAX_ADAPTER_NAME_UTF16
        || name.chars().any(|character| {
            character.is_control()
                || matches!(character, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
    {
        return Err(WintunError::InvalidName);
    }
    Ok(())
}

#[derive(Debug)]
pub enum WintunError {
    Io(io::Error),
    InvalidConfiguration(&'static str),
    InvalidName,
    DriverHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    DriverCacheFull,
    MissingExport(&'static str),
    Win32 {
        operation: &'static str,
        code: u32,
    },
    AdapterAlreadyExists(String),
    AdapterNameMismatch {
        expected: String,
        actual: String,
    },
    MtuMismatch {
        expected: usize,
        actual: u32,
    },
    RingFull,
    SessionClosed,
    Poisoned,
    Packet(Error),
}

impl fmt::Display for WintunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidConfiguration(reason) => write!(formatter, "invalid configuration: {reason}"),
            Self::InvalidName => formatter.write_str("invalid Wintun adapter name"),
            Self::DriverHashMismatch { expected, actual } => write!(
                formatter,
                "wintun.dll SHA-256 mismatch: expected {}, got {}",
                hex(expected),
                hex(actual)
            ),
            Self::DriverCacheFull => formatter.write_str(
                "too many distinct Wintun driver images have been loaded in this process",
            ),
            Self::MissingExport(name) => write!(formatter, "wintun.dll is missing export {name}"),
            Self::Win32 { operation, code } => write!(
                formatter,
                "{operation} failed with Windows error {code} (0x{code:08x})"
            ),
            Self::AdapterAlreadyExists(name) => {
                write!(formatter, "an interface named {name:?} already exists")
            }
            Self::AdapterNameMismatch { expected, actual } => write!(
                formatter,
                "Wintun adapter alias mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::MtuMismatch { expected, actual } => {
                write!(formatter, "MTU mismatch: expected {expected}, got {actual}")
            }
            Self::RingFull => formatter.write_str("Wintun send ring is full"),
            Self::SessionClosed => formatter.write_str("Wintun session is closed"),
            Self::Poisoned => formatter.write_str("Wintun queue lock is poisoned"),
            Self::Packet(error) => write!(formatter, "packet error: {error}"),
        }
    }
}

impl std::error::Error for WintunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Packet(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for WintunError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Error> for WintunError {
    fn from(error: Error) -> Self {
        Self::Packet(error)
    }
}

#[derive(Clone)]
pub struct WintunDevice {
    inner: Arc<WintunInner>,
}

struct WintunInner {
    api: Arc<WintunApi>,
    adapter: AdapterHandle,
    session: SessionHandle,
    wait_event: HANDLE,
    luid: NET_LUID_LH,
    name: String,
    mtu: usize,
    read_lock: Mutex<()>,
    send_lock: Mutex<()>,
}

// SAFETY: adapter and session handles are immutable for the lifetime of this
// inner value and are closed exactly once in Drop. WintunReceivePacket and
// WintunSendPacket are documented thread-safe; this module additionally
// serializes receive and send independently.
unsafe impl Send for WintunInner {}
unsafe impl Sync for WintunInner {}

impl Drop for WintunInner {
    fn drop(&mut self) {
        // SAFETY: both handles were returned successfully by Wintun and no
        // other owner can close them; ending the session precedes CloseAdapter.
        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
        }
    }
}

struct AdapterGuard {
    api: Arc<WintunApi>,
    handle: AdapterHandle,
}

impl AdapterGuard {
    fn release(mut self) -> AdapterHandle {
        let handle = self.handle;
        self.handle = ptr::null_mut();
        handle
    }
}

impl Drop for AdapterGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: this guard owns the adapter handle returned by
            // WintunCreateAdapter and has not released it.
            unsafe { (self.api.close_adapter)(self.handle) };
        }
    }
}

struct SessionGuard {
    api: Arc<WintunApi>,
    handle: SessionHandle,
}

impl SessionGuard {
    fn release(mut self) -> SessionHandle {
        let handle = self.handle;
        self.handle = ptr::null_mut();
        handle
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: this guard owns the session handle returned by
            // WintunStartSession and has not released it.
            unsafe { (self.api.end_session)(self.handle) };
        }
    }
}

enum Receive {
    Packet(Vec<u8>),
    Empty,
    Closed,
}

struct Received<'a> {
    api: &'a WintunApi,
    session: SessionHandle,
    packet: *const u8,
}

impl Drop for Received<'_> {
    fn drop(&mut self) {
        // SAFETY: packet came from WintunReceivePacket on this session and is
        // released exactly once; the caller copied the bytes before dropping.
        unsafe { (self.api.release_receive_packet)(self.session, self.packet) };
    }
}

impl WintunDevice {
    /// Create a real Wintun adapter (or fail closed). Requires an elevated
    /// process and a trusted, hash-pinned `wintun.dll`; no driver is bundled or
    /// deleted by this crate.
    pub fn create(config: WintunConfig) -> Result<Self, WintunError> {
        config.validate()?;
        if alias_exists(&config.name)? {
            return Err(WintunError::AdapterAlreadyExists(config.name.clone()));
        }
        let api = WintunApi::load(&config)?;
        let name = wide(&config.name);
        let tunnel_type = wide(&config.tunnel_type);
        // SAFETY: both strings are NUL-terminated for the duration of the call;
        // a null GUID asks Wintun to generate an adapter identity.
        let adapter = unsafe {
            (api.create_adapter)(
                name.as_ptr(),
                tunnel_type.as_ptr(),
                ptr::null::<Guid>(),
            )
        };
        if adapter.is_null() {
            return Err(last_error("WintunCreateAdapter"));
        }
        let adapter = AdapterGuard {
            api: Arc::clone(&api),
            handle: adapter,
        };
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: adapter is a live handle; WintunGetAdapterLUID writes one LUID.
        unsafe { (api.get_adapter_luid)(adapter.handle, &mut luid) };
        verify_alias(&luid, &config.name)?;
        // SAFETY: adapter is live and ring capacity was validated before loading.
        let session = unsafe { (api.start_session)(adapter.handle, config.ring_capacity) };
        if session.is_null() {
            return Err(last_error("WintunStartSession"));
        }
        let session = SessionGuard {
            api: Arc::clone(&api),
            handle: session,
        };
        // SAFETY: session is live; the returned event remains owned by Wintun.
        let wait_event = unsafe { (api.get_read_wait_event)(session.handle) };
        if wait_event.is_null() {
            return Err(last_error("WintunGetReadWaitEvent"));
        }
        set_ip_mtu(&luid, AF_INET, config.mtu)?;
        set_ip_mtu(&luid, AF_INET6, config.mtu)?;
        let inner = WintunInner {
            api,
            adapter: adapter.release(),
            session: session.release(),
            wait_event,
            luid,
            name: config.name,
            mtu: config.mtu,
            read_lock: Mutex::new(()),
            send_lock: Mutex::new(()),
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn mtu(&self) -> usize {
        self.inner.mtu
    }

    pub fn luid(&self) -> u64 {
        // SAFETY: NET_LUID_LH is a union with a single u64 value written by
        // WintunGetAdapterLUID before this device was published.
        unsafe { self.inner.luid.Value }
    }

    /// Re-read the adapter alias and both IP interface MTUs from Windows.
    pub fn verify(&self) -> Result<(), WintunError> {
        verify_alias(&self.inner.luid, &self.inner.name)?;
        for family in [AF_INET, AF_INET6] {
            let actual = get_ip_mtu(&self.inner.luid, family)?;
            if actual != self.inner.mtu as u32 {
                return Err(WintunError::MtuMismatch {
                    expected: self.inner.mtu,
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Block until one packet is available. Returns `Ok(None)` when Wintun
    /// reports that the session/adaptor is terminating.
    pub fn read_packet(&self) -> Result<Option<Vec<u8>>, WintunError> {
        let _read = self.inner.read_lock.lock().map_err(|_| WintunError::Poisoned)?;
        loop {
            match self.receive_once()? {
                Receive::Packet(packet) => return Ok(Some(packet)),
                Receive::Closed => return Ok(None),
                Receive::Empty => {}
            }
            // SAFETY: wait_event is owned by the live Wintun session.
            let wait = unsafe { WaitForSingleObject(self.inner.wait_event, u32::MAX) };
            if wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT {
                return Err(last_error("WaitForSingleObject"));
            }
        }
    }

    /// Wait at most `timeout` for a packet, including time spent waiting for
    /// another reader to release the single-reader lock. `Ok(None)` means the
    /// deadline expired or the session is terminating, never an unvalidated
    /// packet.
    pub fn read_packet_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>, WintunError> {
        let start = Instant::now();
        let _read = loop {
            match self.inner.read_lock.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(WintunError::Poisoned),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let remaining = timeout.saturating_sub(start.elapsed());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        };
        loop {
            match self.receive_once()? {
                Receive::Packet(packet) => return Ok(Some(packet)),
                Receive::Closed => return Ok(None),
                Receive::Empty => {}
            }
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            let milliseconds = remaining
                .as_millis()
                .min((u32::MAX - 1) as u128) as u32;
            // SAFETY: wait_event is owned by the live Wintun session.
            let wait = unsafe { WaitForSingleObject(self.inner.wait_event, milliseconds) };
            if wait == WAIT_TIMEOUT {
                return Ok(None);
            }
            if wait != WAIT_OBJECT_0 {
                return Err(last_error("WaitForSingleObject"));
            }
        }
    }

    /// Validate and place one complete L3 packet in the Wintun send ring.
    pub fn write_packet(&self, packet: &[u8]) -> Result<(), WintunError> {
        if packet.len() > self.inner.mtu {
            return Err(WintunError::Packet(Error::PacketTooLarge {
                mtu: self.inner.mtu,
            }));
        }
        inspect_packet(packet)?;
        let length = u32::try_from(packet.len())
            .map_err(|_| WintunError::Packet(Error::InvalidLength))?;
        let _send = self.inner.send_lock.lock().map_err(|_| WintunError::Poisoned)?;
        // SAFETY: session is live; AllocateSendPacket returns a writable buffer
        // of exactly `length` bytes or null.
        let slot = unsafe { (self.inner.api.allocate_send_packet)(self.inner.session, length) };
        if slot.is_null() {
            // SAFETY: reads the calling thread's last-error value.
            let code = unsafe { GetLastError() };
            return Err(match code {
                ERROR_BUFFER_OVERFLOW => WintunError::RingFull,
                ERROR_HANDLE_EOF => WintunError::SessionClosed,
                _ => WintunError::Win32 {
                    operation: "WintunAllocateSendPacket",
                    code,
                },
            });
        }
        // SAFETY: slot is writable for `length` bytes and packet.len() == length;
        // the regions do not overlap. SendPacket consumes the allocation.
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len());
            (self.inner.api.send_packet)(self.inner.session, slot);
        }
        Ok(())
    }

    fn receive_once(&self) -> Result<Receive, WintunError> {
        let mut size = 0u32;
        // SAFETY: session is live and `size` is a valid out pointer.
        let packet = unsafe { (self.inner.api.receive_packet)(self.inner.session, &mut size) };
        if packet.is_null() {
            // SAFETY: reads the calling thread's last-error value.
            let code = unsafe { GetLastError() };
            return match code {
                ERROR_NO_MORE_ITEMS => Ok(Receive::Empty),
                ERROR_HANDLE_EOF => Ok(Receive::Closed),
                _ => Err(WintunError::Win32 {
                    operation: "WintunReceivePacket",
                    code,
                }),
            };
        }
        let received = Received {
            api: self.inner.api.as_ref(),
            session: self.inner.session,
            packet,
        };
        let size = size as usize;
        if size == 0 || size > MAX_IP_PACKET {
            return Err(WintunError::Packet(Error::InvalidLength));
        }
        // SAFETY: WintunReceivePacket returned a readable buffer of `size`
        // bytes. The copy completes before `received` releases the slot.
        let copy = unsafe { std::slice::from_raw_parts(packet, size) }.to_vec();
        drop(received);
        if copy.len() > self.inner.mtu {
            return Err(WintunError::Packet(Error::PacketTooLarge {
                mtu: self.inner.mtu,
            }));
        }
        inspect_packet(&copy)?;
        Ok(Receive::Packet(copy))
    }
}

impl PacketIo for WintunDevice {
    fn read_packet(&self) -> Result<Option<Vec<u8>>, Error> {
        WintunDevice::read_packet(self).map_err(packet_error)
    }

    fn write_packet(&self, packet: &[u8]) -> Result<(), Error> {
        WintunDevice::write_packet(self, packet).map_err(packet_error)
    }
}

fn packet_error(error: WintunError) -> Error {
    match error {
        WintunError::Packet(packet) => packet,
        WintunError::RingFull => Error::QueueFull,
        _ => Error::QueueClosed,
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Result<Vec<u16>, WintunError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.contains(&0) {
        return Err(WintunError::InvalidConfiguration(
            "wintun.dll path contains NUL or is empty",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn last_error(operation: &'static str) -> WintunError {
    // SAFETY: reads the calling thread's last-error value.
    WintunError::Win32 {
        operation,
        code: unsafe { GetLastError() },
    }
}

fn alias_exists(name: &str) -> Result<bool, WintunError> {
    let wide = wide(name);
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: wide is NUL-terminated and luid is a valid out pointer.
    let result = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    match result {
        NO_ERROR => Ok(true),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(false),
        _ => Err(WintunError::Win32 {
            operation: "ConvertInterfaceAliasToLuid",
            code: result,
        }),
    }
}

fn verify_alias(luid: &NET_LUID_LH, expected: &str) -> Result<(), WintunError> {
    let mut alias = [0u16; IF_MAX_STRING_SIZE + 1];
    // SAFETY: luid is a live adapter LUID and alias is writable for its length.
    let result = unsafe { ConvertInterfaceLuidToAlias(luid, alias.as_mut_ptr(), alias.len()) };
    if result != NO_ERROR {
        return Err(WintunError::Win32 {
            operation: "ConvertInterfaceLuidToAlias",
            code: result,
        });
    }
    let end = alias
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(WintunError::InvalidConfiguration(
            "interface alias is not NUL-terminated",
        ))?;
    let actual = String::from_utf16(&alias[..end]).map_err(|_| {
        WintunError::InvalidConfiguration("interface alias is not valid UTF-16")
    })?;
    if actual != expected {
        return Err(WintunError::AdapterNameMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn get_ip_mtu(luid: &NET_LUID_LH, family: u16) -> Result<u32, WintunError> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
    row.Family = family;
    row.InterfaceLuid = *luid;
    // SAFETY: row is fully initialized for the query and writable by the API.
    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result != NO_ERROR {
        return Err(WintunError::Win32 {
            operation: "GetIpInterfaceEntry",
            code: result,
        });
    }
    Ok(row.NlMtu)
}

fn set_ip_mtu(luid: &NET_LUID_LH, family: u16, mtu: usize) -> Result<(), WintunError> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
    row.Family = family;
    row.InterfaceLuid = *luid;
    // SAFETY: row is fully initialized for the query and writable by the API.
    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result != NO_ERROR {
        return Err(WintunError::Win32 {
            operation: "GetIpInterfaceEntry",
            code: result,
        });
    }
    let wanted = u32::try_from(mtu).map_err(|_| {
        WintunError::InvalidConfiguration("mtu does not fit in a Windows interface row")
    })?;
    if row.NlMtu != wanted {
        row.NlMtu = wanted;
        if family == AF_INET {
            // SetIpInterfaceEntry requires SitePrefixLength to be zero for
            // IPv4; for IPv6 it is a real setting and is left untouched.
            row.SitePrefixLength = 0;
        }
        // SAFETY: row came from GetIpInterfaceEntry and only NlMtu (plus the
        // mandatory IPv4 SitePrefixLength zeroing) was changed before the
        // write-back.
        let result = unsafe { SetIpInterfaceEntry(&mut row) };
        if result != NO_ERROR {
            return Err(WintunError::Win32 {
                operation: "SetIpInterfaceEntry",
                code: result,
            });
        }
    }
    let actual = get_ip_mtu(luid, family)?;
    if actual != wanted {
        return Err(WintunError::MtuMismatch {
            expected: mtu,
            actual,
        });
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> Result<[u8; 32], WintunError> {
    let mut reader: &[u8] = bytes;
    sha256_reader(&mut reader, bytes.len() as u64)
}

fn sha256_reader<R: Read>(reader: &mut R, max_bytes: u64) -> Result<[u8; 32], WintunError> {
    let mut algorithm: BCRYPT_ALG_HANDLE = ptr::null_mut();
    // SAFETY: algorithm is a valid out pointer; the algorithm id is a static
    // wide string and flags are zero.
    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
    };
    if status < 0 {
        return Err(nt_error("BCryptOpenAlgorithmProvider", status));
    }
    let _algorithm = AlgorithmHandle(algorithm);

    let mut object_length = 0u32;
    let mut written = 0u32;
    // SAFETY: algorithm is live, the output buffer is four writable bytes, and
    // `written` is a valid out pointer.
    let status = unsafe {
        BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            (&mut object_length as *mut u32).cast::<u8>(),
            4,
            &mut written,
            0,
        )
    };
    if status < 0 || written != 4 || object_length == 0 || object_length > 1024 * 1024 {
        return Err(WintunError::InvalidConfiguration(
            "BCrypt object length is invalid",
        ));
    }
    let mut object = vec![0u8; object_length as usize];
    let mut hash: BCRYPT_HASH_HANDLE = ptr::null_mut();
    // SAFETY: algorithm is live, hash is a valid out pointer, object is
    // writable for object_length bytes, and no secret is supplied.
    let status = unsafe {
        BCryptCreateHash(
            algorithm,
            &mut hash,
            object.as_mut_ptr(),
            object_length,
            ptr::null(),
            0,
            0,
        )
    };
    if status < 0 {
        return Err(nt_error("BCryptCreateHash", status));
    }
    let _hash = HashHandle(hash);

    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(WintunError::InvalidConfiguration("driver size overflow"))?;
        if total > max_bytes {
            return Err(WintunError::InvalidConfiguration(
                "wintun.dll grew beyond the size limit while hashing",
            ));
        }
        // SAFETY: hash is live and buffer[..read] is readable.
        let status = unsafe { BCryptHashData(hash, buffer.as_ptr(), read as u32, 0) };
        if status < 0 {
            return Err(nt_error("BCryptHashData", status));
        }
    }
    let mut digest = [0u8; 32];
    // SAFETY: hash is live and digest is writable for 32 bytes.
    let status = unsafe { BCryptFinishHash(hash, digest.as_mut_ptr(), 32, 0) };
    if status < 0 {
        return Err(nt_error("BCryptFinishHash", status));
    }
    Ok(digest)
}

struct AlgorithmHandle(BCRYPT_ALG_HANDLE);

impl Drop for AlgorithmHandle {
    fn drop(&mut self) {
        // SAFETY: self.0 is a live algorithm handle owned by this guard.
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

struct HashHandle(BCRYPT_HASH_HANDLE);

impl Drop for HashHandle {
    fn drop(&mut self) {
        // SAFETY: self.0 is a live hash handle owned by this guard.
        unsafe { BCryptDestroyHash(self.0) };
    }
}

fn nt_error(operation: &'static str, status: i32) -> WintunError {
    WintunError::Win32 {
        operation,
        code: status as u32,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        let mut input: &[u8] = b"abc";
        let digest = sha256_reader(&mut input, 1024).expect("BCrypt SHA-256");
        assert_eq!(
            hex(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn config_requires_absolute_hash_pinned_dll_and_bounded_mtu() {
        let valid = WintunConfig::new(
            "BoreasTest",
            r"C:\Windows\System32\wintun.dll",
            [7u8; 32],
        );
        assert!(valid.validate().is_ok());
        let relative = WintunConfig::new("BoreasTest", "wintun.dll", [7u8; 32]);
        assert!(relative.validate().is_err());
        let bad_mtu = WintunConfig {
            mtu: 1279,
            ..valid.clone()
        };
        assert!(bad_mtu.validate().is_err());
        let bad_ring = WintunConfig {
            ring_capacity: 0x20001,
            ..valid.clone()
        };
        assert!(bad_ring.validate().is_err());
        let zero_hash = WintunConfig {
            dll_sha256: [0u8; 32],
            ..valid
        };
        assert!(zero_hash.validate().is_err());
    }

    #[test]
    fn wrong_dll_hash_fails_before_load() {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "boreas-tun-wrong-hash-{}-{sequence}.dll",
            std::process::id()
        ));
        std::fs::write(&path, b"not a wintun dll").expect("write dummy driver");
        let config = WintunConfig::new("BoreasTest", path.clone(), [0xAA; 32]);
        let result = WintunApi::load(&config);
        let _ = std::fs::remove_file(&path);
        assert!(
            matches!(result, Err(WintunError::DriverHashMismatch { .. })),
            "hash mismatch must fail before LoadLibrary"
        );
    }
}
