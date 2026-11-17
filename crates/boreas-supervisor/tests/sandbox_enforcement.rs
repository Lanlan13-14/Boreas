#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

//! Real child-process enforcement tests for [`boreas_supervisor::sandbox`].
//!
//! The unit tests in `src/sandbox.rs` interpret the emitted classic-BPF
//! instructions over synthetic `seccomp_data`. They cannot prove that the
//! kernel enforces the program. These tests close that gap for the native
//! ABI only: each case re-executes this test binary as a child, installs the
//! real filter with `sandbox::install_current()` (NO_NEW_PRIVS + TSYNC), and
//! then performs the case's probe syscall(s). The parent asserts on the
//! child's signal or errno, so what is tested is the kernel's action, not the
//! userspace interpreter.
//!
//! Covered here:
//!
//! * `AF_UNIX` `SOCK_STREAM | SOCK_CLOEXEC` is allowed (the management
//!   transport shape). Only `socket()` creation is covered: `bind`, `listen`
//!   and `accept` are not on the filter's allowlist, so this is not an
//!   end-to-end management-channel test.
//! * `AF_INET` / `AF_INET6` `SOCK_DGRAM` and `SOCK_RAW` are denied with
//!   `EPERM`; `AF_INET` stream, `AF_UNIX` DGRAM/SEQPACKET are denied too
//!   because the installed policy rejects them. An unprivileged process
//!   would also get `EPERM` for a raw socket with no filter, so the raw
//!   cases corroborate the policy (next to the UDP/DGRAM cases) rather than
//!   isolating the raw rule on their own.
//! * `io_uring_setup`/`enter`/`register`, the x32 syscall bit (x86-64 only)
//!   and syscall number 102 kill the child with `SIGSYS`. Number 102 is the
//!   i386/ARM-32 `socketcall` number, but on the native ABIs it is `getuid`
//!   (x86-64) or `getitimer` (AArch64); killing it is a deliberate over-deny
//!   inherited from the current policy, recorded here rather than mistaken
//!   for a socketcall proof. Compat rejection itself is exercised only at the
//!   interpreter level (see below).
//! * An inherited UDP fd and an inherited `AF_UNIX` DGRAM fd still work after
//!   the filter is installed, while creating a new UDP socket is denied.
//!   This is the real "a filter cannot revoke an fd the process already
//!   holds" audit; it does not audit a Boreas daemon's fd cleanup.
//!
//! Not covered, deliberately: AArch64 cannot execute AArch32 from a 64-bit
//! process; on x86-64 `int 0x80` can enter ia32 compat, but this test binary
//! does not issue it. The ia32/AArch32 compat-arch rejection therefore stays
//! a synthetic unit-test case, and the number-102 child test is native
//! over-deny evidence, not compat evidence. There is still no production
//! daemon that installs this filter, so none of this is `G-SANDBOX`
//! evidence.
//!
//! After a successful install the child uses only `libc::write` and
//! `libc::_exit` (`write`/`exit_group` are on the allowlist). It does not use
//! `println!`, `std::process::exit` or the allocator in the filtered region;
//! the install-failure message is emitted only when no filter was attached.

use boreas_supervisor::sandbox;
use std::env;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const CHILD_CASE: &str = "BOREAS_SANDBOX_CHILD_CASE";
const CHILD_FD: &str = "BOREAS_SANDBOX_CHILD_FD";
const IO_URING_SETUP: libc::c_long = 425;
const IO_URING_ENTER: libc::c_long = 426;
const IO_URING_REGISTER: libc::c_long = 427;
const X32_SYSCALL_BIT: u64 = 0x4000_0000;
const X86_32_SOCKETCALL: libc::c_long = 102;

const EXIT_INSTALL_FAILED: i32 = 90;
const EXIT_UNEXPECTED: i32 = 91;
const EXIT_NO_FD: i32 = 92;

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn run_child(case: &str, inherited_fd: Option<RawFd>) -> Output {
    let mut command = Command::new(env::current_exe().expect("current test executable"));
    command
        .args(["child_worker", "--exact", "--test-threads=1", "--nocapture"])
        .env(CHILD_CASE, case)
        .env_remove(CHILD_FD)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(fd) = inherited_fd {
        command.env(CHILD_FD, fd.to_string());
    }
    command.output().expect("spawn sandbox child")
}

fn assert_installed(output: &Output) {
    let out = stdout(output);
    assert!(
        out.contains("CHILD_INSTALLED"),
        "child did not install the filter (status={:?}, stdout={out}, stderr={})",
        output.status,
        stderr(output)
    );
}

fn assert_sigsys(output: &Output, case: &str) {
    assert_installed(output);
    assert!(
        stdout(output).contains("CHILD_PRE_SYSCALL"),
        "{case}: child did not reach the syscall: {}",
        stdout(output)
    );
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGSYS),
        "{case}: expected SIGSYS from SECCOMP_RET_KILL_PROCESS, status={:?} stdout={} stderr={}",
        output.status,
        stdout(output),
        stderr(output)
    );
}

#[test]
fn child_process_allows_af_unix_management_socket() {
    let output = run_child("allow_af_unix_stream", None);
    assert_installed(&output);
    assert!(
        output.status.success(),
        "child failed: status={:?} stdout={} stderr={}",
        output.status,
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("RESULT ALLOWED"),
        "AF_UNIX stream socket was not allowed: {}",
        stdout(&output)
    );
    println!(
        "BOREAS_SANDBOX_EVIDENCE arch={} case=af_unix_stream_cloexec verdict=allowed",
        env::consts::ARCH
    );
}

#[test]
fn child_process_denies_inet_udp_raw_and_unix_dgram() {
    let cases = [
        "deny_inet_udp_v4",
        "deny_inet_udp_v6",
        "deny_inet_raw_v4",
        "deny_inet_raw_v6",
        "deny_inet_stream_v4",
        "deny_unix_dgram",
        "deny_unix_seqpacket",
    ];
    for case in cases {
        let output = run_child(case, None);
        assert_installed(&output);
        assert!(
            output.status.success(),
            "{case}: child failed: status={:?} stdout={} stderr={}",
            output.status,
            stdout(&output),
            stderr(&output)
        );
        assert!(
            stdout(&output).contains("RESULT DENIED_EPERM"),
            "{case}: expected EPERM denial, stdout={}",
            stdout(&output)
        );
    }
    println!(
        "BOREAS_SANDBOX_EVIDENCE arch={} case=inet_udp_raw_unix_dgram verdict=denied_eperm",
        env::consts::ARCH
    );
}

#[test]
fn child_process_kills_io_uring_calls() {
    for case in [
        "kill_io_uring_setup",
        "kill_io_uring_enter",
        "kill_io_uring_register",
    ] {
        let output = run_child(case, None);
        assert_sigsys(&output, case);
    }
    println!(
        "BOREAS_SANDBOX_EVIDENCE arch={} case=io_uring_trio verdict=killed_sigsys",
        env::consts::ARCH
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn child_process_kills_x32_syscall_bit() {
    let output = run_child("kill_x32_read", None);
    assert_sigsys(&output, "x32 read");
    println!(
        "BOREAS_SANDBOX_EVIDENCE arch={} case=x32_syscall_bit verdict=killed_sigsys",
        env::consts::ARCH
    );
}

#[test]
fn child_process_records_native_number_102_over_deny() {
    // Number 102 is `socketcall` on i386, `getuid` on x86-64 and `getitimer`
    // on AArch64. Native socketcall cannot be called from these ABIs, and the
    // compat audit arch / x32 bit are rejected separately. The unconditional
    // kill is therefore an over-deny on the native ABIs, not socketcall
    // enforcement; the test records the current policy without changing it.
    let output = run_child("kill_number_102", None);
    assert_sigsys(&output, "syscall 102");
    println!(
        "BOREAS_SANDBOX_EVIDENCE arch={} case=syscall_number_102_over_deny verdict=killed_sigsys",
        env::consts::ARCH
    );
}

struct UdpPair {
    receiver: OwnedFd,
    sender: OwnedFd,
}

fn udp_pair() -> UdpPair {
    let receiver_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(
        receiver_fd >= 0,
        "create UDP receiver: {}",
        io::Error::last_os_error()
    );
    // SAFETY: `receiver_fd` is a fresh, owned descriptor.
    let receiver = unsafe { OwnedFd::from_raw_fd(receiver_fd) };

    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = u16::try_from(libc::AF_INET).expect("AF_INET fits sa_family_t");
    address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    address.sin_port = 0;
    let length = u32::try_from(std::mem::size_of::<libc::sockaddr_in>())
        .expect("sockaddr_in length fits socklen_t");

    assert_eq!(
        unsafe {
            libc::bind(
                receiver.as_raw_fd(),
                std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                length,
            )
        },
        0,
        "bind UDP receiver: {}",
        io::Error::last_os_error()
    );

    let mut bound = address;
    let mut bound_length = length;
    assert_eq!(
        unsafe {
            libc::getsockname(
                receiver.as_raw_fd(),
                std::ptr::from_mut(&mut bound).cast::<libc::sockaddr>(),
                &mut bound_length,
            )
        },
        0,
        "getsockname: {}",
        io::Error::last_os_error()
    );

    let sender_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(
        sender_fd >= 0,
        "create UDP sender: {}",
        io::Error::last_os_error()
    );
    // SAFETY: `sender_fd` is a fresh, owned descriptor.
    let sender = unsafe { OwnedFd::from_raw_fd(sender_fd) };
    assert_eq!(
        unsafe {
            libc::connect(
                sender.as_raw_fd(),
                std::ptr::from_ref(&bound).cast::<libc::sockaddr>(),
                bound_length,
            )
        },
        0,
        "connect UDP sender: {}",
        io::Error::last_os_error()
    );
    UdpPair { receiver, sender }
}

fn read_one_byte(fd: RawFd) -> u8 {
    let mut byte = 0u8;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let read = unsafe {
            libc::recv(
                fd,
                std::ptr::from_mut(&mut byte).cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        };
        if read == 1 {
            return byte;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EAGAIN) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        panic!("inherited fd produced no datagram (ret={read}, err={error})");
    }
}

#[test]
fn inherited_udp_fd_still_writes_but_new_udp_socket_is_denied() {
    let pair = udp_pair();
    let output = run_child(
        "inherited_udp_write_then_deny_new",
        Some(pair.sender.as_raw_fd()),
    );
    assert_installed(&output);
    assert!(
        output.status.success(),
        "child failed: status={:?} stdout={} stderr={}",
        output.status,
        stdout(&output),
        stderr(&output)
    );
    let out = stdout(&output);
    assert!(
        out.contains("INHERITED_WRITE_OK"),
        "write through the inherited UDP fd was not allowed: {out}"
    );
    assert!(
        out.contains("NEW_SOCKET_DENIED_EPERM"),
        "a new UDP socket was not denied: {out}"
    );
    assert_eq!(
        read_one_byte(pair.receiver.as_raw_fd()),
        b'I',
        "the inherited fd did not deliver its datagram"
    );
    println!(
        "BOREAS_SANDBOX_EVIDENCE arch={} case=inherited_udp_fd verdict=usable_new_socket_denied",
        env::consts::ARCH
    );
}

#[test]
fn inherited_af_unix_dgram_fd_still_writes() {
    let mut fds = [0i32; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
        0,
        "socketpair: {}",
        io::Error::last_os_error()
    );
    // SAFETY: `socketpair` returned two fresh, owned descriptors.
    let child_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let parent_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    let output = run_child("inherited_unix_dgram_write", Some(child_end.as_raw_fd()));
    assert_installed(&output);
    assert!(
        output.status.success(),
        "child failed: status={:?} stdout={} stderr={}",
        output.status,
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("INHERITED_WRITE_OK"),
        "write through the inherited AF_UNIX DGRAM fd was not allowed: {}",
        stdout(&output)
    );
    assert_eq!(
        read_one_byte(parent_end.as_raw_fd()),
        b'U',
        "the inherited AF_UNIX DGRAM fd did not deliver its datagram"
    );
    println!(
        "BOREAS_SANDBOX_EVIDENCE arch={} case=inherited_af_unix_dgram_fd verdict=usable",
        env::consts::ARCH
    );
}

// ---------------------------------------------------------------------------
// Child side. Only reached with `BOREAS_SANDBOX_CHILD_CASE` set; the parent
// re-executes this binary with `--exact child_worker`, so no other test runs
// in the filtered process.
// ---------------------------------------------------------------------------

fn emit(text: &str) {
    let bytes = text.as_bytes();
    let mut written = 0usize;
    while written < bytes.len() {
        let rest = &bytes[written..];
        let count = unsafe { libc::write(1, rest.as_ptr().cast(), rest.len()) };
        if count <= 0 {
            finish(EXIT_UNEXPECTED);
        }
        written += usize::try_from(count).expect("write returned a positive length");
    }
}

#[allow(unreachable_code)]
fn finish(code: i32) -> ! {
    // `exit_group` is on the filter's allowlist; libtest's atexit handlers are
    // not, so leave the process directly.
    unsafe { libc::_exit(code) };
    std::process::abort()
}

fn raw_socket(domain: i32, socket_type: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_socket, domain, socket_type, 0) }
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn expect_allowed(domain: i32, socket_type: i32) {
    let fd = raw_socket(domain, socket_type);
    if fd < 0 {
        emit("RESULT DENIED\n");
        finish(EXIT_UNEXPECTED);
    }
    unsafe { libc::close(i32::try_from(fd).expect("socket fd fits i32")) };
    emit("RESULT ALLOWED\n");
    finish(0);
}

fn expect_denied_eperm(domain: i32, socket_type: i32, protocol: i32) {
    let fd = unsafe { libc::syscall(libc::SYS_socket, domain, socket_type, protocol) };
    if fd >= 0 {
        unsafe { libc::close(i32::try_from(fd).expect("socket fd fits i32")) };
        emit("RESULT ALLOWED_UNEXPECTEDLY\n");
        finish(EXIT_UNEXPECTED);
    }
    if last_errno() == libc::EPERM {
        emit("RESULT DENIED_EPERM\n");
        finish(0);
    }
    emit("RESULT DENIED_OTHER_ERRNO\n");
    finish(EXIT_UNEXPECTED);
}

fn inherited_fd() -> RawFd {
    let fd = env::var(CHILD_FD)
        .ok()
        .and_then(|value| value.parse::<i32>().ok());
    let Some(fd) = fd else {
        emit("RESULT NO_INHERITED_FD\n");
        finish(EXIT_NO_FD);
    };
    fd
}

fn write_inherited(fd: RawFd, byte: u8) -> bool {
    let count = unsafe { libc::write(fd, std::ptr::from_ref(&byte).cast(), 1) };
    count == 1
}

#[test]
fn child_worker() {
    let Ok(case) = env::var(CHILD_CASE) else {
        // Ordinary `cargo test` run: this is the parent side.
        return;
    };
    // Read the inherited fd number before the filter forbids new syscalls
    // outside the allowlist.
    let inherited = env::var(CHILD_FD).ok().map(|_| inherited_fd());

    if let Err(error) = sandbox::install_current() {
        // Every error path leaves no filter attached (a failed TSYNC install
        // attaches nothing), so this formatting happens outside the filtered
        // region. After a successful install the child only uses `emit`
        // (write) and `finish` (_exit/exit_group), both allowlisted.
        emit(&format!("CHILD_INSTALL_FAILED {error}\n"));
        finish(EXIT_INSTALL_FAILED);
    }
    emit("CHILD_INSTALLED\n");

    match case.as_str() {
        "allow_af_unix_stream" => {
            expect_allowed(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC)
        }
        "deny_inet_udp_v4" => expect_denied_eperm(libc::AF_INET, libc::SOCK_DGRAM, 0),
        "deny_inet_udp_v6" => expect_denied_eperm(libc::AF_INET6, libc::SOCK_DGRAM, 0),
        "deny_inet_raw_v4" => expect_denied_eperm(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP),
        "deny_inet_raw_v6" => {
            expect_denied_eperm(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_TCP)
        }
        "deny_inet_stream_v4" => {
            expect_denied_eperm(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
        }
        "deny_unix_dgram" => expect_denied_eperm(libc::AF_UNIX, libc::SOCK_DGRAM, 0),
        "deny_unix_seqpacket" => expect_denied_eperm(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0),
        "kill_io_uring_setup" => {
            emit("CHILD_PRE_SYSCALL\n");
            let mut params = [0u8; 120];
            let result = unsafe { libc::syscall(IO_URING_SETUP, 2, params.as_mut_ptr()) };
            emit("RESULT RETURNED\n");
            let _ = result;
            finish(EXIT_UNEXPECTED);
        }
        "kill_io_uring_enter" => {
            emit("CHILD_PRE_SYSCALL\n");
            let result = unsafe {
                libc::syscall(
                    IO_URING_ENTER,
                    -1,
                    0,
                    0,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    0,
                )
            };
            emit("RESULT RETURNED\n");
            let _ = result;
            finish(EXIT_UNEXPECTED);
        }
        "kill_io_uring_register" => {
            emit("CHILD_PRE_SYSCALL\n");
            let result = unsafe {
                libc::syscall(
                    IO_URING_REGISTER,
                    -1,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    0,
                )
            };
            emit("RESULT RETURNED\n");
            let _ = result;
            finish(EXIT_UNEXPECTED);
        }
        "kill_x32_read" => {
            emit("CHILD_PRE_SYSCALL\n");
            let nr = (libc::SYS_read as u64) | X32_SYSCALL_BIT;
            let nr = libc::c_long::try_from(nr).expect("x32 syscall number fits c_long");
            let mut byte = 0u8;
            let result = unsafe {
                libc::syscall(
                    nr,
                    std::ptr::from_mut(&mut byte).cast::<libc::c_void>(),
                    1usize,
                )
            };
            emit("RESULT RETURNED\n");
            let _ = result;
            finish(EXIT_UNEXPECTED);
        }
        "kill_number_102" => {
            emit("CHILD_PRE_SYSCALL\n");
            let result = unsafe { libc::syscall(X86_32_SOCKETCALL, 1, 0, 0, 0, 0, 0) };
            emit("RESULT RETURNED\n");
            let _ = result;
            finish(EXIT_UNEXPECTED);
        }
        "inherited_udp_write_then_deny_new" => {
            let Some(fd) = inherited else {
                emit("RESULT NO_INHERITED_FD\n");
                finish(EXIT_NO_FD);
            };
            if !write_inherited(fd, b'I') {
                emit("INHERITED_WRITE_FAILED\n");
                finish(EXIT_UNEXPECTED);
            }
            emit("INHERITED_WRITE_OK\n");
            let new_fd =
                unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if new_fd >= 0 {
                unsafe { libc::close(i32::try_from(new_fd).expect("socket fd fits i32")) };
                emit("NEW_SOCKET_ALLOWED\n");
                finish(EXIT_UNEXPECTED);
            }
            if last_errno() == libc::EPERM {
                emit("NEW_SOCKET_DENIED_EPERM\n");
                finish(0);
            }
            emit("NEW_SOCKET_DENIED_OTHER_ERRNO\n");
            finish(EXIT_UNEXPECTED);
        }
        "inherited_unix_dgram_write" => {
            let Some(fd) = inherited else {
                emit("RESULT NO_INHERITED_FD\n");
                finish(EXIT_NO_FD);
            };
            if write_inherited(fd, b'U') {
                emit("INHERITED_WRITE_OK\n");
                finish(0);
            }
            emit("INHERITED_WRITE_FAILED\n");
            finish(EXIT_UNEXPECTED);
        }
        _ => {
            emit("CHILD_UNKNOWN_CASE\n");
            finish(EXIT_UNEXPECTED);
        }
    }
}
