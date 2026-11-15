//! Classic seccomp-BPF filter builder for master plan §9.5 (进程 0-UDP 与隔离边界).
//!
//! # What this module is
//!
//! [`program`] builds a classic BPF `sock_filter` program (no libseccomp).
//! [`install_current`] tries to install that program on the calling Linux
//! thread group: `PR_SET_NO_NEW_PRIVS = 1`, then
//! `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, …)`. A failed
//! syscall returns the errno and does **not** mean the process is sandboxed.
//!
//! # What this module is not
//!
//! **Installing this filter is not `G-SANDBOX`, and it is not a complete
//! sandbox.** §9.5 also requires, and this module does none of:
//!
//! - cleanup of inherited file descriptors;
//! - refusal of `SCM_RIGHTS` (including inherited network fds and existing
//!   `io_uring` rings — a filter cannot revoke a ring the process already holds);
//! - dropping privileges / shrinking capabilities onto a dedicated user after
//!   the privileged TUN / route / `SO_MARK` setup path;
//! - an `strace` negative test on the target ABI.
//!
//! “0-UDP” only constrains sockets **this process** creates. It does not cover
//! user UDP carried inside the tunnel, synthetic DNS packets inside TUN, or
//! any other system process. Do not describe this filter as a complete sandbox
//! or as a passed `G-SANDBOX` gate.
//!
//! The filter is inherited across `exec` and cannot be withdrawn. A later
//! binary whose syscall set is not a subset of this allowlist must be started
//! by a controlled service restart, not by an in-place `exec` that assumes the
//! old filter will allow it.
//!
//! # Policy
//!
//! 1. Load `seccomp_data.arch` first. Accept only the native ABI of the
//!    selected [`TargetArch`]: `AUDIT_ARCH_X86_64` or `AUDIT_ARCH_AARCH64`.
//!    Every other architecture, including ia32 compat (`AUDIT_ARCH_I386`),
//!    returns `SECCOMP_RET_KILL_PROCESS`. x32 is not a distinct audit arch:
//!    the kernel reports `AUDIT_ARCH_X86_64` and sets bit 30 of the syscall
//!    number (`__X32_SYSCALL_BIT`). The x86-64 program kills that bit. ORing
//!    the bit into `AUDIT_ARCH_X86_64` does nothing, because that constant
//!    already has bit 30 set (`__AUDIT_ARCH_LE`).
//! 2. `io_uring_setup`, `io_uring_enter`, `io_uring_register` return
//!    `SECCOMP_RET_KILL_PROCESS`.
//! 3. The x86-32 `socketcall` syscall (number 102) is unconditionally
//!    `SECCOMP_RET_KILL_PROCESS`. Classic BPF cannot dereference the argument
//!    pointer that `socketcall` passes, so the family and type cannot be
//!    inspected. x86-64 and AArch64 do not use `socketcall`; killing number 102
//!    there also rejects a compat/x32 attempt that reuses that number.
//! 4. `socket` is allowed only when argument 0 is `AF_UNIX` **and** argument 1
//!    is exactly `SOCK_STREAM | SOCK_CLOEXEC`. `AF_INET` and `AF_INET6` are
//!    rejected. `SOCK_DGRAM` and `SOCK_RAW` are rejected on every family,
//!    including `AF_UNIX` (stricter than the plan's two-family minimum; the
//!    plan's type-mask rule is applied family-independently, matching the
//!    sandbox-audit fixture's choice). Any other socket shape returns
//!    `SECCOMP_RET_ERRNO | EPERM`.
//! 5. A fixed allowlist (read, write, exit, exit_group, futex, clock_gettime,
//!    getrandom, brk, mmap, munmap, mprotect, close, fcntl, ppoll, and poll
//!    where that ABI has it, rt_sigreturn) returns `SECCOMP_RET_ALLOW`.
//!    `socket`, `sendto`, `recvfrom`, and the `io_uring_*` calls are not on
//!    that list.
//! 6. Every other syscall number returns `SECCOMP_RET_ERRNO | EPERM`.
//!
//! Unit tests interpret the emitted instructions over synthetic
//! `seccomp_data`. They do not call [`install_current`]: this process may
//! already sit inside an outer sandbox, and a successful install cannot be
//! undone.

use std::fmt;
#[cfg(target_os = "linux")]
use std::io;

/// Classic BPF instruction count limit used by this slice (`linux/filter.h`
/// historically documents 4096; the §9.5 slice budget is 256).
pub const BPF_MAXINSNS: usize = 256;

/// `linux/audit.h` `AUDIT_ARCH_X86_64` (`EM_X86_64 | __AUDIT_ARCH_64BIT`).
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `linux/audit.h` `AUDIT_ARCH_AARCH64` (`EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// `linux/audit.h` / `arch/x86` `__X32_SYSCALL_BIT`.
///
/// x32 is not a distinct `seccomp_data.arch`: the kernel still reports
/// `AUDIT_ARCH_X86_64` and sets this bit in the syscall number. ORing it
/// into the audit word is a no-op (`AUDIT_ARCH_X86_64` already has bit 30
/// from `__AUDIT_ARCH_LE`). Compat ia32 is `AUDIT_ARCH_I386` and dies in the
/// arch compare.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// x86-32 multiplexed socket syscall. Not an x86-64 or AArch64 native number;
/// killed unconditionally because classic BPF cannot follow its argument pointer.
const X86_32_SOCKETCALL: u32 = 102;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

const EPERM: i32 = 1;

const BPF_LD: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_AND: u16 = 0x50;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

/// `offset_of!(seccomp_data, nr)`. `nr` is first; `arch` follows it.
const OFF_NR: u32 = 0;
/// `offset_of!(seccomp_data, arch)`.
const OFF_ARCH: u32 = 4;
/// `offset_of!(seccomp_data, args[0])`.
const OFF_ARG0: u32 = 16;
/// `offset_of!(seccomp_data, args[1])`.
const OFF_ARG1: u32 = 24;

const AF_UNIX: u32 = 1;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
/// `SOCK_CLOEXEC` on x86-64 and AArch64 (not MIPS).
const SOCK_CLOEXEC: u32 = 0o2_000_000;
const SOCK_TYPE_MASK: u32 = 0xf;

/// Only socket shape this slice allows.
const ALLOWED_SOCKET_TYPE: u32 = SOCK_STREAM | SOCK_CLOEXEC;

/// Return value of `SECCOMP_RET_ERRNO | EPERM`.
const RET_EPERM: u32 = SECCOMP_RET_ERRNO | ((EPERM as u32) & SECCOMP_RET_DATA);

/// ABI whose native syscall numbers the filter encodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetArch {
    /// Native x86-64 (`AUDIT_ARCH_X86_64`). x32 is rejected.
    X86_64,
    /// Native AArch64 (`AUDIT_ARCH_AARCH64`).
    Aarch64,
}

impl TargetArch {
    /// Architecture token the filter accepts in `seccomp_data.arch`.
    pub const fn audit_arch(self) -> u32 {
        match self {
            Self::X86_64 => AUDIT_ARCH_X86_64,
            Self::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    /// Native syscall numbers for this ABI. Numbers are the Linux generic
    /// (AArch64) and x86-64 tables; they are not read back from the host.
    const fn syscalls(self) -> SyscallTable {
        match self {
            Self::X86_64 => SyscallTable {
                read: 0,
                write: 1,
                close: 3,
                poll: Some(7),
                mmap: 9,
                mprotect: 10,
                munmap: 11,
                brk: 12,
                rt_sigreturn: 15,
                socket: 41,
                exit: 60,
                fcntl: 72,
                futex: 202,
                clock_gettime: 228,
                exit_group: 231,
                ppoll: 271,
                getrandom: 318,
                io_uring_setup: 425,
                io_uring_enter: 426,
                io_uring_register: 427,
            },
            Self::Aarch64 => SyscallTable {
                read: 63,
                write: 64,
                close: 57,
                // AArch64 has no `poll`; only `ppoll` (73).
                poll: None,
                mmap: 222,
                mprotect: 226,
                munmap: 215,
                brk: 214,
                rt_sigreturn: 139,
                socket: 198,
                exit: 93,
                fcntl: 25,
                futex: 98,
                clock_gettime: 113,
                exit_group: 94,
                ppoll: 73,
                getrandom: 278,
                io_uring_setup: 425,
                io_uring_enter: 426,
                io_uring_register: 427,
            },
        }
    }
}

/// Compile-target ABI. `None` on architectures this slice does not emit a filter for.
pub const fn native_target() -> Option<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Some(TargetArch::X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(TargetArch::Aarch64)
    } else {
        None
    }
}

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Clone, Copy)]
struct SyscallTable {
    read: u32,
    write: u32,
    close: u32,
    poll: Option<u32>,
    mmap: u32,
    mprotect: u32,
    munmap: u32,
    brk: u32,
    rt_sigreturn: u32,
    socket: u32,
    exit: u32,
    fcntl: u32,
    futex: u32,
    clock_gettime: u32,
    exit_group: u32,
    ppoll: u32,
    getrandom: u32,
    io_uring_setup: u32,
    io_uring_enter: u32,
    io_uring_register: u32,
}

impl SyscallTable {
    /// Syscalls that return `SECCOMP_RET_ALLOW` with no further inspection.
    /// `socket` is not included: it has its own argument checks. `sendto` and
    /// `recvfrom` are intentionally absent.
    const fn allowlist(self) -> [u32; 15] {
        [
            self.read,
            self.write,
            self.exit,
            self.exit_group,
            self.futex,
            self.clock_gettime,
            self.getrandom,
            self.brk,
            self.mmap,
            self.munmap,
            self.mprotect,
            self.close,
            self.fcntl,
            self.ppoll,
            self.rt_sigreturn,
        ]
    }
}

/// Why [`install_current`] did not establish a sandbox.
#[derive(Debug)]
pub enum SandboxError {
    /// This OS cannot install a Linux seccomp filter. The process is unchanged.
    Unsupported,
    /// `PR_SET_NO_NEW_PRIVS` failed. The filter was not installed.
    NoNewPrivs(i32),
    /// The seccomp syscall failed. The process must be treated as unsandboxed,
    /// even if `NO_NEW_PRIVS` was set.
    Seccomp(i32),
    /// The compile target is not x86-64 or AArch64, so no native filter exists.
    UnsupportedArch,
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str(
                "seccomp filter install is unsupported on this OS; process is not sandboxed",
            ),
            Self::NoNewPrivs(err) => write!(
                f,
                "PR_SET_NO_NEW_PRIVS failed with errno {err}; seccomp filter was not installed"
            ),
            Self::Seccomp(err) => write!(
                f,
                "seccomp FILTER+TSYNC failed with errno {err}; process is not sandboxed"
            ),
            Self::UnsupportedArch => f.write_str(
                "no native seccomp filter for this architecture; process is not sandboxed",
            ),
        }
    }
}

impl std::error::Error for SandboxError {}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump_eq(value: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k: value,
    }
}

fn ret(action: u32) -> SockFilter {
    stmt(BPF_RET | BPF_K, action)
}

/// Build the classic BPF program for `target`.
///
/// The program is at most [`BPF_MAXINSNS`] instructions. Jump offsets are
/// relative to the next instruction, matching `linux/filter.h`.
pub fn program(target: TargetArch) -> Vec<SockFilter> {
    let sys = target.syscalls();
    let allow = sys.allowlist();
    // Fixed prefix (arch, three io_uring kills, socketcall kill) plus one
    // compare per allowlisted number plus the socket argument block plus the
    // default errno return. `poll` adds one compare on ABIs that have it.
    let mut insns = Vec::with_capacity(4 + 6 + allow.len() + 1 + 12);

    // 1. Architecture. Anything other than the native audit arch is killed.
    //    That includes ia32 compat (`AUDIT_ARCH_I386`). x32 is not a separate
    //    audit arch; it is rejected below via bit 30 of the syscall number.
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    insns.push(jump_eq(target.audit_arch(), 1, 0));
    insns.push(ret(SECCOMP_RET_KILL_PROCESS));

    // 2. Syscall number. A fresh LD ABS replaces A; the arch word is not reused.
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    if target == TargetArch::X86_64 {
        // x32 shares AUDIT_ARCH_X86_64. Kill when bit 30 of `nr` is set,
        // then reload the full number for the comparisons below.
        insns.push(stmt(BPF_ALU | BPF_AND | BPF_K, X32_SYSCALL_BIT));
        insns.push(jump_eq(0, 1, 0));
        insns.push(ret(SECCOMP_RET_KILL_PROCESS));
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    }

    // 3. io_uring trio: kill, do not merely return EPERM.
    for nr in [
        sys.io_uring_setup,
        sys.io_uring_enter,
        sys.io_uring_register,
    ] {
        insns.push(jump_eq(nr, 0, 1));
        insns.push(ret(SECCOMP_RET_KILL_PROCESS));
    }

    // 4. x86-32 socketcall. Unconditional kill: the argument pointer is not
    //    dereferenced by classic BPF.
    insns.push(jump_eq(X86_32_SOCKETCALL, 0, 1));
    insns.push(ret(SECCOMP_RET_KILL_PROCESS));

    // 5. Allowlist. Each hit skips the rest of the compares and the socket
    //    block, landing on the final ALLOW. Offsets are filled after the
    //    socket block exists, because its length is known only then.
    let allow_at = insns.len();
    for nr in allow {
        insns.push(jump_eq(nr, 0, 0));
    }
    if let Some(nr) = sys.poll {
        insns.push(jump_eq(nr, 0, 0));
    }
    let allow_end = insns.len();

    // 6. socket: fall through only when the number matches; otherwise the
    //    default EPERM return (one instruction past the socket block).
    insns.push(jump_eq(sys.socket, 0, 0));
    let socket_jump_at = insns.len() - 1;

    // Family must be AF_UNIX. The low 32 bits are what classic BPF loads.
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
    insns.push(jump_eq(AF_UNIX, 1, 0));
    insns.push(ret(RET_EPERM));

    // Type must be exactly SOCK_STREAM|SOCK_CLOEXEC. Masking to the low
    // nibble rejects DGRAM and RAW on every family (including AF_UNIX) even
    // when SOCK_CLOEXEC / SOCK_NONBLOCK are OR-ed in; the exact compare then
    // rejects SEQPACKET, bare STREAM, and any other flag combination.
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1));
    insns.push(stmt(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK));
    insns.push(jump_eq(SOCK_DGRAM, 0, 1));
    insns.push(ret(RET_EPERM));
    insns.push(jump_eq(SOCK_RAW, 0, 1));
    insns.push(ret(RET_EPERM));
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1));
    insns.push(jump_eq(ALLOWED_SOCKET_TYPE, 1, 0));
    insns.push(ret(RET_EPERM));
    let allow_ret_at = insns.len();
    insns.push(ret(SECCOMP_RET_ALLOW));

    let default_at = insns.len();
    insns.push(ret(RET_EPERM));

    // Allowlist hits jump to the shared ALLOW return.
    let allow_skip = u8::try_from(allow_ret_at - allow_at - 1).expect("allow jump fits in u8");
    for (i, insn) in insns.iter_mut().enumerate().take(allow_end).skip(allow_at) {
        let jt = allow_skip - u8::try_from(i - allow_at).expect("allow index fits");
        insn.jt = jt;
        insn.jf = 0;
    }

    // Non-socket numbers skip the socket block to the default EPERM return.
    let socket_skip = u8::try_from(default_at - socket_jump_at - 1).expect("socket jump fits");
    insns[socket_jump_at].jt = 0;
    insns[socket_jump_at].jf = socket_skip;

    debug_assert!(insns.len() <= BPF_MAXINSNS);
    debug_assert!(insns.len() < 256, "jt/jf offsets must fit in u8");
    insns
}

/// Linux install passes `libc::sock_filter`, whose `#[repr(C)]` layout is the
/// kernel's. [`SockFilter`] is the safe builder's copy and is not what the
/// syscall receives.
#[cfg(target_os = "linux")]
fn to_libc_filters(prog: &[SockFilter]) -> Vec<libc::sock_filter> {
    prog.iter()
        .map(|insn| libc::sock_filter {
            code: insn.code,
            jt: insn.jt,
            jf: insn.jf,
            k: insn.k,
        })
        .collect()
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
///
/// The only `unsafe` here is the `libc::syscall` call. `PR_SET_NO_NEW_PRIVS`
/// takes no pointer; the five arguments are the option and the four integer
/// operands from the prctl man page.
#[cfg(target_os = "linux")]
fn prctl_no_new_privs() -> i64 {
    // SAFETY: no pointer argument; see the function comment.
    unsafe { libc::syscall(libc::SYS_prctl, 38i64, 1i64, 0i64, 0i64, 0i64) }
}

/// `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, prog)`.
///
/// The only `unsafe` here is the `libc::syscall` call. `prog` must point at a
/// live `libc::sock_fprog` whose `filter` pointer addresses `len` instructions
/// for the duration of the call. The kernel copies those instructions before
/// returning.
#[cfg(target_os = "linux")]
fn seccomp_filter_tsync(prog: *const libc::sock_fprog) -> i64 {
    // SECCOMP_SET_MODE_FILTER = 1, SECCOMP_FILTER_FLAG_TSYNC = 1.
    // SAFETY: caller keeps `prog` and its filter buffer alive; see the function comment.
    unsafe { libc::syscall(libc::SYS_seccomp, 1i64, 1i64, prog) }
}

/// Install [`program`] for the compile target on this process.
///
/// Linux only. Order is fixed: `PR_SET_NO_NEW_PRIVS`, then
/// `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &sock_fprog)`.
/// `TSYNC` applies the filter to every thread in the thread group; if any
/// sibling cannot be synchronized the syscall fails and this function returns
/// that errno without claiming the caller is sandboxed.
///
/// Must be called before the process creates threads it expects to be covered,
/// and only after privileged setup that needs syscalls outside the allowlist.
/// Failure leaves the process unsandboxed (apart from `NO_NEW_PRIVS` if that
/// step succeeded and the seccomp step then failed — still not a sandbox).
///
/// The only `unsafe` in this module is the two `libc::syscall` wrappers above.
#[cfg(target_os = "linux")]
pub fn install_current() -> Result<(), SandboxError> {
    let Some(target) = native_target() else {
        return Err(SandboxError::UnsupportedArch);
    };
    let built = program(target);
    if built.is_empty() || built.len() > BPF_MAXINSNS {
        return Err(SandboxError::UnsupportedArch);
    }
    let len = u16::try_from(built.len()).map_err(|_| SandboxError::UnsupportedArch)?;
    let mut filters = to_libc_filters(&built);

    let nnp = prctl_no_new_privs();
    if nnp != 0 {
        return Err(SandboxError::NoNewPrivs(last_errno()));
    }

    let fprog = libc::sock_fprog {
        len,
        filter: filters.as_mut_ptr(),
    };
    // `fprog` and `filters` stay in this frame for the call.
    let installed = seccomp_filter_tsync(&fprog);
    if installed != 0 {
        return Err(SandboxError::Seccomp(last_errno()));
    }
    Ok(())
}

/// Non-Linux: installing a seccomp filter is unsupported. The process is not
/// modified and the error must not be treated as success.
#[cfg(not(target_os = "linux"))]
pub fn install_current() -> Result<(), SandboxError> {
    let _ = native_target();
    Err(SandboxError::Unsupported)
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(EPERM)
}

/// Userspace classic-BPF interpreter covering only the opcodes [`program`] emits:
/// `LD W ABS`, `ALU AND K`, `JMP JEQ K`, `RET K`. No packet loads, no memory,
/// no `LDX`. Used by unit tests; not a general BPF implementation.
pub fn eval(prog: &[SockFilter], data: &[u8]) -> Result<u32, &'static str> {
    if prog.is_empty() || prog.len() > BPF_MAXINSNS {
        return Err("program length out of range");
    }
    let mut acc: u32 = 0;
    let mut pc: usize = 0;
    for _ in 0..prog.len().saturating_mul(4).saturating_add(1) {
        let insn = prog.get(pc).ok_or("pc out of range")?;
        let class = insn.code & 0x07;
        match class {
            BPF_LD => {
                if insn.code != BPF_LD | BPF_W | BPF_ABS {
                    return Err("unsupported ld");
                }
                let off = insn.k as usize;
                let bytes: [u8; 4] = data
                    .get(off..off + 4)
                    .ok_or("ld out of range")?
                    .try_into()
                    .map_err(|_| "ld width")?;
                acc = u32::from_le_bytes(bytes);
                pc += 1;
            }
            BPF_ALU => {
                if insn.code != BPF_ALU | BPF_AND | BPF_K {
                    return Err("unsupported alu");
                }
                acc &= insn.k;
                pc += 1;
            }
            BPF_JMP => {
                if insn.code != BPF_JMP | BPF_JEQ | BPF_K {
                    return Err("unsupported jmp");
                }
                let offset = if acc == insn.k { insn.jt } else { insn.jf };
                pc = pc
                    .checked_add(1)
                    .and_then(|n| n.checked_add(usize::from(offset)))
                    .ok_or("jmp overflow")?;
            }
            BPF_RET => {
                if insn.code != BPF_RET | BPF_K {
                    return Err("unsupported ret");
                }
                return Ok(insn.k);
            }
            _ => return Err("unsupported class"),
        }
    }
    Err("step limit")
}

/// Synthetic `seccomp_data`: `nr`, `arch`, `instruction_pointer`, `args[6]`.
pub fn seccomp_data(nr: u32, arch: u32, args: [u64; 6]) -> [u8; 64] {
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&nr.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    // instruction_pointer left zero; this filter never reads it.
    for (i, arg) in args.iter().enumerate() {
        let off = 16 + i * 8;
        data[off..off + 8].copy_from_slice(&arg.to_le_bytes());
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(prog: &[SockFilter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        eval(prog, &seccomp_data(nr, arch, args)).expect("eval")
    }

    fn is_eperm(action: u32) -> bool {
        action == RET_EPERM
    }

    #[test]
    fn x86_64_allows_read_and_rejects_aarch64_arch() {
        let prog = program(TargetArch::X86_64);
        assert!(prog.len() <= BPF_MAXINSNS);
        let read = TargetArch::X86_64.syscalls().read;
        // x86-64 `read` is syscall 0. Pass a non-zero dummy argument so a
        // filter that forgot to load `nr` (and compared A against the zero
        // argument slot) cannot look like a successful allow.
        let args = [0x1111, 0, 0, 0, 0, 0];
        assert_eq!(
            action(&prog, read, AUDIT_ARCH_X86_64, args),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            action(&prog, read, AUDIT_ARCH_AARCH64, args),
            SECCOMP_RET_KILL_PROCESS
        );
        // x32 keeps AUDIT_ARCH_X86_64 and sets bit 30 of the syscall number.
        assert_eq!(
            action(&prog, read | X32_SYSCALL_BIT, AUDIT_ARCH_X86_64, args),
            SECCOMP_RET_KILL_PROCESS
        );
        // ia32 compat is a different audit arch.
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        assert_eq!(
            action(&prog, read, AUDIT_ARCH_I386, args),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn aarch64_allows_read_and_rejects_x86_64_arch() {
        let prog = program(TargetArch::Aarch64);
        assert!(prog.len() <= BPF_MAXINSNS);
        let read = TargetArch::Aarch64.syscalls().read;
        assert_eq!(
            action(&prog, read, AUDIT_ARCH_AARCH64, [0; 6]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            action(&prog, read, AUDIT_ARCH_X86_64, [0; 6]),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 10;

    fn socket_args(family: u32, sock_type: u32) -> [u64; 6] {
        let mut args = [0u64; 6];
        args[0] = u64::from(family);
        args[1] = u64::from(sock_type);
        args
    }

    #[test]
    fn socket_af_unix_stream_cloexec_allowed() {
        for target in [TargetArch::X86_64, TargetArch::Aarch64] {
            let prog = program(target);
            let nr = target.syscalls().socket;
            assert_eq!(
                action(
                    &prog,
                    nr,
                    target.audit_arch(),
                    socket_args(AF_UNIX, ALLOWED_SOCKET_TYPE),
                ),
                SECCOMP_RET_ALLOW,
                "{target:?}"
            );
        }
    }

    #[test]
    fn socket_inet_and_dgram_and_raw_rejected() {
        for target in [TargetArch::X86_64, TargetArch::Aarch64] {
            let prog = program(target);
            let nr = target.syscalls().socket;
            let arch = target.audit_arch();
            let cases = [
                socket_args(AF_INET, SOCK_STREAM),
                socket_args(AF_INET, SOCK_STREAM | SOCK_CLOEXEC),
                socket_args(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC),
                socket_args(AF_UNIX, SOCK_DGRAM),
                socket_args(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC),
                socket_args(AF_UNIX, SOCK_RAW),
                socket_args(AF_INET, SOCK_DGRAM),
                socket_args(AF_INET, SOCK_RAW),
                // Bare STREAM is not the one accepted shape.
                socket_args(AF_UNIX, SOCK_STREAM),
            ];
            for args in cases {
                let got = action(&prog, nr, arch, args);
                assert!(
                    is_eperm(got) || got == SECCOMP_RET_KILL_PROCESS,
                    "{target:?} args={args:?} action={got:#x}"
                );
                assert!(is_eperm(got), "{target:?} socket deny should be EPERM");
            }
        }
    }

    #[test]
    fn io_uring_setup_is_kill() {
        for target in [TargetArch::X86_64, TargetArch::Aarch64] {
            let prog = program(target);
            let sys = target.syscalls();
            for nr in [
                sys.io_uring_setup,
                sys.io_uring_enter,
                sys.io_uring_register,
            ] {
                assert_eq!(
                    action(&prog, nr, target.audit_arch(), [8, 0, 0, 0, 0, 0]),
                    SECCOMP_RET_KILL_PROCESS,
                    "{target:?} nr={nr}"
                );
            }
        }
    }

    #[test]
    fn socketcall_is_kill_on_both_filters() {
        for target in [TargetArch::X86_64, TargetArch::Aarch64] {
            let prog = program(target);
            assert_eq!(
                action(
                    &prog,
                    X86_32_SOCKETCALL,
                    target.audit_arch(),
                    [1, 0, 0, 0, 0, 0]
                ),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn unknown_syscall_is_eperm() {
        for target in [TargetArch::X86_64, TargetArch::Aarch64] {
            let prog = program(target);
            // 0xFFFF is not a real syscall on either ABI.
            let got = action(&prog, 0xFFFF, target.audit_arch(), [0; 6]);
            assert!(is_eperm(got), "{target:?} got {got:#x}");
            // sendto / recvfrom stay off the allowlist.
            let (sendto, recvfrom) = match target {
                TargetArch::X86_64 => (44u32, 45u32),
                TargetArch::Aarch64 => (206u32, 207u32),
            };
            assert!(is_eperm(action(&prog, sendto, target.audit_arch(), [0; 6])));
            assert!(is_eperm(action(
                &prog,
                recvfrom,
                target.audit_arch(),
                [0; 6]
            )));
        }
    }

    #[test]
    fn allowlist_numbers_are_allowed_and_program_is_bounded() {
        for target in [TargetArch::X86_64, TargetArch::Aarch64] {
            let prog = program(target);
            assert!(prog.len() <= BPF_MAXINSNS, "{}", prog.len());
            let sys = target.syscalls();
            for nr in sys.allowlist() {
                assert_eq!(
                    action(&prog, nr, target.audit_arch(), [0; 6]),
                    SECCOMP_RET_ALLOW,
                    "{target:?} nr={nr}"
                );
            }
            if let Some(nr) = sys.poll {
                assert_eq!(
                    action(&prog, nr, target.audit_arch(), [0; 6]),
                    SECCOMP_RET_ALLOW
                );
            } else {
                // AArch64 must not treat the x86-64 poll number as allow.
                assert!(is_eperm(action(&prog, 7, target.audit_arch(), [0; 6])));
            }
        }
    }

    #[test]
    fn install_current_is_not_invoked_by_these_tests() {
        // Compiles the non-installing path only. Calling install_current from
        // a unit test would apply an irreversible filter to this process.
        let _ = std::any::type_name::<fn() -> Result<(), SandboxError>>();
        assert!(
            native_target().is_some()
                || !cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
        );
    }
}
