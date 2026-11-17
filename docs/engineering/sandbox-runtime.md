# Sandbox runtime: enforcement and crash-recovery evidence

Status: **narrow vertical slice, not `G-SANDBOX`.** This page records what the
current supervisor seccomp policy actually proves on a native Linux ABI, what
the inherited-fd audit covers, and which crash-recovery negatives are now
exercised in CI. It does not describe a production daemon sandbox, because no
accepted Boreas daemon/worker installs this filter yet.

## Policy under test (unchanged)

The filter is built by `boreas_supervisor::sandbox::program` and installed by
`sandbox::install_current` (`PR_SET_NO_NEW_PRIVS`, then
`seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, …)`).

- Native `AUDIT_ARCH` only (`x86_64` or `AArch64`); any other audit arch is
  `SECCOMP_RET_KILL_PROCESS`.
- x86-64 also kills any syscall number with bit 30 set (x32).
- `io_uring_setup` / `io_uring_enter` / `io_uring_register` kill the process.
- Syscall number 102 kills the process (`socketcall` on i386; on the native
  ABIs it is `getuid`/`getitimer`, see the note below).
- `socket()` is allowed only for `AF_UNIX` + exactly
  `SOCK_STREAM | SOCK_CLOEXEC`. `AF_INET`/`AF_INET6` and every
  `SOCK_DGRAM`/`SOCK_RAW` shape return `EPERM`.
- A fixed allowlist (read/write/futex/mmap/… ) returns `ALLOW`; everything
  else returns `EPERM`.

This slice adds **tests only**. It does not relax, extend, or re-implement the
secure runtime policy, and it does not wire the filter into a daemon.

## Real child-process enforcement tests

Unit tests in `src/sandbox.rs` interpret the BPF program in userspace. The new
integration target `crates/boreas-supervisor/tests/sandbox_enforcement.rs`
re-executes the test binary as a child, installs the real filter, performs the
case's probe syscall(s), and lets the parent assert on the kernel's action
(`SIGSYS` or `EPERM`). A userspace interpreter bug cannot make these green.
After a successful install the child uses only `write` and `_exit`
(`exit_group`), both on the filter's allowlist; it does not call `println!`,
`std::process::exit` or the allocator in the filtered region.

| Case | Native x86-64 | Native AArch64 | Expected |
|---|---|---|---|
| `AF_UNIX` `SOCK_STREAM\|SOCK_CLOEXEC` | real child | real child | fd returned |
| `AF_INET`/`AF_INET6` `SOCK_DGRAM` | real child | real child | `EPERM` |
| `AF_INET`/`AF_INET6` `SOCK_RAW` | real child | real child | `EPERM` (an unfiltered unprivileged process also gets `EPERM`; corroborating, not isolating) |
| `AF_INET` stream, `AF_UNIX` DGRAM/SEQPACKET | real child | real child | `EPERM` (policy is stricter than the plan minimum) |
| `io_uring_setup`/`enter`/`register` | real child | real child | killed, `SIGSYS` |
| x32 syscall bit | real child | n/a (no x32 ABI) | killed, `SIGSYS` |
| syscall 102 | real child | real child | killed, `SIGSYS` (`getuid`/`getitimer` over-deny; see note) |
| ia32 / AArch32 compat audit arch | synthetic unit test only | synthetic unit test only | killed |

Why compat arch is synthetic: AArch64 cannot execute AArch32 from a 64-bit
process. On x86-64 a 64-bit process *can* enter ia32 compat through
`int 0x80`, but this slice does not issue that instruction, so it does not
claim real compat enforcement. The unit test feeds `AUDIT_ARCH_I386` /
`AUDIT_ARCH_ARM` directly to the interpreter. Proving compat rejection for
real needs either an `int 0x80` case (x86-64) or a 32-bit binary under the
same filter; that gap is stated rather than papered over.

Number-102 note: 102 is `socketcall` on i386/ARM-32, `getuid` on x86-64 and
`getitimer` on AArch64. Native socketcall does not exist on the two native
ABIs, compat is already rejected by the audit-arch check (x32 by bit 30), and
the native child test therefore records an over-deny of `getuid`/`getitimer`,
never socketcall enforcement. This slice records it as the current policy and
does **not** silently change it; removing the kill would need a policy review.

## Inherited-fd audit (probe process only)

A seccomp filter cannot revoke a descriptor the process already holds. The
fixture makes that concrete twice:

1. `tests/sandbox_enforcement.rs` creates, in the parent, a connected loopback
   UDP socket and an `AF_UNIX` `SOCK_DGRAM` `socketpair`, passes one fd to a
   real filtered child, and verifies:
   - writing through the inherited fd still succeeds;
   - creating a new UDP socket in the same child returns `EPERM`;
   - the datagram is actually delivered to the parent.
2. `tools/sandbox-audit/probe.c` creates a UDP pair, an `AF_UNIX` DGRAM pair,
   and (when the kernel allows it) an `io_uring` ring **before** installing
   the reference filter, then reports `inherited_udp_fd`,
   `inherited_unix_dgram_fd`, and `inherited_io_uring_ring`. Ring fd validity
   is checked with `fcntl(F_GETFD)` before the filter, because an outer ptrace
   sandbox can fabricate a successful `io_uring_setup`. The ring case is
   conditional: if ring creation is forbidden before the filter, the harness
   records it as setup-unavailable (and says so in the report reason) instead
   of pretending the ring was audited. Because these descriptors are created
   before the filter, the harness's `strace` contradiction check only looks at
   transcript lines after the filter install; a successful pre-filter
   `socket`/`io_uring_setup` is expected, not a contradiction.

What this proves: the tested filters do not retroactively close inherited
network fds or rings. What it does **not** prove: that a Boreas daemon has an
empty fd table, cleans inherited rings, or refuses `SCM_RIGHTS`. Those remain
daemon-side requirements, and `report.json` always records
`"inherited_fd_audit": "probe-process-only"` plus
`"production_daemon_audited": false`.

## Supervisor crash-recovery negative tests

`crates/boreas-supervisor/tests/readiness.rs` now drives the **real**
supervisor binary through two failure paths:

### SIGKILL mid-trial

1. A candidate is prepared and the supervisor is started with a readiness
   timeout larger than the test's observation window. The supervisor runs in
   its own process group so the candidate can be cleaned up deterministically.
2. A real candidate (`/bin/sh` script) creates a "started" file and then
   sleeps; it never answers readiness. Waiting for that file proves the
   candidate exists before the kill, not merely that the journal moved.
3. Once the journal is `Activated` and the active pointer names the candidate,
   the test sends `SIGKILL` to the supervisor (asserting the wait status really
   is signal 9).
4. Immediately after reaping the supervisor, the test `SIGKILL`s the whole
   process group. The supervisor cannot reap its child after being killed, so
   this is what prevents an orphaned candidate from surviving the test; a drop
   guard repeats the group kill if an assertion fails first.
5. Before recovery, the test asserts the on-disk state is still `Activated`
   with the pointer on the candidate and the trial reservation `in_flight`.
   Nothing may report the upgrade as confirmed.
6. A second real `supervise` invocation must recover before spawning: it rolls
   back to the retained old version, marks the attempt failed, and runs the
   caller-supplied steady program instead of retrying the unconfirmed
   candidate.
7. Assertions: active pointer `1.0.0`, journal `Prepared`, `attempts == 1`,
   `in_flight == false`, old version directory retained.

This also proves the store lock died with the killed process: the second
invocation is not blocked by a stale lock.

### Early candidate exit before readiness

The candidate exits non-zero immediately. The supervisor must exit non-zero,
diagnose "exited before readiness", roll the pointer back, keep the old version
active, and consume exactly one durable trial attempt (`in_flight == false`).
An early exit is not readiness and must never confirm an upgrade.

## CI wiring

`.github/workflows/sandbox-diagnostics.yml` runs two jobs on native
`ubuntu-24.04` (x86-64) and `ubuntu-24.04-arm` (aarch64):

- **Seccomp fixture audit + diagnostics**: the reference-fixture job, extended
  to require the inherited UDP/UNIX-dgram cases and, when ring creation is
  permitted, the inherited-ring case; it asserts
  `"inherited_fd_audit": "probe-process-only"`. A ring-setup refusal is
  recorded as setup-unavailable in the report reason, never as ring evidence.
- **Real seccomp child process + crash recovery**: clippy, the real
  child-process enforcement tests, the supervisor readiness/recovery tests,
  and hard assertions on the printed evidence markers
  (`BOREAS_SANDBOX_EVIDENCE …`, `BOREAS_SUPERVISOR_RECOVERY_EVIDENCE …`). A
  missing marker, a skipped test, or an `UNPROVEN` fixture run fails the job.
  The new steps use the reviewed action commits from
  `tools/dependencies/action-pins.json`; the floating-tag ceiling in
  `action-pins-inventory.json` is not raised.

All build, test, and format work for this slice runs in Actions. No local
`cargo build/test/fmt` result is claimed here.

## Honest limits

- Not `G-SANDBOX`: no production daemon installs the filter; no per-target
  release evidence exists.
- The child-process tests prove the kernel's action for **this** filter on
  **this** runner kernel; they are not a claim about every target kernel or
  every container runtime.
- The install path uses TSYNC. The Rust test harness may run the test on a
  helper thread, so TSYNC has to synchronize more than one thread, but this is
  not a multi-threaded daemon workload.
- The allowed `AF_UNIX` shape covers `socket()` creation only; `bind`,
  `listen` and `accept` are not on the allowlist, so this is not an
  end-to-end management-channel test.
- Compat ABI rejection is synthetic only (see above); the native number-102
  case is an over-deny record, not compat evidence.
- On an unprivileged runner a raw socket fails with `EPERM` even without the
  filter, so the raw cases corroborate the socket policy rather than
  isolating its raw rule.
- The inherited-ring fixture case is conditional on the host permitting ring
  creation before the filter; a skip is recorded, not silently passed.
- Inherited-fd audit is probe/process-local, not a daemon fd-table audit.
- The supervisor recovery tests cover journal/pointer behavior, not data-plane
  durability or service-manager restart policy.
