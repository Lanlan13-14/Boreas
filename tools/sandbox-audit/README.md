# sandbox-audit — seccomp reference-policy audit fixture

Implements the auditable part of master plan v1.11.0 §9.5 / Phase 3
`G-SANDBOX` that can land before a production daemon exists: a reference
seccomp policy, a probe that exercises it, and a fail-closed harness that
judges the result and writes an evidence directory.

## What this does and does not prove

| Claim | Status |
|---|---|
| The reference classic-BPF filter in `probe.c` denies INET/INET6 UDP (`SOCK_DGRAM`), `SOCK_RAW` and `io_uring_setup/enter/register`, and rejects non-native `AUDIT_ARCH`, on the host that ran it. It contains a `__NR_socketcall` rule only on ABIs that define that number; the supported x86-64/AArch64 builds do not, so no native socketcall case is claimed | Proved by a `PASS_FIXTURE` run on that host only |
| `AF_UNIX` `SOCK_STREAM`/`SOCK_SEQPACKET` and TCP `SOCK_STREAM` still work under the reference filter | Proved by the same run |
| A connected UDP fd, an `AF_UNIX` `SOCK_DGRAM` fd and (when the kernel permits ring creation) an `io_uring` ring created **before** the filter remain usable/blocked exactly as reported; a host that forbids ring creation records that case as skipped, not passed | Proved by the same run, for the probe process only |
| Any Boreas daemon/worker installs this (or any) filter, cleans inherited fds/rings, or refuses `SCM_RIGHTS` | **Not proved.** No accepted production daemon/worker exists yet |
| `G-SANDBOX` passed | **No.** `report.json` always records `"g_sandbox_production": "UNPROVEN"` |
| CI runner success equals production-environment success | **No** (plan §11: evidence per target environment) |

## Usage

```sh
sh tools/sandbox-audit/run-sandbox-audit.sh --out /tmp/audit --self-test
cat /tmp/audit/report.json
```

Exit codes: `0` all required fixture cases matched the reference policy; `1` a case
violated the policy; `2` the environment cannot prove anything
(`UNPROVEN`, fail-closed — missing compiler, non-Linux, unsupported arch,
incomplete transcript, or a case denied with a non-`EPERM` errno, which
means something other than this filter did the denying); `3` usage error.
The inherited-ring case is conditional: when the kernel refuses to create the
ring before the filter, it is recorded as skipped in the report reason rather
than counted as evidence or as a policy failure.

`--self-test` also verifies the harness fails closed: missing compiler ⇒
exit 2 + `UNPROVEN`, `--target` refuses, non-empty `--out` refuses.

`--target PATH` is reserved for a future accepted daemon binary. It
currently refuses (exit 2). Auditing a real daemon needs a different
design (attach/`strace` a running worker, verify *its* installed filter,
fd inheritance and resolver behavior) and must not be faked by re-running
this fixture against a binary path.

## Reference policy (probe.c)

- `PR_SET_NO_NEW_PRIVS=1` before installing the filter.
- First instruction checks `AUDIT_ARCH`; only the native build arch is
  accepted (`AUDIT_ARCH_X86_64` or `AUDIT_ARCH_AARCH64`), per §9.5.
- Deny (`SECCOMP_RET_ERRNO|EPERM`): `io_uring_setup`, `io_uring_enter`,
  `io_uring_register`, and `socket()` with `(type & 0xf)` in
  {`SOCK_DGRAM`, `SOCK_RAW`} for **every** family. The i386/ARM-32
  `socketcall` rule is compiled only where `__NR_socketcall` exists; the
  supported x86-64/AArch64 probes do not define it, so this fixture never
  claims a native socketcall result.
- Stricter-than-plan note: the plan requires denying INET/INET6
  DGRAM/RAW. This fixture also denies `AF_UNIX` DGRAM (case
  `unix_dgram_strict`) because the single-argument check is simpler to
  audit. A daemon needing `AF_UNIX` DGRAM (e.g. some notify paths) must
  carry a reviewed two-argument filter and its own evidence; do not relax
  this fixture silently.
- The probe is single-threaded when it installs the filter, so TSYNC is
  not applicable and not claimed. A real multi-threaded daemon must use
  `SECCOMP_FILTER_FLAG_TSYNC` before creating threads (§9.5).

Boundary note: `inet_raw_v4`/`inet_raw_v6` also fail with `EPERM` for an
unprivileged process with no filter at all, so they corroborate the DGRAM
denials but do not by themselves isolate the raw rule.

## Inherited-fd audit (probe process only)

Before installing the filter the probe creates three things that no seccomp
filter can retroactively revoke:

- a connected loopback `AF_INET` `SOCK_DGRAM` socket,
- an `AF_UNIX` `SOCK_DGRAM` `socketpair`,
- an `io_uring` ring when the kernel permits it (the fd is validated with
  `fcntl(F_GETFD)` so a fabricated success from an outer ptrace sandbox is
  reported as `INCONCLUSIVE`, not as a usable ring). If ring creation is
  refused, the probe reports `INCONCLUSIVE_SETUP_FAILED` and the harness
  records the case as skipped.

After installation it reports whether those fds still work
(`inherited_udp_fd`, `inherited_unix_dgram_fd`, `inherited_io_uring_ring`).
The filter cannot revoke them: writes/reads through the pre-existing UDP and
UNIX-dgram fds succeed, while `io_uring_enter` on the pre-existing ring is
denied. That is why inherited-fd/ring cleanup is a required daemon-side step
and **not** something this fixture provides. The audit covers only the probe
process; it says nothing about a daemon's fd table, `SCM_RIGHTS` handling, or
whole-daemon isolation.

## Known environment trap: outer ptrace sandboxes (PRoot/Android)

On the Android/PRoot development host used for this change:

- The shell already runs under outer seccomp filters (`Seccomp_filters: 2`
  in `/proc/self/status`), and `io_uring_setup` returns `ENOSYS` even with
  **no** probe filter installed. The probe therefore reports
  `io_uring_setup` as `INCONCLUSIVE_DENIED_OTHER_ERRNO`, and the harness
  exits `2` (`UNPROVEN`) instead of printing PASS. That is the correct,
  honest result there.
- Under `strace` on that host, PRoot's ptrace emulation can report
  `socket`/`io_uring_setup` successes that the direct probe denied. The
  harness inspects only transcript lines after the filter install, so the
  probe's deliberate pre-filter setup is not mistaken for a contradiction; a
  post-filter success still downgrades the run to `UNPROVEN` rather than
  trusting either transcript.

Run this in CI on a plain Linux runner (and later on each real target) for
a meaningful `PASS_FIXTURE`; see `.github/workflows/sandbox-diagnostics.yml`
and `docs/engineering/sandbox-audit-and-diagnostics.md`.

## Still required for real G-SANDBOX (not covered here)

Daemon/worker filter installation (incl. TSYNC and load order), a real
inherited-fd audit of the daemon's own descriptor table (the probe's
inherited-fd section is fixture-only), inherited `io_uring` ring cleanup,
`SCM_RIGHTS` refusal, `AF_UNIX` control-socket authentication (`0600` +
`SO_PEERCRED`), system-resolver UDP audit, capability drop ordering, per-ABI
`strace` of the real daemon, and post-upgrade re-audit. See the engineering
doc for the checklist.
