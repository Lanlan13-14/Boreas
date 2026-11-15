# sandbox-audit — seccomp reference-policy audit fixture

Implements the auditable part of master plan v1.11.0 §9.5 / Phase 3
`G-SANDBOX` that can land before a production daemon exists: a reference
seccomp policy, a probe that exercises it, and a fail-closed harness that
judges the result and writes an evidence directory.

## What this does and does not prove

| Claim | Status |
|---|---|
| The reference classic-BPF filter in `probe.c` denies INET/INET6 UDP (`SOCK_DGRAM`), `SOCK_RAW`, `io_uring_setup/enter/register` and `socketcall` (where present), and rejects non-native `AUDIT_ARCH`, on the host that ran it | Proved by a `PASS_FIXTURE` run on that host only |
| `AF_UNIX` `SOCK_STREAM`/`SOCK_SEQPACKET` and TCP `SOCK_STREAM` still work under the reference filter | Proved by the same run |
| Any Boreas daemon/worker installs this (or any) filter | **Not proved.** No accepted production daemon/worker exists yet |
| `G-SANDBOX` passed | **No.** `report.json` always records `"g_sandbox_production": "UNPROVEN"` |
| CI runner success equals production-environment success | **No** (plan §11: evidence per target environment) |

## Usage

```sh
sh tools/sandbox-audit/run-sandbox-audit.sh --out /tmp/audit --self-test
cat /tmp/audit/report.json
```

Exit codes: `0` all fixture cases matched the reference policy; `1` a case
violated the policy; `2` the environment cannot prove anything
(`UNPROVEN`, fail-closed — missing compiler, non-Linux, unsupported arch,
incomplete transcript, or a case denied with a non-`EPERM` errno, which
means something other than this filter did the denying); `3` usage error.

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
  `io_uring_register`, `socketcall` (x86-64; classic BPF cannot dereference
  its pointer argument, so it is rejected wholesale), and `socket()` with
  `(type & 0xf)` in {`SOCK_DGRAM`, `SOCK_RAW`} for **every** family.
- Stricter-than-plan note: the plan requires denying INET/INET6
  DGRAM/RAW. This fixture also denies `AF_UNIX` DGRAM (case
  `unix_dgram_strict`) because the single-argument check is simpler to
  audit. A daemon needing `AF_UNIX` DGRAM (e.g. some notify paths) must
  carry a reviewed two-argument filter and its own evidence; do not relax
  this fixture silently.
- The probe is single-threaded when it installs the filter, so TSYNC is
  not applicable and not claimed. A real multi-threaded daemon must use
  `SECCOMP_FILTER_FLAG_TSYNC` before creating threads (§9.5).

## Known environment trap: outer ptrace sandboxes (PRoot/Android)

On the Android/PRoot development host used for this change:

- The shell already runs under outer seccomp filters (`Seccomp_filters: 2`
  in `/proc/self/status`), and `io_uring_setup` returns `ENOSYS` even with
  **no** probe filter installed. The probe therefore reports
  `io_uring_setup` as `INCONCLUSIVE_DENIED_OTHER_ERRNO`, and the harness
  exits `2` (`UNPROVEN`, 11/12 cases) instead of printing PASS. That is
  the correct, honest result there.
- Under `strace` on that host, PRoot's ptrace emulation reports a
  fabricated `io_uring_setup(...) = 8` success. The harness detects a
  strace transcript that contradicts the direct probe and downgrades the
  run to `UNPROVEN` rather than trusting either transcript.

Run this in CI on a plain Linux runner (and later on each real target) for
a meaningful `PASS_FIXTURE`; see `.github/workflows/sandbox-diagnostics.yml`
and `docs/engineering/sandbox-audit-and-diagnostics.md`.

## Still required for real G-SANDBOX (not covered here)

Daemon/worker filter installation (incl. TSYNC and load order), inherited
fd / inherited `io_uring` ring cleanup, `SCM_RIGHTS` refusal, `AF_UNIX`
control-socket authentication (`0600` + `SO_PEERCRED`), system-resolver
UDP audit, capability drop ordering, per-ABI `strace` of the real daemon,
and post-upgrade re-audit. See the engineering doc for the checklist.
