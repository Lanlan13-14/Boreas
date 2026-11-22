# Sandbox audit & redacted diagnostics: evidence tooling for G-SANDBOX

Authority: master plan v1.11.0 (内部设计规范)
§9.5 (process 0-UDP and isolation boundary), §10.3 (preflight), §10.4
(telemetry/console, redacted diagnostics), §10.5 (service unit), and
Phase 3 gate `G-SANDBOX`. Where this note and the plan disagree, the plan
wins. Evidence labels below follow the plan's §"阅读约定" convention.

## Delivered tools

| Path | Purpose |
|---|---|
| `tools/sandbox-audit/probe.c` | Single-threaded C fixture: installs a reference classic-BPF seccomp filter (native-only `AUDIT_ARCH`, deny `SOCK_DGRAM`/`SOCK_RAW` sockets, `io_uring_{setup,enter,register}`, `socketcall` where present) and exercises 4 positive + 8 negative cases, one `CASE` line each |
| `tools/sandbox-audit/run-sandbox-audit.sh` | POSIX-sh harness: builds the probe (no libseccomp, no Rust workspace involvement), runs it directly and under `strace`, judges every required case, writes `report.json` + transcripts; fail-closed with `UNPROVEN` (exit 2) whenever the environment cannot prove the policy |
| `tools/diagnostics/collect-diagnostics.sh` | POSIX-sh redacted collector: OS/arch/kernel, pre-existing seccomp state, limits, fd counts by type (never targets), disk, toolchain versions, env-var presence (never values), optional binary SHA-256/ELF/sonames; final secret-shaped-pattern scan deletes the bundle on any hit |
| `.github/workflows/sandbox-diagnostics.yml` | Independent workflow (separate file, path-filtered): shellcheck, fixture audit + self-tests on native `ubuntu-24.04` (x86_64) and `ubuntu-24.04-arm` (aarch64) runners, honesty-field assertions, evidence artifact upload |

## Evidence level actually obtained

`[实测·本开发机]` Android/PRoot (aarch64, kernel 6.1.157-android14),
2026-11-15, running the exact commands in each tool's README:

- Probe direct run: 11/12 cases matched the reference policy — all UDP/RAW
  sockets (v4, v6, `SOCK_CLOEXEC`, `SOCK_NONBLOCK`, `AF_UNIX` DGRAM) denied
  with `EPERM` from the probe's own filter; `AF_UNIX` STREAM/SEQPACKET and
  TCP v4/v6 allowed; `Seccomp_filters` rose to 3 (2 pre-existing outer
  filters + the probe's).
- `io_uring_setup` on this host returns `ENOSYS` **even with no probe
  filter installed** (Android outer sandbox), so the case is
  `INCONCLUSIVE_DENIED_OTHER_ERRNO` and the harness exits 2 with
  `status: UNPROVEN`. It does not print PASS. This is the designed
  behavior, not a defect: a denial performed by an outer sandbox is not
  evidence about our filter.
- Under `strace` on this host, PRoot's ptrace layer fabricated
  `io_uring_setup(8, NULL) = 8`. The harness flags this as
  `contradicts-probe-outer-ptrace-suspected` and would downgrade to
  `UNPROVEN` on that ground alone. Lesson recorded for future target-ABI
  `strace` work: run it on a native host, never under PRoot.
- Self-tests passed on this host: missing compiler ⇒ exit 2 + `UNPROVEN`;
  `--target` refused; non-empty `--out` refused; diagnostics scan matched
  planted PEM/long-blob markers; shellcheck clean; `sh -n` clean.
- Diagnostics bundle collected on this host contains only the allowlisted
  sections and a verifiable `SHA256SUMS`.

`[待证]` A `PASS_FIXTURE` run (all 12 cases, incl. `io_uring_setup` denied
with `EPERM` by the probe filter itself) still requires a plain-Linux
host. The CI workflow is designed to produce exactly that on native
x86_64/aarch64 runners and to *fail the job* if the runner environment can
only produce `UNPROVEN`, so an unproven environment is visible rather than
green. Until that workflow run is observed, treat `PASS_FIXTURE` as not yet
demonstrated anywhere.

## What this does not prove — remaining G-SANDBOX work

`report.json` permanently records `"evidence_level":
"fixture-reference-filter"`, `"g_sandbox_production": "UNPROVEN"` and
`"production_daemon_audited": false`. The following plan requirements are
**not** addressed by this tooling and remain open for whoever builds the
daemon/worker sandbox:

1. The real Boreas binary/workers installing a filter at all, with §9.5
   load order (`PR_SET_NO_NEW_PRIVS` → filter → `SECCOMP_FILTER_FLAG_TSYNC`
   before thread creation; the fixture is single-threaded and does not
   exercise TSYNC).
2. Inherited-fd cleanup, including inherited `io_uring` rings (denying new
   rings does not neutralize inherited ones) and refusal of network fds
   via `SCM_RIGHTS`.
3. `AF_UNIX` control-socket authentication (`0600`, `SO_PEERCRED`) on the
   real management/notify paths.
4. System-resolver audit (no stealth UDP from NSS/resolver code paths) on
   the real binary.
5. Privilege-drop/capability ordering vs. the §10.5 unit, and the "do not
   call UDP-denial a complete sandbox" remainder (filesystem, namespaces,
   etc. per future design).
6. Per-target-ABI `strace` of the real daemon and post-upgrade re-audit
   (filters survive `exec`; §9.5 filter/exec compatibility, §10.3
   preflight seccomp-compatibility check).
7. x86-64-specific negative cases beyond the arch check: x32/compat ABI
   call attempts against the real filter (the fixture rejects non-native
   `AUDIT_ARCH` by construction, but no compat-ABI caller was exercised).
8. Diagnostics from the *daemon's* `/proc/<pid>/` (limits, fd summary,
   seccomp state) via a separately reviewed, authorized path; the
   collector here only describes the collecting shell by design.

## Operating rules for future evidence runs

- Never edit a `report.json` by hand; re-run the harness. A run's value is
  the co-located transcripts (`probe-output.txt`, `strace.txt`,
  `environment.txt`), not the status word alone.
- If a host yields `UNPROVEN`, record that; do not retry under a ptrace
  emulation layer hoping for green.
- When a production daemon exists, `--target` mode must be designed as an
  audit of the daemon's *installed* state (attached `strace`, negative
  syscall attempts against workers, fd/resolver checks). Pointing this
  fixture at a binary path would prove nothing and is refused today for
  exactly that reason.
