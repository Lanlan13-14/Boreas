#!/bin/sh
# Boreas sandbox-audit harness (master plan v1.11.0, section 9.5 / G-SANDBOX).
#
# Usage:
#   run-sandbox-audit.sh [--out DIR] [--self-test]
#   run-sandbox-audit.sh --target /path/to/boreas  (reserved; currently refuses)
#
# Modes:
#   (default)   Build probe.c and audit the reference filter against the
#               positive/negative case matrix. This audits the harness and
#               the reference policy only. It does NOT audit a Boreas
#               daemon/worker and never claims G-SANDBOX passed.
#   --self-test Additionally verify the harness fails closed: running with
#               a missing compiler must exit 2 with status UNPROVEN (never
#               PASS), --target must refuse, and a non-empty --out
#               directory must be refused.
#   --target    Reserved for a future accepted daemon binary. There is no
#               accepted production daemon yet, so this mode currently
#               refuses to run (exit 2, UNPROVEN) instead of pretending.
#
# Exit codes:
#   0  every required case produced its expected verdict (fixture level)
#   1  at least one case violated the reference policy (FAIL)
#   2  environment/tooling cannot prove anything (UNPROVEN, fail-closed)
#   3  usage error
#
# Output: writes an evidence directory containing probe output, optional
# strace transcript, environment facts and report.json. The report always
# states evidence_level=fixture-reference-filter and
# g_sandbox_production=UNPROVEN. A CI runner passing this script is not
# production-environment evidence (plan section 11).
set -eu
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
OUT_DIR=""
SELF_TEST=0
TARGET=""

usage() {
    echo "usage: $0 [--out DIR] [--self-test] [--target PATH]" >&2
    exit 3
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out) [ $# -ge 2 ] || usage; OUT_DIR=$2; shift 2 ;;
        --self-test) SELF_TEST=1; shift ;;
        --target) [ $# -ge 2 ] || usage; TARGET=$2; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

# --- Reserved target mode: fail closed until a real daemon exists. ---------
if [ -n "$TARGET" ]; then
    echo "UNPROVEN: --target mode is not implemented; no accepted Boreas daemon/worker exists to audit." >&2
    echo "UNPROVEN: refusing to imply production G-SANDBOX evidence for: $TARGET" >&2
    exit 2
fi

if [ -z "$OUT_DIR" ]; then
    OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/boreas-sandbox-audit.XXXXXX")
else
    mkdir -p "$OUT_DIR"
    # Refuse to reuse a non-empty evidence dir: stale files could fake a pass.
    if [ -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]; then
        echo "UNPROVEN: --out directory is not empty (refusing stale evidence): $OUT_DIR" >&2
        exit 2
    fi
fi
REPORT="$OUT_DIR/report.json"
PROBE_OUT="$OUT_DIR/probe-output.txt"
ENV_OUT="$OUT_DIR/environment.txt"
STRACE_OUT="$OUT_DIR/strace.txt"
STATUS="UNPROVEN"
REASON="not run"

write_report() {
    # $1=status $2=reason $3=cases_ok $4=cases_required $5=strace_note
    # Values are harness-generated (no quotes/backslashes by construction);
    # keep them that way: reason strings below avoid '"' and '\'.
    {
        echo '{'
        echo '  "tool": "boreas-sandbox-audit",'
        echo '  "schema": 1,'
        echo "  \"status\": \"$1\","
        echo "  \"reason\": \"$2\","
        echo '  "evidence_level": "fixture-reference-filter",'
        echo '  "g_sandbox_production": "UNPROVEN",'
        echo '  "production_daemon_audited": false,'
        echo '  "inherited_fd_audit": "probe-process-only",'
        echo "  \"cases_ok\": $3,"
        echo "  \"cases_required\": $4,"
        echo "  \"strace\": \"$5\","
        echo "  \"arch\": \"$(uname -m 2>/dev/null || echo unknown)\","
        kernel_name=$(uname -sr 2>/dev/null || echo unknown)
        echo "  \"kernel\": \"$kernel_name\""
        echo '}'
    } > "$REPORT"
}

finish() {
    # $1=exit code. Always leave a report behind, even on failure.
    write_report "$STATUS" "$REASON" "${CASES_OK:-0}" "${CASES_REQUIRED:-0}" "${STRACE_NOTE:-not-run}"
    echo "sandbox-audit: status=$STATUS cases=${CASES_OK:-0}/${CASES_REQUIRED:-0} out=$OUT_DIR"
    echo "sandbox-audit: evidence_level=fixture-reference-filter g_sandbox_production=UNPROVEN"
    exit "$1"
}

# --- Environment facts (no secrets; host facts only). -----------------------
{
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
    echo "uname: $(uname -a 2>/dev/null || echo unknown)"
    echo "arch: $(uname -m 2>/dev/null || echo unknown)"
    if [ -r /proc/self/status ]; then
        grep -E '^(NoNewPrivs|Seccomp|Seccomp_filters):' /proc/self/status || true
    fi
    echo "note: if Seccomp_filters > 0 before the probe runs, an outer sandbox"
    echo "note: (container/Android/PRoot) is present and may mask results."
} > "$ENV_OUT" 2>/dev/null || true

# --- Toolchain preflight: missing tools => UNPROVEN, exit 2. Never PASS. ----
CC_BIN=${CC:-cc}
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
    STATUS="UNPROVEN"; REASON="missing C compiler ($CC_BIN); cannot build probe"
    finish 2
fi
if [ "$(uname -s 2>/dev/null || echo unknown)" != "Linux" ]; then
    STATUS="UNPROVEN"; REASON="seccomp audit requires Linux"
    finish 2
fi
case "$(uname -m 2>/dev/null || echo unknown)" in
    x86_64|aarch64|arm64) : ;;
    *) STATUS="UNPROVEN"; REASON="unsupported audit arch; plan targets x86_64/aarch64 only"; finish 2 ;;
esac

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/boreas-probe-build.XXXXXX")
# Invoked indirectly via trap below.
# shellcheck disable=SC2317
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT INT TERM

if ! "$CC_BIN" -O2 -Wall -Wextra -Werror -o "$WORK_DIR/probe" "$SCRIPT_DIR/probe.c" >"$OUT_DIR/build.log" 2>&1; then
    STATUS="UNPROVEN"; REASON="probe build failed; see build.log"
    finish 2
fi

# --- Run the probe. ----------------------------------------------------------
set +e
"$WORK_DIR/probe" > "$PROBE_OUT" 2>&1
PROBE_EXIT=$?
set -e
echo "probe_exit=$PROBE_EXIT" >> "$ENV_OUT"
if [ "$PROBE_EXIT" -eq 3 ]; then
    STATUS="UNPROVEN"; REASON="probe reported unsupported environment or filter install failure"
    finish 2
fi
if [ "$PROBE_EXIT" -ne 0 ]; then
    STATUS="FAIL"; REASON="probe exited abnormally"
    finish 1
fi
if ! grep -q '^FILTER_INSTALLED ' "$PROBE_OUT" || ! grep -q '^PROBE_DONE$' "$PROBE_OUT"; then
    STATUS="UNPROVEN"; REASON="probe transcript incomplete (filter not confirmed installed)"
    finish 2
fi

# --- Judge the case matrix. Every required case must appear with an OK_*. ---
REQUIRED_CASES="unix_stream unix_seqpacket tcp_stream_v4 tcp_stream_v6 inet_udp_v4 inet_udp_v6 inet_udp_cloexec inet_udp_nonblock inet_raw_v4 inet_raw_v6 unix_dgram_strict io_uring_setup io_uring_enter io_uring_register inherited_udp_fd inherited_unix_dgram_fd"
CASES_REQUIRED=0
CASES_OK=0
CASES_FAIL=""
CASES_INCONCLUSIVE=""
CASES_SKIPPED=""
for case_name in $REQUIRED_CASES; do
    CASES_REQUIRED=$((CASES_REQUIRED + 1))
    line=$(grep "^CASE $case_name result=" "$PROBE_OUT" || true)
    if [ -z "$line" ]; then
        CASES_FAIL="$CASES_FAIL $case_name(missing)"
        continue
    fi
    case "$line" in
        *" result=OK_"*) CASES_OK=$((CASES_OK + 1)) ;;
        *" result=INCONCLUSIVE_"*) CASES_INCONCLUSIVE="$CASES_INCONCLUSIVE $case_name" ;;
        *) CASES_FAIL="$CASES_FAIL $case_name" ;;
    esac
done

# The inherited-ring case is conditional: creating a ring before installing
# the filter requires kernel policy to permit io_uring_setup. A host that
# forbids it records setup-unavailable instead of claiming ring evidence. If
# a ring was created, the filter must still block further io_uring_enter.
RING_LINE=$(grep '^CASE inherited_io_uring_ring result=' "$PROBE_OUT" || true)
if [ -z "$RING_LINE" ]; then
    CASES_FAIL="$CASES_FAIL inherited_io_uring_ring(missing)"
else
    case "$RING_LINE" in
        *" result=OK_"*)
            CASES_REQUIRED=$((CASES_REQUIRED + 1))
            CASES_OK=$((CASES_OK + 1))
            ;;
        *" result=INCONCLUSIVE_SETUP_FAILED"*)
            CASES_SKIPPED="$CASES_SKIPPED inherited_io_uring_ring(setup-unavailable)"
            ;;
        *" result=INCONCLUSIVE_"*)
            CASES_INCONCLUSIVE="$CASES_INCONCLUSIVE inherited_io_uring_ring"
            ;;
        *)
            CASES_FAIL="$CASES_FAIL inherited_io_uring_ring"
            ;;
    esac
fi

# --- Optional strace cross-check (plan G-SANDBOX asks for strace evidence). --
# strace under an outer ptrace-based sandbox (PRoot) can report fabricated
# results, so a strace disagreement never upgrades a verdict; it is recorded
# and, if it contradicts the probe, downgrades the run to UNPROVEN.
STRACE_NOTE="not-available"
if command -v strace >/dev/null 2>&1; then
    set +e
    strace -f -o "$STRACE_OUT" -e trace=socket,io_uring_setup,io_uring_enter,io_uring_register,seccomp "$WORK_DIR/probe" > "$OUT_DIR/probe-under-strace.txt" 2>"$OUT_DIR/strace-stderr.txt"
    STRACE_EXIT=$?
    set -e
    if [ "$STRACE_EXIT" -eq 0 ] && [ -s "$STRACE_OUT" ]; then
        STRACE_NOTE="recorded"
        # The probe intentionally creates UDP and io_uring descriptors BEFORE
        # installing its filter, so successful socket/io_uring_setup lines
        # before the seccomp install are expected, not a contradiction. Only
        # the transcript after the filter install can contradict the probe.
        STRACE_AFTER_FILTER="$OUT_DIR/strace-after-filter.txt"
        awk '/seccomp\(/ { after = 1 } after' "$STRACE_OUT" > "$STRACE_AFTER_FILTER"
        # If strace shows a successful UDP/RAW socket or io_uring_setup after
        # the install while the direct probe denied it, the tracing layer is
        # interfering (observed under PRoot): the whole run is then unproven,
        # not failed policy, because neither transcript can be fully trusted.
        if grep -E 'socket\(AF_INET6?, SOCK_(DGRAM|RAW)[^)]*\)[[:space:]]*=[[:space:]]*[0-9]' "$STRACE_AFTER_FILTER" >/dev/null 2>&1 \
           || grep -E 'io_uring_setup\([^)]*\)[[:space:]]*=[[:space:]]*[0-9]' "$STRACE_AFTER_FILTER" >/dev/null 2>&1; then
            STRACE_NOTE="contradicts-probe-outer-ptrace-suspected"
        fi
    else
        STRACE_NOTE="strace-failed"
    fi
fi

# --- Optional fail-closed self-test of the harness itself. -------------------
# Runs before the fixture verdict so that on hosts where the environment
# makes cases inconclusive (e.g. PRoot) the harness self-test still runs.
# A self-test failure is a hard FAIL; a self-test pass never upgrades an
# UNPROVEN verdict.
if [ "$SELF_TEST" -eq 1 ]; then
    SELF_DIR=$(mktemp -d "${TMPDIR:-/tmp}/boreas-audit-selftest.XXXXXX")
    # 1) Missing compiler must exit 2 with UNPROVEN (never PASS).
    set +e
    CC=/nonexistent/boreas-no-cc sh "$SCRIPT_DIR/run-sandbox-audit.sh" --out "$SELF_DIR/no-cc" > "$SELF_DIR/no-cc.log" 2>&1
    NOCC_EXIT=$?
    set -e
    if [ "$NOCC_EXIT" -ne 2 ] || ! grep -q '"status": "UNPROVEN"' "$SELF_DIR/no-cc/report.json" 2>/dev/null; then
        echo "SELF-TEST FAIL: missing-compiler run did not fail closed (exit=$NOCC_EXIT)" >&2
        STATUS="FAIL"; REASON="self-test: missing-compiler path did not fail closed"
        finish 1
    fi
    # 2) --target must refuse (no production daemon exists yet).
    set +e
    sh "$SCRIPT_DIR/run-sandbox-audit.sh" --target /bin/true > "$SELF_DIR/target.log" 2>&1
    TARGET_EXIT=$?
    set -e
    if [ "$TARGET_EXIT" -eq 0 ]; then
        echo "SELF-TEST FAIL: --target mode did not refuse" >&2
        STATUS="FAIL"; REASON="self-test: target mode did not fail closed"
        finish 1
    fi
    # 3) Non-empty --out must be refused (stale-evidence guard).
    mkdir -p "$SELF_DIR/dirty"; echo stale > "$SELF_DIR/dirty/old.txt"
    set +e
    sh "$SCRIPT_DIR/run-sandbox-audit.sh" --out "$SELF_DIR/dirty" > "$SELF_DIR/dirty.log" 2>&1
    DIRTY_EXIT=$?
    set -e
    if [ "$DIRTY_EXIT" -eq 0 ]; then
        echo "SELF-TEST FAIL: non-empty --out was accepted" >&2
        STATUS="FAIL"; REASON="self-test: stale evidence dir accepted"
        finish 1
    fi
    rm -rf "$SELF_DIR"
    echo "SELF-TEST OK: missing-cc=UNPROVEN/2 target-refused stale-out-refused" >> "$ENV_OUT"
fi

# --- Verdict (fixture level only; decided after the self-test). --------------
if [ -n "$CASES_FAIL" ]; then
    STATUS="FAIL"; REASON="policy-violating cases:$CASES_FAIL"
    finish 1
fi
if [ -n "$CASES_INCONCLUSIVE" ]; then
    STATUS="UNPROVEN"; REASON="inconclusive cases (denied by other errno, outer sandbox suspected):$CASES_INCONCLUSIVE"
    finish 2
fi
if [ "$STRACE_NOTE" = "contradicts-probe-outer-ptrace-suspected" ]; then
    STATUS="UNPROVEN"; REASON="strace transcript contradicts direct probe; outer ptrace sandbox suspected"
    finish 2
fi

STATUS="PASS_FIXTURE"
REASON="all required fixture cases matched reference policy; production daemon not audited"
if [ -n "$CASES_SKIPPED" ]; then
    REASON="$REASON; conditional cases skipped:$CASES_SKIPPED"
fi
finish 0
