#!/bin/sh
# Boreas redacted diagnostics collector (master plan v1.11.0, sections
# 10.3 preflight / 10.4 telemetry / Phase 3 operations evidence).
#
# Collects only environment facts useful for support and upgrade preflight:
# OS/arch/kernel, Boreas binary identity (path, sha256, ELF header, dynamic
# dependency summary -- no binary contents), toolchain versions, resource
# limits, /proc status summary of this shell, open-fd *counts by type*
# (never fd target paths), disk space of the output filesystem, and
# seccomp/tool availability.
#
# Redaction contract (fail-closed):
#   - Never reads private keys, certificates, config files, environment
#     variable values, argv of other processes, or log files.
#   - Never prints environment values; only whether a small allowlist of
#     variable *names* is set (values are never echoed).
#   - Hostname, username and home directory are replaced with placeholders.
#   - A final scan rejects the bundle if it contains PEM private-key
#     markers, TLS session-secret labels, or long hex/base64 blobs that
#     look like key material; on any hit the bundle is deleted and the
#     script exits 1 (fail-closed) instead of "best effort" shipping it.
#
# Usage:
#   collect-diagnostics.sh [--out DIR] [--boreas-bin PATH] [--self-test]
#
# Exit codes: 0 ok; 1 redaction scan hit / self-test failure;
#             2 required tool missing or output unusable (fail-closed);
#             3 usage error.
set -eu
umask 077

OUT_DIR=""
BOREAS_BIN=""
SELF_TEST=0

usage() {
    echo "usage: $0 [--out DIR] [--boreas-bin PATH] [--self-test]" >&2
    exit 3
}
while [ $# -gt 0 ]; do
    case "$1" in
        --out) [ $# -ge 2 ] || usage; OUT_DIR=$2; shift 2 ;;
        --boreas-bin) [ $# -ge 2 ] || usage; BOREAS_BIN=$2; shift 2 ;;
        --self-test) SELF_TEST=1; shift ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

# Required tools: without hashes we cannot identify the binary, so a
# bundle would be misleading. Fail closed instead of emitting half-evidence.
for tool in sha256sum uname date; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "UNPROVEN: required tool missing: $tool" >&2
        exit 2
    fi
done

if [ -z "$OUT_DIR" ]; then
    OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/boreas-diagnostics.XXXXXX")
else
    mkdir -p "$OUT_DIR"
    if [ -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]; then
        echo "UNPROVEN: --out directory is not empty (refusing to mix bundles): $OUT_DIR" >&2
        exit 2
    fi
fi
BUNDLE="$OUT_DIR/diagnostics.txt"
MANIFEST="$OUT_DIR/SHA256SUMS"

# Redactor: strip hostname/user/home and anything secret-shaped from a
# stream. Applied to every section, including tool version output, because
# version strings can embed build paths containing a username.
# Written with plain BRE (no alternation) for busybox sed portability.
redact() {
    sed \
        -e "s|${HOME:-/nonexistent-home}|~|g" \
        -e "s|$(hostname 2>/dev/null || echo no-hostname-available)|<hostname>|g" \
        -e "s|$(id -un 2>/dev/null || echo no-user-available)|<user>|g" \
        -e 's/PRIVATE KEY-----.*/PRIVATE KEY-----<redacted-line>/' \
        -e 's/[Ss]ecret[=:][^ ]*/secret=<redacted>/g' \
        -e 's/[Pp]assword[=:][^ ]*/password=<redacted>/g' \
        -e 's/[Tt]oken[=:][^ ]*/token=<redacted>/g'
}

{
    echo "== Boreas redacted diagnostics =="
    echo "collected_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "collector: tools/diagnostics/collect-diagnostics.sh schema=1"
    echo "note: environment facts only; no keys, certs, configs, logs or env values."
    echo
    echo "-- system --"
    echo "os: $(uname -s 2>/dev/null || echo unknown)"
    echo "arch: $(uname -m 2>/dev/null || echo unknown)"
    echo "kernel: $(uname -sr 2>/dev/null || echo unknown)"
    if [ -r /etc/os-release ]; then
        # Allowlist two non-sensitive fields only.
        grep -E '^(ID|VERSION_ID)=' /etc/os-release || true
    fi
    # Outer-sandbox hint: pre-existing seccomp filters change what any
    # audit on this host can prove (see sandbox-audit README).
    if [ -r /proc/self/status ]; then
        grep -E '^(NoNewPrivs|Seccomp|Seccomp_filters|CapEff|CapBnd):' /proc/self/status || true
    fi
    echo
    echo "-- limits (this shell; daemon limits come from its service unit) --"
    # busybox/dash/bash all support -a here; /proc/self/limits below is the
    # authoritative source on Linux, this is a convenience summary.
    # shellcheck disable=SC3045
    ulimit -a 2>/dev/null || echo "ulimit unavailable"
    if [ -r /proc/self/limits ]; then
        grep -E '^(Limit|Max open files|Max locked memory|Max address space|Max processes)' /proc/self/limits || true
    fi
    echo
    echo "-- open fd summary (this shell; counts by type, no target paths) --"
    if [ -d /proc/self/fd ]; then
        fd_total=0; fd_socket=0; fd_pipe=0; fd_other=0
        for fd_path in /proc/self/fd/*; do
            [ -e "$fd_path" ] || continue
            fd_total=$((fd_total + 1))
            fd_target=$(readlink "$fd_path" 2>/dev/null || echo unreadable)
            case "$fd_target" in
                socket:*) fd_socket=$((fd_socket + 1)) ;;
                pipe:*) fd_pipe=$((fd_pipe + 1)) ;;
                *) fd_other=$((fd_other + 1)) ;;
            esac
        done
        echo "fd_total: $fd_total"
        echo "fd_sockets: $fd_socket"
        echo "fd_pipes: $fd_pipe"
        echo "fd_other_files_and_devices: $fd_other"
    else
        echo "fd summary unavailable (no /proc/self/fd)"
    fi
    echo
    echo "-- disk (output filesystem only) --"
    df -k "$OUT_DIR" 2>/dev/null | sed -n '1p;2p' || echo "df unavailable"
    echo
    echo "-- toolchain (first line of --version where available) --"
    for tool in cc rustc cargo python3 strace shellcheck; do
        if command -v "$tool" >/dev/null 2>&1; then
            version_line=$("$tool" --version 2>/dev/null | sed -n '1p' || echo version-error)
            echo "$tool: $version_line"
        else
            echo "$tool: MISSING"
        fi
    done
    echo
    echo "-- relevant env presence (names only, values never collected) --"
    for var_name in BOREAS_HOME RUSTUP_HOME CARGO_HOME OPENSSL_PREFIX; do
        # Indirect expansion via eval on a fixed allowlist of names only.
        var_is_set="unset"
        eval "var_is_set=\${$var_name+set}"
        if [ "$var_is_set" = "set" ]; then echo "$var_name: set"; else echo "$var_name: unset"; fi
    done
    echo
    echo "-- boreas binary --"
    if [ -n "$BOREAS_BIN" ]; then
        if [ ! -f "$BOREAS_BIN" ]; then
            echo "boreas_bin: NOT FOUND at given path"
        else
            echo "boreas_bin_sha256: $(sha256sum "$BOREAS_BIN" | cut -d' ' -f1)"
            echo "boreas_bin_size_bytes: $(wc -c < "$BOREAS_BIN" | tr -d ' ')"
            if command -v readelf >/dev/null 2>&1; then
                # ELF header + interpreter presence only (plan 10.3/10.5:
                # static target has no dynamic interpreter). No sections
                # beyond the header, no symbol dump.
                readelf -h "$BOREAS_BIN" 2>/dev/null | grep -E 'Class:|Data:|Type:|Machine:' || echo "elf_header: unreadable"
                if readelf -l "$BOREAS_BIN" 2>/dev/null | grep -q 'Requesting program interpreter'; then
                    echo "dynamic_interpreter: present"
                else
                    echo "dynamic_interpreter: absent (static or non-ELF)"
                fi
            else
                echo "elf_header: readelf MISSING"
            fi
            if command -v ldd >/dev/null 2>&1; then
                # Library sonames only; strip resolved paths (may embed
                # usernames) down to the soname before '=>'.
                echo "dynamic_deps_sonames:"
                ldd "$BOREAS_BIN" 2>/dev/null | sed -e 's/=>.*//' -e 's/^[[:space:]]*/  /' | sed -n '1,40p' || echo "  (ldd failed; likely static)"
            fi
        fi
    else
        echo "boreas_bin: not specified (pass --boreas-bin to identify a binary)"
    fi
} | redact > "$BUNDLE"

# --- Fail-closed secret scan over the finished bundle. -----------------------
# Patterns: PEM key headers, TLS key-log labels, and long opaque blobs.
# sha256 of the Boreas binary itself is 64 hex chars; it is allowlisted by
# only flagging *unlabelled* blobs: lines already carrying a known label
# are exempted explicitly below.
SCAN_HIT=0
if grep -Eq 'BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY|CLIENT_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET|CLIENT_RANDOM|Resumption PSK|Master Secret' "$BUNDLE"; then
    SCAN_HIT=1
fi
if grep -Ev '^(boreas_bin_sha256:|collected_utc:)' "$BUNDLE" | grep -Eq '[0-9a-fA-F]{96,}|[A-Za-z0-9+/]{120,}={0,2}($|[^A-Za-z0-9+/=])'; then
    SCAN_HIT=1
fi
if [ "$SCAN_HIT" -ne 0 ]; then
    echo "FAIL-CLOSED: diagnostics bundle matched a secret-shaped pattern; deleting bundle." >&2
    rm -f "$BUNDLE"
    exit 1
fi

# Manifest lets a receiver verify the bundle was not altered in transit.
# Hash the basename only so no host paths leak into SHA256SUMS.
( cd "$OUT_DIR" && sha256sum diagnostics.txt > SHA256SUMS )
echo "diagnostics: wrote $BUNDLE"
echo "diagnostics: redaction scan clean; manifest at $MANIFEST"

# --- Self-test: plant secret-shaped strings and require rejection. -----------
if [ "$SELF_TEST" -eq 1 ]; then
    TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/boreas-diag-selftest.XXXXXX")
    # The collector never reads arbitrary files, so test the scan itself by
    # feeding the same patterns against a synthetic bundle copy.
    cp "$BUNDLE" "$TEST_DIR/poisoned.txt"
    echo "-----BEGIN PRIVATE KEY-----" >> "$TEST_DIR/poisoned.txt"
    if ! grep -Eq 'BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY' "$TEST_DIR/poisoned.txt"; then
        echo "SELF-TEST FAIL: PEM pattern did not match planted marker" >&2
        rm -rf "$TEST_DIR"; exit 1
    fi
    cp "$BUNDLE" "$TEST_DIR/poisoned2.txt"
    printf 'unlabelled %s\n' "$(printf 'ab%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50)" >> "$TEST_DIR/poisoned2.txt"
    if ! grep -Ev '^(boreas_bin_sha256:|collected_utc:)' "$TEST_DIR/poisoned2.txt" | grep -Eq '[0-9a-fA-F]{96,}'; then
        echo "SELF-TEST FAIL: long-blob pattern did not match planted blob" >&2
        rm -rf "$TEST_DIR"; exit 1
    fi
    # Non-empty --out must be refused.
    set +e
    sh "$0" --out "$TEST_DIR" >/dev/null 2>&1
    DIRTY_EXIT=$?
    set -e
    if [ "$DIRTY_EXIT" -eq 0 ]; then
        echo "SELF-TEST FAIL: non-empty --out accepted" >&2
        rm -rf "$TEST_DIR"; exit 1
    fi
    rm -rf "$TEST_DIR"
    echo "SELF-TEST OK: planted PEM and blob markers detected; dirty --out refused"
fi

exit 0
