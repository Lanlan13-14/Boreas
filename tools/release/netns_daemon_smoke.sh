#!/usr/bin/env bash
# End-to-end Linux network-namespace verification of the real `boreas` binary:
#   1. Offline PKI provisioning (`boreas pki init-ca` + `issue-node` + `verify-bundle`)
#   2. Two isolated Linux network namespaces (`boreas-core-ns`, `boreas-edge-ns`)
#      connected by a veth pair (`192.0.2.1/24` <-> `192.0.2.2/24`)
#   3. Real `/dev/net/tun` interfaces (`btun0`, `10.20.1.1/32` <-> `10.20.1.2/32`)
#   4. Real `boreas daemon serve` + `boreas daemon connect` over outer TLS 1.3 +
#      WSS + pq768 (`X25519MLKEM768` + `ML-DSA-65`) inner mTLS + `RelayCircuit` +
#      pq768 E2E mTLS + `PacketPath`
#   5. Real kernel ICMP latency and an 8 MiB integrity/throughput probe across
#      the overlay + `boreas ctl status` packet counters with `0% packet loss`.
#      These are loopback-veth development measurements, not public-path SLA.
set -euo pipefail

BIN="${1:?usage: netns_daemon_smoke.sh <path-to-boreas-binary>}"
BIN="$(realpath "$BIN")"
PERF_SCRIPT="$(realpath "$(dirname "${BASH_SOURCE[0]}")/netns_overlay_perf.py")"
TUN_MTU="${BOREAS_TUN_MTU:-1360}"
if [[ ! "$TUN_MTU" =~ ^[0-9]+$ ]] || (( TUN_MTU < 1280 || TUN_MTU > 1400 )); then
  echo 'ERROR: BOREAS_TUN_MTU must be 1280..1400' >&2
  exit 1
fi
export BOREAS_NETNS_HOOK_PROTOCOL=1
if [[ -n "${BOREAS_NETNS_HOOK:-}" ]]; then
  [[ "${BOREAS_NETNS_HOOK_VERSION:-}" == 1 && "$BOREAS_NETNS_HOOK" = /* && -f "$BOREAS_NETNS_HOOK" ]] || {
    echo 'ERROR: routing hook requires an absolute regular file and version 1' >&2
    exit 1
  }
fi
run_hook() {
  if [[ -n "${BOREAS_NETNS_HOOK:-}" ]]; then
    bash "$BOREAS_NETNS_HOOK" "$1" "$CORE_NS" "$EDGE_NS" "$WORK"
  fi
}

# --- Startup/handshake stage timing (diagnostic collection only) -------------
# One monotonic timestamp is read per phase from `/proc/uptime` by a shell
# builtin: no timer process is spawned per poll, so the existing wait loops and
# their bounds are untouched. Values are harness observation latency from a
# launch to an observed boundary, never crypto/CPU service time, and no budget
# is asserted. `ctl` probes emit only an availability/connected classification:
# raw status and error text are discarded, so no path list or key material is
# dumped. Missing clock evidence is `unmeasured` and never turns a gate green.
STARTUP_TIMING_LINES=()
STARTUP_TIMINGS_REPORTED=0

mono_ms() { # $1=destination variable; empty and nonzero on unreadable clock
  local uptime fraction
  if ! read -r uptime _ < /proc/uptime 2>/dev/null; then
    printf -v "$1" '%s' ''
    return 1
  fi
  if [[ ! "$uptime" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    printf -v "$1" '%s' ''
    return 1
  fi
  [[ "$uptime" == *.* ]] || uptime="$uptime.0"
  fraction="${uptime#*.}000"
  printf -v "$1" '%d' "$(( 10#${uptime%%.*} * 1000 + 10#${fraction:0:3} ))"
}

record_stage() { # $1=stage $2=start ms $3=end ms $4=result|- (not asserted)
  local elapsed=unmeasured
  if [[ -n "$2" && -n "$3" ]] && (( $3 >= $2 )); then
    elapsed=$(( $3 - $2 ))
  fi
  STARTUP_TIMING_LINES+=("stage_${1}_elapsed_ms=${elapsed}")
  [[ "$4" == - ]] || STARTUP_TIMING_LINES+=("stage_${1}_result=${4}")
}

probe_ctl_state() { # $1=stage $2=label $3=socket; classification only
  local output state rc=0
  output="$("$BIN" ctl status --socket "$3" 2>/dev/null)" || rc=$?
  if (( rc != 0 )); then
    state="unavailable:ctl-exit-${rc}"
  elif [[ "$output" == *'"daemon_connected":true'* ]]; then
    state=available-connected
  else
    state=available-not-connected
  fi
  STARTUP_TIMING_LINES+=("stage_${1}_${2}_ctl=${state}")
}

report_startup_timings() {
  if (( STARTUP_TIMINGS_REPORTED )); then
    return 0
  fi
  STARTUP_TIMINGS_REPORTED=1
  local line
  echo "--- startup/handshake stage timing (harness-observed boundaries) ---"
  echo 'startup_timing_source=linux-proc-uptime-monotonic-shell-builtin'
  echo 'startup_timing_scope=harness-observation-latency;not-crypto-or-cpu-service-time'
  echo "startup_timing_stage_lines=${#STARTUP_TIMING_LINES[@]}"
  for line in "${STARTUP_TIMING_LINES[@]}"; do
    printf '%s\n' "$line"
  done
  echo 'startup_timing_connected_wait_scope=fixed-harness-poll-window;not-total-handshake-or-crypto-time'
  echo 'startup_timing_threshold=none-asserted'
}

FAILURES=()
record_failure() {
  FAILURES+=("$1")
}
report_daemon_state() {
  local label socket status log spec
  echo "--- daemon state ---" >&2
  for spec in "Core:$CORE_STATE/control.sock" "Edge:$EDGE_STATE/control.sock"; do
    label="${spec%%:*}"
    socket="${spec#*:}"
    if status="$("$BIN" ctl status --socket "$socket" 2>&1)"; then
      echo "$label ctl status: $status" >&2
    else
      echo "$label ctl status unavailable: $status" >&2
    fi
  done
  for log in "$WORK/core.out" "$WORK/core.err" "$WORK/edge.out" "$WORK/edge.err"; do
    if [[ -s "$log" ]]; then
      echo "--- $log ---" >&2
      cat "$log" >&2 || true
    fi
  done
  return 0
}
report_failure_evidence() {
  local log
  echo "--- failure evidence ---" >&2
  report_daemon_state
  for log in "$WORK/ping.log" "$WORK"/perf-*.log; do
    if [[ -s "$log" ]]; then
      echo "--- $log ---" >&2
      cat "$log" >&2 || true
    fi
  done
  report_ss_evidence
  return 0
}

# --- Daemon resource evidence (read-only /proc, no threshold asserted) --------
# Both daemons must be measured as the real exec'd processes, never the
# `ip netns exec`/`unshare`/`bash -c` wrapper chain nor the short-lived probe
# workers: only the recorded `$!` PIDs are candidates, and every sample re-checks
# `/proc/<pid>/stat` starttime ticks plus the `/proc/<pid>/exe` name and inode.
# Unverified becomes `unmeasured`, never counted. Read-only /proc: no sysctl,
# route or qdisc change, no key material, numbers only. No CPU/RSS threshold is
# asserted (no accepted budget exists) and missing evidence never fails the smoke.
RESOURCE_INTERVAL_MS=100
RESOURCE_SAMPLER_PID=""
RESOURCE_SUMMARY=""
RESOURCE_SAMPLER_ERR=""
RESOURCE_STOP_FILE=""

# One bounded background child. It exits on the stop sentinel or on its own
# sample/time deadline, then prints the derived summary (numbers only).
start_resource_sampler() { # $1=core exec pid|- $2=edge exec pid|-
  RESOURCE_SUMMARY="$WORK/resource-summary.txt"
  RESOURCE_SAMPLER_ERR="$WORK/resource-sampler.err"
  RESOURCE_STOP_FILE="$WORK/resource-sampler.stop"
  RESOURCE_SAMPLER_PID=""
  rm -f "$RESOURCE_STOP_FILE" "$RESOURCE_SUMMARY"
  python3 - "$1" "$2" "$RESOURCE_STOP_FILE" "$RESOURCE_INTERVAL_MS" "$BIN" \
    >"$RESOURCE_SUMMARY" 2>"$RESOURCE_SAMPLER_ERR" <<'PY' &
import os
import sys
import time

core_pid, edge_pid, stop_path, interval_ms, binary = sys.argv[1:6]
# Bounded: 500 samples or 45 s, whichever comes first. The stop sentinel ends
# the loop within one interval, so a normal probe reaches neither bound.
interval = max(1, int(interval_ms)) / 1000.0
MAX_SAMPLES, MAX_SECONDS = 500, 45.0
FIELDS = {"utime": 14, "stime": 15, "starttime": 22, "rss_pages": 24}


def sysconf(name):
    """No fallback: a fabricated tick rate or page size would fake the units."""
    try:
        value = int(os.sysconf(name))
    except (AttributeError, OSError, ValueError):
        return None
    return value if value > 0 else None


def read_stat(pid):
    """utime/stime ticks, starttime ticks and resident pages for one PID.
    Parsing starts after the last ') ' because `comm` may contain spaces."""
    try:
        raw = open("/proc/%s/stat" % pid, "rb").read().decode("ascii", "replace")
    except OSError:
        return None
    head = raw.rfind(")")
    if head < 0:
        return None
    fields = raw[head + 2:].split()
    try:
        return {key: int(fields[number - 3]) for key, number in FIELDS.items()}
    except (IndexError, ValueError):
        return None


def exe_identity(pid):
    """Kernel-reported executable of this PID: (basename, device, inode)."""
    try:
        link = os.readlink("/proc/%s/exe" % pid)
        info = os.stat("/proc/%s/exe" % pid)
    except OSError:
        return None
    return (os.path.basename(link), info.st_dev, info.st_ino)


def start_identity(pid):
    """Identity token; (None, reason) is unmeasured and never a substituted PID."""
    if pid == "-":
        return None, "recorded-exec-pid-missing"
    entry, ident = read_stat(pid), exe_identity(pid)
    if entry is None or ident is None:
        return None, "recorded-exec-pid-stat-or-exe-unreadable"
    try:
        want = os.stat(binary)
    except OSError:
        return None, "tested-binary-stat-unreadable"
    if ident[1:] != (want.st_dev, want.st_ino):
        # A same-name impostor and an in-rootfs install copy both fail here: only
        # the tested binary image itself may be reported as measured, so a rootfs
        # run reports `unmeasured` rather than being accepted by name.
        return None, "recorded-exec-pid-is-not-the-tested-binary-inode"
    return (entry["starttime"], ident), None


def snapshot(pid, token):
    """Re-verifies starttime and exe name/inode on every single sample."""
    entry, ident = read_stat(pid), exe_identity(pid)
    if entry is None or ident is None or (entry["starttime"], ident) != token:
        return None
    return {"utime": entry["utime"], "stime": entry["stime"],
            "rss_kb": entry["rss_pages"] * PAGE_BYTES // 1024}


def uptime():
    with open("/proc/uptime", encoding="ascii") as handle:
        return float(handle.read().split()[0])


CLK_TCK, PAGE_BYTES = sysconf("SC_CLK_TCK"), sysconf("SC_PAGE_SIZE")
core_token, core_problem = start_identity(core_pid)
edge_token, edge_problem = start_identity(edge_pid)
if CLK_TCK is None or PAGE_BYTES is None:
    core_problem = core_problem or "sysconf-unavailable"
    edge_problem = edge_problem or "sysconf-unavailable"
rows = []
if core_problem is None or edge_problem is None:
    deadline = uptime() + MAX_SECONDS
    while len(rows) < MAX_SAMPLES:
        now = uptime()
        rows.append({"t": now,
                     "core": None if core_problem else snapshot(core_pid, core_token),
                     "edge": None if edge_problem else snapshot(edge_pid, edge_token)})
        if now >= deadline or os.path.exists(stop_path):
            break
        time.sleep(interval)


def summarise(label, pid, token, problem):
    if problem is not None:
        return ["%s_evidence_status=unmeasured" % label,
                "%s_evidence_detail=%s" % (label, problem)], False
    picks = [row[label] for row in rows if row[label] is not None]
    if len(picks) != len(rows) or len(picks) < 2:
        # Every sample must re-verify starttime and exe inode; a partially
        # verified window is unmeasured instead of being counted as evidence.
        return ["%s_evidence_status=unmeasured" % label,
                "%s_evidence_detail=unverified-samples:%d-of-%d" % (label, len(picks), len(rows))], False
    window = rows[-1]["t"] - rows[0]["t"]
    ticks = (picks[-1]["utime"] + picks[-1]["stime"]) - (picks[0]["utime"] + picks[0]["stime"])
    if window <= 0 or ticks < 0:
        return ["%s_evidence_status=unmeasured" % label,
                "%s_evidence_detail=clock-or-counter-regression" % label], False
    return ["%s_evidence_status=measured" % label,
            "%s_daemon_pid=%s" % (label, pid),
            "%s_daemon_starttime_ticks=%d" % (label, token[0]),
            "%s_window_seconds=%.3f" % (label, window),
            "%s_samples=%d" % (label, len(picks)),
            "%s_cpu_ticks=%d" % (label, ticks),
            "%s_cpu_seconds=%.3f" % (label, ticks / CLK_TCK),
            "%s_cpu_percent_of_one_cpu=%.2f" % (label, ticks / CLK_TCK / window * 100),
            "%s_rss_peak_kb=%d" % (label, max(row["rss_kb"] for row in picks))], True


core_lines, core_ok = summarise("core", core_pid, core_token, core_problem)
edge_lines, edge_ok = summarise("edge", edge_pid, edge_token, edge_problem)
summary = ["--- daemon resource evidence (bidirectional overlay probe window) ---",
           "resource_evidence_source=linux-proc-stat-read-only",
           "resource_evidence_status=%s" % ("measured" if core_ok and edge_ok else "unmeasured")]
if not (core_ok and edge_ok):
    summary.append("resource_evidence_detail=see-per-daemon-detail")
summary += ["resource_sampling_interval_ms=%d" % int(round(interval * 1000)),
            "resource_clock_ticks_per_second=%s" % CLK_TCK,
            "resource_page_size_bytes=%s" % PAGE_BYTES,
            "resource_samples=%d" % len(rows)]
if rows:
    summary.append("resource_window_seconds=%.3f" % (rows[-1]["t"] - rows[0]["t"]))
summary += core_lines + edge_lines
summary += ["resource_cpu_scope=process-thread-group-aggregate",
            "resource_rss_scope=sampled-window-peak-not-kernel-lifetime-peak",
            "resource_threshold=none-asserted"]
print("\n".join(summary))
PY
  RESOURCE_SAMPLER_PID=$!
}

# Stop through the sentinel and join the child: the sampler is never signalled,
# so no PID that could have been reused (for example after daemon exit) is hit.
stop_resource_sampler() {
  [[ -n "$RESOURCE_SAMPLER_PID" ]] || return 0
  : > "$RESOURCE_STOP_FILE" 2>/dev/null || true
  wait "$RESOURCE_SAMPLER_PID" 2>/dev/null || true
  RESOURCE_SAMPLER_PID=""
}

# Reported, never graded: no accepted CPU/RSS budget exists for this workload, so
# missing or unverified resource evidence does not fail the functional smoke.
report_resource_evidence() {
  if [[ -s "$RESOURCE_SUMMARY" ]]; then
    cat "$RESOURCE_SUMMARY"
    return 0
  fi
  echo "--- daemon resource evidence (bidirectional overlay probe window) ---"
  echo "resource_evidence_status=unmeasured"
  echo "resource_evidence_detail=sampler-produced-no-summary"
  echo "resource_sampling_interval_ms=$RESOURCE_INTERVAL_MS"
  echo "resource_threshold=none-asserted"
  if [[ -s "$RESOURCE_SAMPLER_ERR" ]]; then
    echo "--- resource sampler diagnostics ---" >&2
    cat "$RESOURCE_SAMPLER_ERR" >&2 || true
  fi
  return 0
}

WORK="$(mktemp -d /tmp/boreas-netns-e2e.XXXXXX)"
chmod 0700 "$WORK"
CORE_NS="boreas-core-$$"
EDGE_NS="boreas-edge-$$"
HOST_CORE="bc-$$"
HOST_EDGE="be-$$"
CORE_NS_CREATED=0
EDGE_NS_CREATED=0
VETH_CREATED=0

# --- Underlay TCP kernel telemetry (read-only `ss -tin`, collection only) -----
# Brackets the bidirectional probe with two namespace-scoped snapshots. `ss`
# runs inside each already-created disposable namespace, so it reads that
# namespace's own /proc and cannot observe the host or the other namespace.
# Only sockets of the fixed underlay pair are kept (Core listens on
# 192.0.2.1:8443; Edge dials it from 192.0.2.2) together with their raw TCP_INFO
# continuation line: rtt/rttvar, retransmits, cwnd, bytes_acked/bytes_received,
# delivery rate and the remaining kernel fields. This adds no sysctl, qdisc,
# route or interface change, changes no transfer/ping/deadline/byte/key/security
# state, retries nothing and asserts no threshold. A partial or failed capture is
# still emitted and never turns an assertion green.
SS_UNDERLAY_FILTER='192\.0\.2\.[12]:8443'
SS_CAPTURE_ERR="$WORK/ss-capture.err"
SS_REPORTED=0

capture_ss_snapshot() { # $1=phase: before|after
  local phase="$1" spec label ns raw out rc kept status
  for spec in "core:$CORE_NS" "edge:$EDGE_NS"; do
    label="${spec%%:*}"
    ns="${spec#*:}"
    raw="$WORK/ss-$phase-$label.raw"
    out="$WORK/ss-$phase-$label.log"
    : > "$raw"
    : > "$out"
    rc=0
    if ! command -v ss >/dev/null 2>&1; then
      rc=127
    elif command -v timeout >/dev/null 2>&1; then
      # `ss` is kernel-backed and normally returns immediately, but the call is
      # bounded anyway so a wedged netlink read cannot stall the probe window.
      timeout 5 ip netns exec "$ns" ss -tin >"$raw" 2>>"$SS_CAPTURE_ERR" || rc=$?
    else
      # Never make an optional diagnostic an unbounded wait.
      rc=127
    fi
    kept="$(SS_UNDERLAY_FILTER="$SS_UNDERLAY_FILTER" awk '
        /^[[:space:]]/ { if (keep) print; next }
        { keep = ($0 ~ ENVIRON["SS_UNDERLAY_FILTER"]) }
        keep { print }
      ' "$raw" 2>>"$SS_CAPTURE_ERR")" || kept=""
    if [[ -n "$kept" ]]; then
      printf '%s\n' "$kept" > "$out"
      status=measured
    elif (( rc == 0 )); then
      # ss succeeded but no socket matched the fixed underlay pair.
      status=no-matching-socket
    else
      status="unmeasured:ss-exit-$rc"
    fi
    printf '%s\n' "$status" > "$WORK/ss-$phase-$label.status"
  done
  return 0
}

report_ss_evidence() {
  local phase label path status_file status count line
  if (( SS_REPORTED )); then
    return 0
  fi
  SS_REPORTED=1
  echo "--- underlay TCP kernel telemetry (ss -tin, namespace scoped) ---"
  echo "ss_evidence_source=linux-iproute2-ss-tin-read-only-proc"
  echo "ss_underlay_peer_filter=core-192.0.2.1:8443,edge-192.0.2.2->192.0.2.1:8443"
  echo "ss_field_scope=kernel-tcpinfo-of-underlay-outer-tls;not-cross-tls-layer-latency-attribution"
  for phase in before after; do
    for label in core edge; do
      path="$WORK/ss-$phase-$label.log"
      status_file="$WORK/ss-$phase-$label.status"
      status=unmeasured:no-snapshot
      if [[ -s "$status_file" ]]; then
        status="$(<"$status_file")"
      fi
      count=0
      if [[ -s "$path" ]]; then
        count="$(awk 'END { print NR }' "$path")"
      fi
      echo "ss_${phase}_${label}_status=$status"
      echo "ss_${phase}_${label}_captured_lines=$count"
      if (( count > 0 )); then
        echo "--- ss $phase $label (raw kernel lines: socket line + TCP_INFO) ---"
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done < "$path"
      fi
    done
  done
  if [[ -s "$SS_CAPTURE_ERR" ]]; then
    echo "--- ss capture diagnostics ---"
    while IFS= read -r line; do
      printf '  %s\n' "$line"
    done < "$SS_CAPTURE_ERR"
  fi
  echo "ss_threshold=none-asserted"
  return 0
}

cleanup() {
  set +e
  # Emit any stage evidence not already reported (for example a signal-terminated
  # run). Guarded, so normal and failed exits never duplicate the block.
  report_startup_timings
  # Stop the bounded resource sampler through its sentinel and join it; never
  # signal a PID that could have been reused.
  stop_resource_sampler
  # Only signal live child jobs, never stale PIDs from already-waited pidfiles.
  # Reap them before deleting WORK: their private mounts must be gone first.
  local pid
  for pid in $(jobs -pr); do
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if (( VETH_CREATED )); then
    ip link del "$HOST_CORE" 2>/dev/null || true
    ip link del "$HOST_EDGE" 2>/dev/null || true
  fi
  if (( CORE_NS_CREATED )); then ip netns del "$CORE_NS" 2>/dev/null || true; fi
  if (( EDGE_NS_CREATED )); then ip netns del "$EDGE_NS" 2>/dev/null || true; fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'report_startup_timings; echo "ERROR: netns smoke failed at line $LINENO" >&2; for log in "$WORK/core.err" "$WORK/edge.err"; do if [[ -f "$log" ]]; then cat "$log" >&2; fi; done' ERR

# Validate all mount destinations before either child starts. Never follow a
# rootfs symlink into the host when preparing privileged bind-mount targets.
if [[ -n "${BOREAS_ROOTFS:-}" ]]; then
  BOREAS_ROOTFS="$(realpath -e -- "$BOREAS_ROOTFS")"
  [[ "$BOREAS_ROOTFS" != / && -d "$BOREAS_ROOTFS" ]] || {
    echo 'ERROR: BOREAS_ROOTFS must be a non-root directory' >&2
    exit 1
  }
  for relative in sys dev dev/net tmp "${WORK#/}"; do
    destination="$BOREAS_ROOTFS/$relative"
    [[ ! -L "$destination" ]] || { echo "ERROR: symlink mount path: $destination" >&2; exit 1; }
    if [[ -e "$destination" && ! -d "$destination" ]]; then
      echo "ERROR: non-directory mount path: $destination" >&2
      exit 1
    fi
    mkdir -p -- "$destination"
  done
  for device in net/tun urandom; do
    destination="$BOREAS_ROOTFS/dev/$device"
    [[ ! -L "$destination" ]] && { [[ ! -e "$destination" ]] || [[ -f "$destination" || -c "$destination" ]]; } || {
      echo "ERROR: unsafe device mount target: $destination" >&2
      exit 1
    }
    if [[ ! -e "$destination" ]]; then : > "$destination"; fi
    [[ -c "/dev/$device" ]] || { echo "ERROR: missing host /dev/$device" >&2; exit 1; }
  done
fi

# LinuxTunDevice sets MTU through sysfs. A network namespace alone retains
# the host sysfs view; remount it in a private mount namespace after setns.
# BOREAS_ROOTFS optionally runs the same static binary inside an unpacked
# OpenWrt userland. The host kernel is still explicitly outside that claim.
run_node() {
  local ns="$1"
  shift
  if [[ -n "${BOREAS_ROOTFS:-}" ]]; then
    exec ip netns exec "$ns" unshare --mount --propagation private \
      bash -e -c 'mount --make-rprivate /; mount -t sysfs sysfs "$1/sys"; mount --bind /dev/net/tun "$1/dev/net/tun"; mount --bind /dev/urandom "$1/dev/urandom"; mount --bind "$2" "$1$2"; exec chroot "$1" /usr/local/bin/boreas "${@:4}"' \
      boreas-node "$BOREAS_ROOTFS" "$WORK" "$@"
  fi
  exec ip netns exec "$ns" unshare --mount --propagation private \
    bash -e -c 'mount --make-rprivate /; umount -l /sys; mount -t sysfs sysfs /sys; exec "$@"' boreas-node "$@"
}

CA_DIR="$WORK/ca"
CORE_MAT="$WORK/core-mat"
EDGE_MAT="$WORK/edge-mat"
CORE_STATE="$WORK/core-state"
EDGE_STATE="$WORK/edge-state"
mkdir -p "$CORE_STATE" "$EDGE_STATE"
chmod 0700 "$CORE_STATE" "$EDGE_STATE"

"$BIN" pki init-ca \
  --ca-dir "$CA_DIR" \
  --net-id "0123456789abcdef0123456789abcdef" \
  --validity-days 30

"$BIN" pki issue-node \
  --ca-dir "$CA_DIR" \
  --out-dir "$CORE_MAT" \
  --role core \
  --home-core 1 \
  --vip-octet 1 \
  --outer-san "wss.boreas.test"

"$BIN" pki issue-node \
  --ca-dir "$CA_DIR" \
  --out-dir "$EDGE_MAT" \
  --role edge \
  --home-core 1 \
  --vip-octet 2

cp "$CORE_MAT/local.signed" "$EDGE_MAT/peer.signed"
cp "$EDGE_MAT/local.signed" "$CORE_MAT/peer.signed"

"$BIN" pki verify-bundle --material-dir "$CORE_MAT" --require-peer
"$BIN" pki verify-bundle --material-dir "$EDGE_MAT" --require-peer

cat > "$WORK/core.toml" <<EOF
version = 2
[node]
net_id = "0123456789abcdef0123456789abcdef"
role = "core"
home_core_id = 1
vip_octet = 1
node_id = 1
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"
[paths]
identity_key = "$CORE_MAT/identity.key"
roots = ["$CORE_MAT/roots.cbor"]
state_dir = "$CORE_STATE"
[uplink]
primary = "wss.boreas.test:8443"
paths = 4
probe_paths = 1
EOF
chmod 0600 "$WORK/core.toml"

cat > "$WORK/edge.toml" <<EOF
version = 2
[node]
net_id = "0123456789abcdef0123456789abcdef"
role = "edge"
home_core_id = 1
vip_octet = 2
node_id = 2
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"
[paths]
identity_key = "$EDGE_MAT/identity.key"
roots = ["$EDGE_MAT/roots.cbor"]
state_dir = "$EDGE_STATE"
[uplink]
primary = "wss.boreas.test:8443"
paths = 4
probe_paths = 1
EOF
chmod 0600 "$WORK/edge.toml"

# Create isolated network namespaces and underlay veth link.
ip netns add "$CORE_NS"
CORE_NS_CREATED=1
ip netns add "$EDGE_NS"
EDGE_NS_CREATED=1
# This candidate negotiates IPv4 only. Disable automatic IPv6 link-local/DAD
# traffic in these disposable namespaces before any interfaces are brought up.
for ns in "$CORE_NS" "$EDGE_NS"; do
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
done
ip link add "$HOST_CORE" type veth peer name "$HOST_EDGE"
VETH_CREATED=1
ip link set "$HOST_CORE" netns "$CORE_NS"
ip link set "$HOST_EDGE" netns "$EDGE_NS"
ip netns exec "$CORE_NS" ip link set "$HOST_CORE" name veth-core
ip netns exec "$EDGE_NS" ip link set "$HOST_EDGE" name veth-edge

ip netns exec "$CORE_NS" ip link set lo up
ip netns exec "$CORE_NS" ip addr add 192.0.2.1/24 dev veth-core
ip netns exec "$CORE_NS" ip link set veth-core up

ip netns exec "$EDGE_NS" ip link set lo up
ip netns exec "$EDGE_NS" ip addr add 192.0.2.2/24 dev veth-edge
ip netns exec "$EDGE_NS" ip link set veth-edge up

run_hook setup

# Optional netem impairment is scoped to the two disposable underlay devices.
# No host qdisc or global sysctl is touched. RTT is one-way per device.
if [[ -n "${BOREAS_NETEM_RTT_MS:-}" ]]; then
  for spec in "$CORE_NS:veth-core" "$EDGE_NS:veth-edge"; do
    ns="${spec%%:*}"
    dev="${spec##*:}"
    ip netns exec "$ns" tc qdisc add dev "$dev" root netem \
      delay "${BOREAS_NETEM_RTT_MS}ms" loss "${BOREAS_NETEM_LOSS_PERCENT:-0}%" \
      rate "${BOREAS_NETEM_RATE_MBIT:-1000}mbit"
  done
fi

# Start Core daemon inside CORE_NS (creates real /dev/net/tun `btun0`).
mono_ms CORE_LAUNCH_MS || CORE_LAUNCH_MS=''
run_node "$CORE_NS" "$BIN" daemon serve \
  --config "$WORK/core.toml" \
  --material-dir "$CORE_MAT" \
  --listen "192.0.2.1:8443" \
  --tun-name "btun0" \
  --mtu "$TUN_MTU" \
  --max-seconds 35 \
  > "$WORK/core.out" 2> "$WORK/core.err" &
echo $! > "$WORK/core.pid"

# Wait for Core `btun0` to appear, then assign permanent VIP 10.20.1.1 and peer route.
CORE_TUN_STATE=timeout
for _ in $(seq 1 80); do
  if ip netns exec "$CORE_NS" ip link show btun0 >/dev/null 2>&1; then
    CORE_TUN_STATE=observed
    break
  fi
  sleep 0.05
done
mono_ms CORE_TUN_MS || CORE_TUN_MS=''
record_stage core_launch_to_tun_observed "$CORE_LAUNCH_MS" "$CORE_TUN_MS" "$CORE_TUN_STATE"
probe_ctl_state core_tun_observed core "$CORE_STATE/control.sock"
ip netns exec "$CORE_NS" ip addr add 10.20.1.1/32 dev btun0
ip netns exec "$CORE_NS" ip link set btun0 up
ip netns exec "$CORE_NS" ip route add 10.20.1.2/32 dev btun0

# Start Edge daemon inside EDGE_NS (creates real /dev/net/tun `btun0` and dials 192.0.2.1:8443).
mono_ms EDGE_LAUNCH_MS || EDGE_LAUNCH_MS=''
run_node "$EDGE_NS" "$BIN" daemon connect \
  --config "$WORK/edge.toml" \
  --material-dir "$EDGE_MAT" \
  --connect "192.0.2.1:8443" \
  --tls-name "wss.boreas.test" \
  --ws-host "wss.boreas.test:8443" \
  --tun-name "btun0" \
  --mtu "$TUN_MTU" \
  --max-seconds 33 \
  > "$WORK/edge.out" 2> "$WORK/edge.err" &
echo $! > "$WORK/edge.pid"

EDGE_TUN_STATE=timeout
for _ in $(seq 1 80); do
  if ip netns exec "$EDGE_NS" ip link show btun0 >/dev/null 2>&1; then
    EDGE_TUN_STATE=observed
    break
  fi
  sleep 0.05
done
mono_ms EDGE_TUN_MS || EDGE_TUN_MS=''
record_stage edge_launch_to_tun_observed "$EDGE_LAUNCH_MS" "$EDGE_TUN_MS" "$EDGE_TUN_STATE"
probe_ctl_state edge_tun_observed edge "$EDGE_STATE/control.sock"
ip netns exec "$EDGE_NS" ip addr add 10.20.1.2/32 dev btun0
ip netns exec "$EDGE_NS" ip link set btun0 up
ip netns exec "$EDGE_NS" ip route add 10.20.1.1/32 dev btun0

run_hook ready

# Wait until `boreas ctl status` reports `daemon_connected:true` on both nodes.
# Timing and ctl-state probes bracket this fixed loop at its boundaries only:
# the poll count, interval and daemon deadlines stay exactly as before.
probe_ctl_state connected_wait_start core "$CORE_STATE/control.sock"
probe_ctl_state connected_wait_start edge "$EDGE_STATE/control.sock"
mono_ms CONNECTED_WAIT_START_MS || CONNECTED_WAIT_START_MS=''
CONNECTED=0
for _ in $(seq 1 100); do
  if "$BIN" ctl status --socket "$EDGE_STATE/control.sock" 2>/dev/null | grep -q '"daemon_connected":true'; then
    CONNECTED=1
    break
  fi
  sleep 0.05
done
mono_ms CONNECTED_WAIT_END_MS || CONNECTED_WAIT_END_MS=''
CONNECTED_RESULT=failure
if [[ "$CONNECTED" -eq 1 ]]; then
  CONNECTED_RESULT=success
fi
record_stage edge_launch_to_connected "$EDGE_LAUNCH_MS" "$CONNECTED_WAIT_END_MS" "$CONNECTED_RESULT"
record_stage edge_tun_to_connected "$EDGE_TUN_MS" "$CONNECTED_WAIT_END_MS" "$CONNECTED_RESULT"
record_stage connected_wait "$CONNECTED_WAIT_START_MS" "$CONNECTED_WAIT_END_MS" "$CONNECTED_RESULT"
probe_ctl_state connected_result core "$CORE_STATE/control.sock"
probe_ctl_state connected_result edge "$EDGE_STATE/control.sock"
report_startup_timings
if [[ "$CONNECTED" -ne 1 ]]; then
  echo "ERROR: Edge daemon never reached connected state" >&2
  report_failure_evidence
  exit 1
fi

# Exercise sparse ICMP traffic and reject the former fixed 25 ms polling delay.
# A packet-loss or latency failure is recorded but does not prevent the
# full-duplex probe from running; the final exit remains nonzero.
PING_FAILED=0
if ! ip netns exec "$EDGE_NS" ping -c 10 -i 0.1 -W 2 -I 10.20.1.2 10.20.1.1 | tee "$WORK/ping.log"; then
  PING_FAILED=1
  echo "WARNING: overlay ping exited nonzero; preserving its output as failure evidence" >&2
fi
if ! python3 - "$WORK/ping.log" <<'PY'
import os
import re
import sys

limit = float(os.environ.get("BOREAS_MAX_PING_MS", "15.0"))

text = open(sys.argv[1], encoding="utf-8").read()
problems = []

loss_match = re.search(r"([0-9]+(?:\.[0-9]+)?)% packet loss", text)
if loss_match is None:
    problems.append("could not parse ping packet-loss statistics")
else:
    loss = float(loss_match.group(1))
    print(f"overlay_ping_loss_percent={loss:.3f}")
    if loss != 0:
        problems.append(f"overlay packet loss {loss:.3f}% exceeds 0%")

match = re.search(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)/[0-9.]+ ms", text)
if match is None:
    print("overlay_ping_average_ms=unavailable")
    print("overlay_ping_max_ms=unavailable")
    problems.append("could not parse ping RTT statistics")
else:
    minimum, average, maximum = map(float, match.groups())
    print(f"overlay_ping_average_ms={average:.3f}")
    print(f"overlay_ping_max_ms={maximum:.3f}")
    if average > limit or maximum > limit:
        problems.append(
            f"overlay RTT avg={average:.3f} ms max={maximum:.3f} ms exceeds {limit:.3f} ms regression bound"
        )

if problems:
    for problem in problems:
        print(f"overlay_ping_failure: {problem}", file=sys.stderr)
    raise SystemExit(1)
PY
then
  PING_FAILED=1
fi
if (( PING_FAILED )); then
  record_failure "overlay ping: packet loss or latency regression bound failed"
  report_daemon_state
fi

# The sampling window brackets the probe: it opens immediately before the four
# probe workers start and closes after all four have been reaped. Only the
# recorded `$!` PIDs (the wrapper chain that ends in `exec` of the daemon) are
# candidates; the sampler verifies starttime and exe identity on every sample and
# reports `unmeasured` when that evidence does not hold, so no wrapper, probe
# worker or recycled PID can be reported as the daemon.
start_resource_sampler "$(cat "$WORK/core.pid")" "$(cat "$WORK/edge.pid")"

# The kernel TCP telemetry window opens on the same established underlay pair and
# is captured before the first probe worker starts.
capture_ss_snapshot before

# Send 8 MiB in each direction at the same time and authenticate both payloads
# with independent SHA-256 digests. This exercises full-duplex progress rather
# than only a one-way throughput happy path; it is not a public-network SLA.
ip netns exec "$CORE_NS" python3 "$PERF_SCRIPT" receive 10.20.1.1 10.20.1.2 > "$WORK/perf-receiver-core.log" 2>&1 &
echo $! > "$WORK/perf-receiver-core.pid"
ip netns exec "$EDGE_NS" python3 "$PERF_SCRIPT" receive 10.20.1.2 10.20.1.1 > "$WORK/perf-receiver-edge.log" 2>&1 &
echo $! > "$WORK/perf-receiver-edge.pid"
sleep 0.1
ip netns exec "$EDGE_NS" python3 "$PERF_SCRIPT" send 10.20.1.2 10.20.1.1 > "$WORK/perf-sender-edge.log" 2>&1 &
echo $! > "$WORK/perf-sender-edge.pid"
ip netns exec "$CORE_NS" python3 "$PERF_SCRIPT" send 10.20.1.1 10.20.1.2 > "$WORK/perf-sender-core.log" 2>&1 &
echo $! > "$WORK/perf-sender-core.pid"
PERF_WORKER_FAILED=0
if ! wait "$(cat "$WORK/perf-sender-edge.pid")"; then
  echo "ERROR: edge_to_core sender exited nonzero" >&2
  PERF_WORKER_FAILED=1
fi
if ! wait "$(cat "$WORK/perf-sender-core.pid")"; then
  echo "ERROR: core_to_edge sender exited nonzero" >&2
  PERF_WORKER_FAILED=1
fi
if ! wait "$(cat "$WORK/perf-receiver-core.pid")"; then
  echo "ERROR: core receiver exited nonzero" >&2
  PERF_WORKER_FAILED=1
fi
if ! wait "$(cat "$WORK/perf-receiver-edge.pid")"; then
  echo "ERROR: edge receiver exited nonzero" >&2
  PERF_WORKER_FAILED=1
fi
# All four probe workers are reaped, so the transfer is complete: snapshot the
# same underlay sockets again, then close the sampling window through the
# sentinel and join the child before any later exit, and report the measured
# CPU/RSS evidence (no threshold applied).
capture_ss_snapshot after
stop_resource_sampler
report_resource_evidence
report_ss_evidence
if (( PERF_WORKER_FAILED )); then
  # Do not treat a sender's JSON as valid throughput when either worker in
  # that direction failed (for example on a digest or socket error).
  echo "ERROR: overlay perf worker failed; measured throughput is not accepted" >&2
  report_failure_evidence
  exit 1
fi

PERF_RESULT=0
python3 - "$WORK/perf-sender-edge.log" "$WORK/perf-sender-core.log" <<'PY' || PERF_RESULT=$?
import json
import math
import os
import sys

labels = ("edge_to_core", "core_to_edge")
minimum = float(os.environ.get("BOREAS_MIN_THROUGHPUT_MBPS", "3.0"))
expected_bytes = int(os.environ.get("BOREAS_PERF_BYTES", str(8 * 1024 * 1024)))
failures = []

for label, path in zip(labels, sys.argv[1:]):
    try:
        with open(path, encoding="utf-8") as source:
            result = json.load(source)
    except (OSError, ValueError) as exc:
        print(f"overlay_throughput_{label}_mbps=unavailable")
        failures.append(f"{label} has no complete sender result: {exc}")
        continue
    if not isinstance(result, dict):
        print(f"overlay_throughput_{label}_mbps=unavailable")
        failures.append(f"{label} sender result is not a JSON object")
        continue

    throughput = result.get("throughput_mbps")
    measured = (
        isinstance(throughput, (int, float))
        and not isinstance(throughput, bool)
        and math.isfinite(throughput)
    )
    if measured:
        print(f"overlay_throughput_{label}_mbps={throughput:.3f}")
    else:
        print(f"overlay_throughput_{label}_mbps=unavailable")
        failures.append(f"{label} has no valid throughput measurement")
    if result.get("bytes") != expected_bytes:
        failures.append(f"{label} transferred {result.get('bytes')} bytes, expected {expected_bytes}")
    if measured and throughput < minimum:
        failures.append(
            f"{label} throughput {throughput:.3f} Mbps is below {minimum:.3f} Mbps regression bound"
        )

# Both direction lines above are printed before any threshold failure exits.
if failures:
    for failure in failures:
        print(f"overlay_perf_failure: {failure}", file=sys.stderr)
    raise SystemExit(1)
PY
if (( PERF_RESULT != 0 )); then
  echo "ERROR: overlay full-duplex throughput/integrity assertion failed" >&2
  report_failure_evidence
  exit 1
fi

CTL_FAILED=0
if CORE_CTL="$("$BIN" ctl status --socket "$CORE_STATE/control.sock" 2>&1)"; then
  echo "Core live ctl: $CORE_CTL"
else
  CTL_FAILED=1
  echo "ERROR: Core ctl status failed: $CORE_CTL" >&2
fi
if EDGE_CTL="$("$BIN" ctl status --socket "$EDGE_STATE/control.sock" 2>&1)"; then
  echo "Edge live ctl: $EDGE_CTL"
else
  CTL_FAILED=1
  echo "ERROR: Edge ctl status failed: $EDGE_CTL" >&2
fi
if (( CTL_FAILED )); then
  record_failure "control status query failed"
fi

DAEMON_FAILED=0
if ! wait "$(cat "$WORK/edge.pid")"; then
  echo "ERROR: Edge daemon exited nonzero" >&2
  DAEMON_FAILED=1
fi
if ! wait "$(cat "$WORK/core.pid")"; then
  echo "ERROR: Core daemon exited nonzero" >&2
  DAEMON_FAILED=1
fi
if (( DAEMON_FAILED )); then
  record_failure "daemon process exited nonzero"
fi

echo " Core exit summary: $(cat "$WORK/core.out")"
echo " Edge exit summary: $(cat "$WORK/edge.out")"
if ! grep -q '"status":"ok"' "$WORK/core.out"; then
  record_failure "Core daemon did not report status ok"
fi
if ! grep -q '"status":"ok"' "$WORK/edge.out"; then
  record_failure "Edge daemon did not report status ok"
fi
if (( ${#FAILURES[@]} > 0 )); then
  echo "ERROR: netns smoke failed ${#FAILURES[@]} assertion(s):" >&2
  for failure in "${FAILURES[@]}"; do
    echo "  - $failure" >&2
  done
  report_failure_evidence
  exit 1
fi
run_hook verify
echo "REAL NETNS PQ768 E2E OVERLAY PING + THROUGHPUT SUCCEEDED"
