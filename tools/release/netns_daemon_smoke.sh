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

WORK="$(mktemp -d /tmp/boreas-netns-e2e.XXXXXX)"
chmod 0700 "$WORK"
CORE_NS="boreas-core-$$"
EDGE_NS="boreas-edge-$$"

cleanup() {
  set +e
  for pidfile in "$WORK"/*.pid; do
    if [[ -f "$pidfile" ]]; then kill "$(cat "$pidfile")" 2>/dev/null || true; fi
  done
  ip netns del "$CORE_NS" 2>/dev/null || true
  ip netns del "$EDGE_NS" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'echo "ERROR: netns smoke failed at line $LINENO" >&2; for log in "$WORK/core.err" "$WORK/edge.err"; do if [[ -f "$log" ]]; then cat "$log" >&2; fi; done' ERR

# LinuxTunDevice sets MTU through sysfs. A network namespace alone retains
# the host sysfs view; remount it in a private mount namespace after setns.
# BOREAS_ROOTFS optionally runs the same static binary inside an unpacked
# OpenWrt userland. The host kernel is still explicitly outside that claim.
run_node() {
  local ns="$1"
  shift
  if [[ -n "${BOREAS_ROOTFS:-}" ]]; then
    mkdir -p "${BOREAS_ROOTFS}/sys" "${BOREAS_ROOTFS}/dev" "${BOREAS_ROOTFS}${WORK}"
    touch "${BOREAS_ROOTFS}/dev/net/tun"
    exec ip netns exec "$ns" unshare --mount --propagation private \
      bash -e -c 'mount --make-rprivate /; mount -t sysfs sysfs "$1/sys"; mount --bind /dev/net/tun "$1/dev/net/tun"; mount --bind "$2" "$1$2"; exec chroot "$1" /usr/local/bin/boreas "${@:3}"' \
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
ip netns add "$EDGE_NS"
# This candidate negotiates IPv4 only. Disable automatic IPv6 link-local/DAD
# traffic in these disposable namespaces before any interfaces are brought up.
for ns in "$CORE_NS" "$EDGE_NS"; do
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
done
ip link add veth-core type veth peer name veth-edge
ip link set veth-core netns "$CORE_NS"
ip link set veth-edge netns "$EDGE_NS"

ip netns exec "$CORE_NS" ip link set lo up
ip netns exec "$CORE_NS" ip addr add 192.0.2.1/24 dev veth-core
ip netns exec "$CORE_NS" ip link set veth-core up

ip netns exec "$EDGE_NS" ip link set lo up
ip netns exec "$EDGE_NS" ip addr add 192.0.2.2/24 dev veth-edge
ip netns exec "$EDGE_NS" ip link set veth-edge up

# Start Core daemon inside CORE_NS (creates real /dev/net/tun `btun0`).
run_node "$CORE_NS" "$BIN" daemon serve \
  --config "$WORK/core.toml" \
  --material-dir "$CORE_MAT" \
  --listen "192.0.2.1:8443" \
  --tun-name "btun0" \
  --mtu 1360 \
  --max-seconds 35 \
  > "$WORK/core.out" 2> "$WORK/core.err" &
echo $! > "$WORK/core.pid"

# Wait for Core `btun0` to appear, then assign permanent VIP 10.20.1.1 and peer route.
for _ in $(seq 1 80); do
  if ip netns exec "$CORE_NS" ip link show btun0 >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
ip netns exec "$CORE_NS" ip addr add 10.20.1.1/32 dev btun0
ip netns exec "$CORE_NS" ip link set btun0 up
ip netns exec "$CORE_NS" ip route add 10.20.1.2/32 dev btun0

# Start Edge daemon inside EDGE_NS (creates real /dev/net/tun `btun0` and dials 192.0.2.1:8443).
run_node "$EDGE_NS" "$BIN" daemon connect \
  --config "$WORK/edge.toml" \
  --material-dir "$EDGE_MAT" \
  --connect "192.0.2.1:8443" \
  --tls-name "wss.boreas.test" \
  --ws-host "wss.boreas.test:8443" \
  --tun-name "btun0" \
  --mtu 1360 \
  --max-seconds 33 \
  > "$WORK/edge.out" 2> "$WORK/edge.err" &
echo $! > "$WORK/edge.pid"

for _ in $(seq 1 80); do
  if ip netns exec "$EDGE_NS" ip link show btun0 >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
ip netns exec "$EDGE_NS" ip addr add 10.20.1.2/32 dev btun0
ip netns exec "$EDGE_NS" ip link set btun0 up
ip netns exec "$EDGE_NS" ip route add 10.20.1.1/32 dev btun0

# Wait until `boreas ctl status` reports `daemon_connected:true` on both nodes.
CONNECTED=0
for _ in $(seq 1 100); do
  if "$BIN" ctl status --socket "$EDGE_STATE/control.sock" 2>/dev/null | grep -q '"daemon_connected":true'; then
    CONNECTED=1
    break
  fi
  sleep 0.05
done
if [[ "$CONNECTED" -ne 1 ]]; then
  echo "ERROR: Edge daemon never reached connected state" >&2
  cat "$WORK/core.err" >&2 || true
  cat "$WORK/edge.err" >&2 || true
  exit 1
fi

# Exercise sparse ICMP traffic and reject the former fixed 25 ms polling delay.
# This threshold applies only to this isolated veth development environment.
ip netns exec "$EDGE_NS" ping -c 10 -i 0.1 -W 2 -I 10.20.1.2 10.20.1.1 | tee "$WORK/ping.log"
grep -q " 0% packet loss" "$WORK/ping.log"
python3 - "$WORK/ping.log" <<'PY'
import os
import re
import sys

limit = float(os.environ.get("BOREAS_MAX_PING_MS", "15.0"))

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)/[0-9.]+ ms", text)
if match is None:
    raise SystemExit("could not parse ping RTT statistics")
minimum, average, maximum = map(float, match.groups())
print(f"overlay_ping_average_ms={average:.3f}")
print(f"overlay_ping_max_ms={maximum:.3f}")
if average > limit or maximum > limit:
    raise SystemExit(
        f"overlay RTT avg={average:.3f} ms max={maximum:.3f} ms exceeds {limit:.3f} ms regression bound"
    )
PY

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
wait "$(cat "$WORK/perf-sender-edge.pid")"
wait "$(cat "$WORK/perf-sender-core.pid")"
wait "$(cat "$WORK/perf-receiver-core.pid")"
wait "$(cat "$WORK/perf-receiver-edge.pid")"
python3 - "$WORK/perf-sender-edge.log" "$WORK/perf-sender-core.log" <<'PY'
import json
import os
import sys

minimum = float(os.environ.get("BOREAS_MIN_THROUGHPUT_MBPS", "3.0"))
expected_bytes = int(os.environ.get("BOREAS_PERF_BYTES", str(8 * 1024 * 1024)))

for label, path in zip(("edge_to_core", "core_to_edge"), sys.argv[1:]):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    if result["bytes"] != expected_bytes:
        raise SystemExit(f"{label} transferred an unexpected byte count")
    if result["throughput_mbps"] < minimum:
        raise SystemExit(f"{label} throughput {result['throughput_mbps']} Mbps is below {minimum} Mbps regression bound")
    print(f"overlay_throughput_{label}_mbps={result['throughput_mbps']:.3f}")
PY

CORE_CTL="$("$BIN" ctl status --socket "$CORE_STATE/control.sock")"
EDGE_CTL="$("$BIN" ctl status --socket "$EDGE_STATE/control.sock")"
echo "Core live ctl: $CORE_CTL"
echo "Edge live ctl: $EDGE_CTL"

wait "$(cat "$WORK/edge.pid")" || { cat "$WORK/edge.err" >&2; exit 1; }
wait "$(cat "$WORK/core.pid")" || { cat "$WORK/core.err" >&2; exit 1; }

echo " Core exit summary: $(cat "$WORK/core.out")"
echo " Edge exit summary: $(cat "$WORK/edge.out")"
grep -q '"status":"ok"' "$WORK/core.out"
grep -q '"status":"ok"' "$WORK/edge.out"
echo "REAL NETNS PQ768 E2E OVERLAY PING + THROUGHPUT SUCCEEDED"
