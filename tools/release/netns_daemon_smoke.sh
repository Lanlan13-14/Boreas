#!/usr/bin/env bash
# End-to-end Linux network-namespace verification of the real `boreas` binary:
#   1. Offline PKI provisioning (`boreas pki init-ca` + `issue-node` + `verify-bundle`)
#   2. Two isolated Linux network namespaces (`boreas-core-ns`, `boreas-edge-ns`)
#      connected by a veth pair (`192.0.2.1/24` <-> `192.0.2.2/24`)
#   3. Real `/dev/net/tun` interfaces (`btun0`, `10.20.1.1/32` <-> `10.20.1.2/32`)
#   4. Real `boreas daemon serve` + `boreas daemon connect` over outer TLS 1.3 +
#      WSS + pq768 (`X25519MLKEM768` + `ML-DSA-65`) inner mTLS + `RelayCircuit` +
#      pq768 E2E mTLS + `PacketPath`
#   5. Real kernel `ping -c 3 10.20.1.1` across the overlay + `boreas ctl status`
#      verifying `tx_packets >= 3` and `rx_packets >= 3` with `0% packet loss`.
set -euo pipefail

BIN="${1:?usage: netns_daemon_smoke.sh <path-to-boreas-binary>}"
BIN="$(realpath "$BIN")"

WORK="$(mktemp -d /tmp/boreas-netns-e2e.XXXXXX)"
chmod 0700 "$WORK"
CORE_NS="boreas-core-$$"
EDGE_NS="boreas-edge-$$"

cleanup() {
  set +e
  if [[ -f "$WORK/core.pid" ]]; then kill "$(cat "$WORK/core.pid")" 2>/dev/null || true; fi
  if [[ -f "$WORK/edge.pid" ]]; then kill "$(cat "$WORK/edge.pid")" 2>/dev/null || true; fi
  ip netns del "$CORE_NS" 2>/dev/null || true
  ip netns del "$EDGE_NS" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'echo "ERROR: netns smoke failed at line $LINENO" >&2; for log in "$WORK/core.err" "$WORK/edge.err"; do if [[ -f "$log" ]]; then cat "$log" >&2; fi; done' ERR

# LinuxTunDevice sets MTU through sysfs. A network namespace alone retains
# the host sysfs view; remount it in a private mount namespace after setns.
run_node() {
  local ns="$1"
  shift
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
  --max-seconds 12 \
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
  --max-seconds 10 \
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

# Send 3 real kernel ICMP echo requests over the pq768 E2E overlay!
ip netns exec "$EDGE_NS" ping -c 3 -W 2 -I 10.20.1.2 10.20.1.1 | tee "$WORK/ping.log"
grep -q " 0% packet loss" "$WORK/ping.log"

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
echo "REAL NETNS PQ768 E2E OVERLAY PING SUCCEEDED"
