#!/usr/bin/env bash
# Real two-node pq768 daemon tests; delegates PKI, daemon lifetime and traffic to smoke.
set -euo pipefail
BIN="$(realpath "${1:?usage: netns_routing_matrix.sh <static-boreas> [artifact-directory]}")"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="${2:-$PWD/routing-matrix-artifacts}"
mkdir -p "$OUT"
OUT="$(realpath "$OUT")"
[[ "$(uname -s)" == Linux && "$EUID" == 0 ]] || { echo 'Linux root/CAP_NET_ADMIN + mount privileges required' >&2; exit 1; }
[[ -x "$BIN" ]] || { echo 'boreas binary must be executable' >&2; exit 1; }
for tool in ip unshare mount sysctl ping python3 readelf timeout; do
  command -v "$tool" >/dev/null || { echo "missing prerequisite: $tool" >&2; exit 1; }
done
# Reject dynamically linked binaries rather than silently changing the test contract.
readelf -l "$BIN" > "$OUT/elf-program-headers.txt"
if grep -q 'INTERP' "$OUT/elf-program-headers.txt"; then
  echo 'routing matrix requires the static release binary (PT_INTERP found)' >&2
  exit 1
fi
[[ -c /dev/net/tun ]] || { echo '/dev/net/tun is required' >&2; exit 1; }
for case_name in policy-1500 asymmetric-1500 policy-1280 asymmetric-1280; do
  case_out="$OUT/$case_name"
  # Do not permit markers from an earlier run to count as evidence.
  mkdir "$case_out"
  mtu="${case_name##*-}"
  tun_mtu=1360
  [[ "$mtu" != 1280 ]] || tun_mtu=1280
  echo "=== routing case: $case_name (underlay=$mtu tun=$tun_mtu) ==="
  # Explicit environment allowlist: no inherited rootfs/netem/skip/threshold overrides.
  env -i PATH="$PATH" HOME="${HOME:-/root}" LANG=C LC_ALL=C \
    BOREAS_NETNS_HOOK="$HERE/netns_routing_hook.sh" BOREAS_NETNS_HOOK_VERSION=1 \
    BOREAS_ROUTING_CASE="$case_name" BOREAS_ROUTING_ARTIFACTS="$case_out" \
    BOREAS_TUN_MTU="$tun_mtu" \
    timeout --signal=TERM --kill-after=10s 180s \
    bash "$HERE/netns_daemon_smoke.sh" "$BIN" 2>&1 | tee "$case_out/smoke.log"
  for phase in setup ready verify; do
    [[ -f "$case_out/$phase.ok" ]] || { echo "missing hook evidence: $case_name/$phase" >&2; exit 1; }
  done
  printf '%s\n' "$case_name passed real daemon smoke + routing assertions" | tee "$case_out/result.txt"
done
echo 'REAL STATIC PQ768 TWO-NODE ROUTING MATRIX SUCCEEDED (not multi-Core)'
