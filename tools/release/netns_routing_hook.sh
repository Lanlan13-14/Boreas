#!/usr/bin/env bash
# Invoked only by the smoke runner's versioned hooks; never source this file.
set -euo pipefail
[[ "${BOREAS_NETNS_HOOK_PROTOCOL:-}" == 1 ]] || { echo 'smoke hook protocol v1 required' >&2; exit 1; }
PHASE="${1:?phase}" CORE="${2:?core namespace}" EDGE="${3:?edge namespace}" WORK="${4:?work directory}"
CASE="${BOREAS_ROUTING_CASE:?}" OUT="${BOREAS_ROUTING_ARTIFACTS:?}"
case "$CASE" in policy-1500|policy-1280|asymmetric-1500|asymmetric-1280) ;; *) exit 1 ;; esac
[[ "$CORE" == boreas-core-* && "$EDGE" == boreas-edge-* && -d "$OUT" && -d "$WORK" ]] || exit 1
MTU="${CASE##*-}"
nip() { local ns="$1"; shift; ip -n "$ns" "$@"; }
snapshot() {
  local stage="$1" ns role remote source dev gateway
  for role in core edge; do
    if [[ "$role" == core ]]; then
      ns="$CORE"; remote=192.0.2.2; source=192.0.2.1; dev=veth-core; gateway=''
      if [[ "$CASE" == asymmetric-* ]]; then dev=rm-core; gateway=192.0.3.2; fi
    else
      ns="$EDGE"; remote=192.0.2.1; source=192.0.2.2; dev=veth-edge; gateway=''
    fi
    nip "$ns" -j route get "$remote" from "$source" > "$OUT/$stage-$role-peer.json"
    nip "$ns" -j route show table all > "$OUT/$stage-$role-routes.json"
    nip "$ns" -j rule show > "$OUT/$stage-$role-rules.json"
    nip "$ns" -s -j link show > "$OUT/$stage-$role-links.json"
    local management=198.51.100.10
    [[ "$role" != edge ]] || management=198.51.100.9
    nip "$ns" -j route get "$management" > "$OUT/$stage-$role-management.json"
    python3 - "$OUT" "$stage" "$role" "$dev" "$gateway" "$management" <<'PY'
import json, pathlib, sys
out, stage, role, dev, gateway, management = sys.argv[1:]
p = pathlib.Path(out)
def load(suffix):
    return json.loads((p / f'{stage}-{role}-{suffix}.json').read_text())
peer = load('peer')[0]
assert peer['dev'] == dev, peer
assert str(peer.get('table')) == '100', peer
assert peer.get('gateway', '') == gateway, peer
expected_source = '192.0.2.1' if role == 'core' else '192.0.2.2'
assert any(str(r.get('table')) == '100' and r.get('priority') == 100
           and r.get('src') in (expected_source, expected_source + '/32')
           for r in load('rules')), load('rules')
mgmt = load('management')[0]
expected_dev = 'veth-core' if role == 'core' else 'veth-edge'
assert mgmt['dev'] == expected_dev and mgmt.get('gateway') == ('192.0.2.2' if role == 'core' else '192.0.2.1'), mgmt
assert any(r.get('dst') == management and r.get('dev') == expected_dev for r in load('routes')), load('routes')
# Compare the explicit host route and the actual lookup, not unrelated new TUN routes.
keys = ('dst', 'gateway', 'dev', 'prefsrc', 'table', 'metric')
canonical = {k: mgmt[k] for k in keys if k in mgmt}
hosts = [{k: r[k] for k in keys if k in r} for r in load('routes') if r.get('dst') == management]
record = {'lookup': canonical, 'host_routes': hosts}
path = p / f'setup-{role}-protected.json'
if stage == 'setup':
    path.write_text(json.dumps(record, sort_keys=True) + '\n')
else:
    assert record == json.loads(path.read_text()), (record, path.read_text())
if stage == 'ready':
    links = load('links')
    tun = next(r for r in links if r['ifname'] == 'btun0')
    underlay_mtu = 1280 if p.name.endswith('1280') else 1500
    expected = 1280 if underlay_mtu == 1280 else 1360
    assert tun['mtu'] == expected, tun
    for link in links:
        if link['ifname'] in ('veth-core', 'veth-edge', 'rm-core', 'rm-edge'):
            assert link['mtu'] == underlay_mtu, link
PY
  done
}
case "$PHASE" in
  setup)
    for ns in "$CORE" "$EDGE"; do
      # All sysctls are inside disposable namespaces; Linux takes max(all, iface).
      ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    done
    nip "$CORE" link set veth-core mtu "$MTU"
    nip "$EDGE" link set veth-edge mtu "$MTU"
    nip "$CORE" addr add 198.51.100.9/32 dev lo
    nip "$EDGE" addr add 198.51.100.10/32 dev lo
    nip "$CORE" route add 198.51.100.10/32 via 192.0.2.2 dev veth-core
    nip "$EDGE" route add 198.51.100.9/32 via 192.0.2.1 dev veth-edge
    if [[ "$CASE" == asymmetric-* ]]; then
      # Create both ends inside namespaces, never transient host interfaces.
      nip "$CORE" link add rm-core type veth peer name rm-edge
      nip "$CORE" link set rm-edge netns "$EDGE"
      nip "$CORE" addr add 192.0.3.1/30 dev rm-core
      nip "$EDGE" addr add 192.0.3.2/30 dev rm-edge
      nip "$CORE" link set rm-core mtu "$MTU" up
      nip "$EDGE" link set rm-edge mtu "$MTU" up
      nip "$CORE" route add table 100 192.0.3.0/30 dev rm-core scope link src 192.0.3.1
      nip "$CORE" route add table 100 192.0.2.2/32 via 192.0.3.2 dev rm-core src 192.0.2.1
    else
      nip "$CORE" route add table 100 192.0.2.2/32 dev veth-core scope link src 192.0.2.1
    fi
    nip "$EDGE" route add table 100 192.0.2.1/32 dev veth-edge scope link src 192.0.2.2
    nip "$CORE" rule add priority 100 from 192.0.2.1/32 lookup 100
    nip "$EDGE" rule add priority 100 from 192.0.2.2/32 lookup 100
    for spec in "$CORE:veth-core" "$EDGE:veth-edge"; do
      ip netns exec "${spec%%:*}" sysctl -qw "net.ipv4.conf.${spec##*:}.rp_filter=0"
    done
    snapshot setup
    ;;
  ready|verify)
    snapshot "$PHASE"
    # Management host routes must still carry real traffic after TUN installation.
    ip netns exec "$EDGE" ping -n -c 2 -W 2 -I 198.51.100.10 198.51.100.9 > "$OUT/$PHASE-management-ping.log"
    grep -q ' 0% packet loss' "$OUT/$PHASE-management-ping.log"
    if [[ "$PHASE" == verify && "$CASE" == asymmetric-* ]]; then
      python3 - "$OUT" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
for role, dev, direction in [('core', 'rm-core', 'tx'), ('edge', 'rm-edge', 'rx')]:
    def count(stage):
        links = json.loads((p / f'{stage}-{role}-links.json').read_text())
        link = next(r for r in links if r['ifname'] == dev)
        return link['stats64'][direction]['bytes']
    before, after = count('ready'), count('verify')
    # 8 MiB smoke payload must actually traverse the return veth, not merely ARP.
    assert after - before >= 8 * 1024 * 1024, (role, direction, before, after)
PY
    fi
    ;;
  *) echo "unknown hook phase: $PHASE" >&2; exit 1 ;;
esac
printf '%s\n' "$CASE $PHASE assertions passed" > "$OUT/$PHASE.ok"
