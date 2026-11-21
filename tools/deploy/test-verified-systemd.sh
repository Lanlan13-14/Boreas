#!/usr/bin/env bash
# GitHub-hosted disposable Linux VM only. Provisioning needs administrator
# permission; the actual unit, supervisor and daemon run as UID boreas.
set -euo pipefail
umask 077
bin=$(realpath "${1:?static Boreas daemon required}")
supervisor=$(realpath "${2:?trusted test supervisor required}")
openssl=$(realpath "${3:?pinned OpenSSL command required}")
fail_bin=$(realpath "${4:?signed failure-fixture candidate required}")
wait_bin=$(realpath "${5:?signed waiting fixture candidate required}")
dir=$(realpath "$(dirname "$0")")
[[ $(id -u) = 0 && ${GITHUB_ACTIONS:-} = true && ${RUNNER_ENVIRONMENT:-} = github-hosted ]]
work=$(mktemp -d /tmp/boreas-ci.XXXXXX)
trust="$work/trust"
trust_installed=/etc/boreas/release-trust
store=/var/lib/boreas/releases
state=/var/lib/boreas/state
sup=/usr/local/libexec/boreas/boreas-supervisor
release_cmd=/usr/local/libexec/boreas/stage-verified-release
iface=boreas-ci0
installed=0
cleanup() {
  if (( installed )); then
    journalctl --no-pager -u boreas.service -n 150 || true
    systemctl stop boreas.service || true
    ip tuntap del dev "$iface" mode tun || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT
modprobe tun || test -c /dev/net/tun
install -m0755 "$supervisor" "$work/supervisor"
"$dir/install-verified-unit.sh" "$work/supervisor"
installed=1
mkdir "$trust"
# Only this user's staging process can traverse into the input subdirectory;
# the ephemeral signing private keys and node CA remain root-only.
chmod 0711 "$work"
chgrp boreas "$trust"
chmod 0750 "$trust"
for alg in ed25519 mldsa65; do
  "$openssl" genpkey -algorithm "$alg" -out "$work/$alg.key"
  "$openssl" pkey -in "$work/$alg.key" -pubout -outform DER -out "$trust/$alg.der"
done
install -m0600 "$trust/ed25519.der" "$trust/mldsa65.der" "$trust_installed/"
printf '%s\n' ci-release >"$trust_installed/key-id"
printf '%s\n' 1 >"$trust_installed/min-sequence"
net=0123456789abcdef0123456789abcdef
"$bin" pki init-ca --ca-dir "$work/ca" --net-id "$net" --validity-days 30
"$bin" pki issue-node --ca-dir "$work/ca" --out-dir "$work/core" --role core --home-core 1 --vip-octet 1 --outer-san wss.boreas.test
"$bin" pki issue-node --ca-dir "$work/ca" --out-dir "$work/edge" --role edge --home-core 1 --vip-octet 2
install -o boreas -g boreas -m0600 "$work/core/"* /etc/boreas/materials/
install -o boreas -g boreas -m0600 "$work/edge/local.signed" /etc/boreas/materials/peer.signed
mkdir "$work/policy"
"$bin" pki sign-policy --ca-dir "$work/ca" --out-dir "$work/policy" --sequence 1 --ttl-seconds 3600
for pair in 'tbs.cbor policy.tbs' 'ed25519.sig policy.ed25519.sig' 'mldsa65.sig policy.mldsa65.sig' \
  'root-ed25519.der network-root.ed25519.der' 'root-mldsa65.der network-root.mldsa65.der'; do
  read -r src dst <<<"$pair"
  install -o boreas -g boreas -m0600 "$work/policy/$src" "$state/$dst"
done
cat >/etc/boreas/node.toml <<'EOF'
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
identity_key = "/etc/boreas/materials/identity.key"
roots = ["/etc/boreas/materials/roots.cbor"]
state_dir = "/var/lib/boreas/state"
[uplink]
primary = "wss.boreas.test:8443"
paths = 4
probe_paths = 1
EOF
chown boreas:boreas /etc/boreas/node.toml
cat >/etc/boreas/service.env <<EOF
BOREAS_ROLE=core
BOREAS_LISTEN=127.0.0.1:18443
BOREAS_TUN_NAME=$iface
BOREAS_MTU=1360
BOREAS_MIN_RUN_SEQUENCE=1
EOF
ip tuntap add dev "$iface" mode tun user boreas
ip link set dev "$iface" mtu 1360 up
ip addr add 10.20.1.1/32 dev "$iface"
ip route add 10.20.1.2/32 dev "$iface"

emit() {
  local seq=$1 name=$2 artifact=$3 end=${4:-future}
  install -g boreas -m0640 "$artifact" "$trust/$name.bin"
  python3 - "$seq" "$name" "$trust/$name.bin" "$end" >"$trust/$name.json" <<'PY'
from datetime import datetime, timedelta, timezone
import hashlib, json, pathlib, sys
n, name, path, end = sys.argv[1:]
now = datetime.now(timezone.utc)
def stamp(delta):
    return (now + timedelta(seconds=delta)).strftime('%Y-%m-%dT%H:%M:%SZ')
data = pathlib.Path(path).read_bytes()
print(json.dumps(dict(product='boreas', manifest_version=1, sequence=int(n),
    published_at=stamp(-120), issued_at=stamp(-90), expires=stamp(-30 if end == 'expired' else 3600),
    min_compatible_state='boreas-node-state-v1', signing_key_id='ci-release',
    assets=[dict(name=name, arch='x86_64-unknown-linux-musl', size=len(data),
                 sha256=hashlib.sha256(data).hexdigest(), url='https://example.invalid/' + name)])))
PY
  for alg in ed25519 mldsa65; do
    "$openssl" pkeyutl -sign -rawin -inkey "$work/$alg.key" -in "$trust/$name.json" -out "$trust/$name.$alg"
  done
  chgrp boreas "$trust/"*
  chmod 0640 "$trust/"*
}
stage() {
  local name=$1
  runuser -u boreas -- "$sup" stage --store "$store" --manifest "$trust/$name.json" \
    --artifact "$trust/$name.bin" --root-key-id ci-release \
    --root-ed25519-der "$trust/ed25519.der" --root-mldsa65-der "$trust/mldsa65.der" \
    --ed25519-signature "$trust/$name.ed25519" --mldsa65-signature "$trust/$name.mldsa65" --min-sequence 1
}
reject() {
  local name=$1 diagnostic=$2
  local watermark_before watermark_after
  watermark_before=$(cat "$store/verified-release.state" 2>/dev/null || true)
  if stage "$name" >"$work/rejected" 2>&1; then
    echo "ERROR: $name unexpectedly staged" >&2; exit 1
  fi
  cat "$work/rejected"
  grep -Eiq "$diagnostic" "$work/rejected"
  watermark_after=$(cat "$store/verified-release.state" 2>/dev/null || true)
  [[ $watermark_before == "$watermark_after" ]]
}
unit_ready() {
  [[ $(systemctl show --value -p ActiveState boreas.service) == active ]]
  # The Core is ready to accept, not falsely connected. A real non-root daemon
  # minted the reply, not the supervisor or the ability to observe a TUN link.
  runuser -u boreas -- "$bin" ctl status --socket "$state/control.sock" | grep -q '"daemon_connected":false'
  local pid child
  pid=$(systemctl show --value -p MainPID boreas.service)
  child=$(pgrep -P "$pid")
  [[ $(readlink "/proc/$child/exe") == '/memfd:boreas-verified (deleted)' ]]
  grep -Eq '^NoNewPrivs:[[:space:]]+1$' "/proc/$child/status"
  grep -Eq '^Seccomp:[[:space:]]+2$' "/proc/$child/status"
  grep -Eq '^CapEff:[[:space:]]+0+$' "/proc/$child/status"
  grep -Eq '^CapPrm:[[:space:]]+0+$' "/proc/$child/status"
  [[ $(awk '/^Uid:/{print $3}' "/proc/$child/status") == "$(id -u boreas)" ]]
}

emit 1 real "$bin"
emit 9 expired "$bin" expired
reject expired 'expir'
for bad in ed25519 mldsa65; do
  emit 9 "bad-$bad" "$bin"
  # Valid shape and one good signature; AND, not OR.
  truncate -s 0 "$trust/bad-$bad.$bad"
  truncate -s "$([[ $bad == ed25519 ]] && printf 64 || printf 3309)" "$trust/bad-$bad.$bad"
  reject "bad-$bad" 'signature|verification'
done
emit 9 tampered "$bin"
# Change only an ELF identification padding byte, not the magic or program headers.
printf '\377' | dd of="$trust/tampered.bin" bs=1 seek=15 conv=notrunc status=none
reject tampered 'SHA-256|digest|hash'
[[ ! -e $store/verified-release.state && ! -e $store/active.version ]]

"$release_cmd" "$trust/real.json" "$trust/real.bin" "$trust/real.ed25519" "$trust/real.mldsa65"

unit_ready
old=$(cat "$store/active.version")
[[ $old == release-1-* ]]
runuser -u boreas -- "$sup" status --store "$store" --json | grep -q '"phase":"Confirmed"'

emit 2 failing "$fail_bin"
if "$release_cmd" "$trust/failing.json" "$trust/failing.bin" "$trust/failing.ed25519" "$trust/failing.mldsa65"; then
  echo 'ERROR: failed signed candidate was reported as confirmed' >&2; exit 1
fi
unit_ready
[[ $(cat "$store/active.version") == "$old" ]]
runuser -u boreas -- "$sup" status --store "$store" --json | grep -q '"phase":"Prepared"'
journalctl --no-pager -u boreas.service | grep -F 'restarting retained verified release'

systemctl stop boreas.service
systemctl reset-failed boreas.service
reject real 'rollback'
emit 2 different "$bin"
reject different 'equivocation'
emit 3 valid-next "$bin"
stage valid-next
# Tampering after staging, even when the filename still claims the old hash.
next=$(cut -d' ' -f1 "$store/verified-release.state")
printf '\377' | dd of="$store/versions/$next/boreas" bs=1 seek=0 conv=notrunc status=none
systemctl start boreas.service
unit_ready
[[ $(cat "$store/active.version") == "$old" ]]
journalctl --no-pager -u boreas.service | grep -F 'verified trial image rejected before execution: stored binary SHA-256 mismatch'

systemctl stop boreas.service
systemctl reset-failed boreas.service
emit 4 interrupted "$wait_bin"
stage interrupted
systemctl start --no-block boreas.service
# Await the actual waiting candidate (not just journal activation), so the
# interrupted supervisor was demonstrably in the verified launch path.
seen=0
for ((i=0; i<200; i++)); do
  pid=$(systemctl show --value -p MainPID boreas.service)
  child=$(pgrep -P "$pid" 2>/dev/null || true)
  if [[ -n $child && $child != *$'\n'* && -r /proc/$child/cmdline ]] &&
     tr '\0' ' ' <"/proc/$child/cmdline" | grep -Fq ' daemon serve '; then
    seen=1
    break
  fi
  sleep .05
done
(( seen ))
[[ $(cat "$store/active.version") == release-4-* ]]
kill -KILL "$pid"
# Let systemd's normal restart start the retained artifact under the next
# supervisor. Service-manager restart triggers recovery, not candidate retry.
for ((i=0; i<200; i++)); do
  if [[ $(systemctl show --value -p ActiveState boreas.service) == active ]]; then break; fi
  sleep .05
done
unit_ready
[[ ! -e /proc/$child && $(cat "$store/active.version") == "$old" ]]
journalctl --no-pager -u boreas.service | grep -F 'rolled back before launch'
systemctl stop boreas.service
systemctl reset-failed boreas.service

# An emergency minimum runnable release must also veto the fallback.
sed -i 's/^BOREAS_MIN_RUN_SEQUENCE=1$/BOREAS_MIN_RUN_SEQUENCE=3/' /etc/boreas/service.env
if systemctl start boreas.service; then
  echo 'ERROR: supervisor started a below-floor fallback' >&2; exit 1
fi
journalctl --no-pager -u boreas.service | grep -F "below the operator's minimum runnable sequence"
systemctl stop boreas.service
