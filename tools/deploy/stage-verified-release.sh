#!/bin/sh
# Explicit privileged operator command; the staged binary and supervisor run
# as boreas. No network, new root or implicit clean-slate initialization.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
fail() { printf 'stage-verified-release: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'administrator required'
[ "$#" -eq 4 ] || fail 'usage: stage-verified-release.sh MANIFEST ARTIFACT ED25519_SIG MLDSA65_SIG'
unit=/etc/systemd/system/boreas.service
sup=/usr/local/libexec/boreas/boreas-supervisor
store=/var/lib/boreas/releases
trust=/etc/boreas/release-trust
[ "$(systemctl show --property=FragmentPath --value boreas.service)" = "$unit" ] || fail 'verified unit not installed'
case "$(systemctl show --property=ExecStart --value boreas.service)" in
  *'path=/usr/local/libexec/boreas/boreas-service ;'*) : ;;
  *) fail 'refusing to operate on a different service' ;;
esac
[ -x "$sup" ] || fail 'trusted supervisor missing'
[ -d "$trust" ] && [ ! -L "$trust" ] && [ "$(stat -c '%u %a' "$trust")" = '0 700' ] || fail 'invalid release trust directory'
for name in key-id min-sequence ed25519.der mldsa65.der; do
  file=$trust/$name
  [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c '%u %a' "$file")" = '0 600' ] || fail "invalid release trust input: $name"
done
IFS= read -r key_id <"$trust/key-id" || fail 'missing release key ID'
IFS= read -r min_sequence <"$trust/min-sequence" || fail 'missing admission floor'

# root handles only independent trust inputs. Candidate files are opened by
# the non-root staging process; put them in a boreas-readable offline spool.
# Hold an operator lock across stop, stage and start; the Rust writer lock is
# independent and protects the journal itself.
exec 9>/run/lock/boreas-release.lock
flock -n 9 || fail 'another deployment operation is active'
work=$(mktemp -d /run/boreas-release.XXXXXX)
was_active=0
stopped=0
cleanup() {
  rc=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "$work"
  if [ "$rc" -ne 0 ] && [ "$stopped" -eq 1 ] && [ "$was_active" -eq 1 ]; then
    systemctl start boreas.service || printf '%s\n' 'ERROR: could not restore previously running service; inspect journal and active pointer' >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chgrp boreas "$work"
chmod 0750 "$work"
install -m0640 -o root -g boreas "$trust/ed25519.der" "$work/ed25519.der"
install -m0640 -o root -g boreas "$trust/mldsa65.der" "$work/mldsa65.der"
if systemctl is-active --quiet boreas.service; then was_active=1; fi
stopped=1
systemctl stop boreas.service
expected=$(runuser -u boreas -- "$sup" stage --store "$store" --manifest "$1" --artifact "$2" \
  --ed25519-signature "$3" --mldsa65-signature "$4" --root-key-id "$key_id" \
  --root-ed25519-der "$work/ed25519.der" --root-mldsa65-der "$work/mldsa65.der" --min-sequence "$min_sequence")
case "$expected" in 'staged release-'*) expected=${expected#staged } ;; *) fail 'unexpected verifier output' ;; esac
systemctl start boreas.service || fail 'service did not report readiness; inspect journal'
stopped=0
active=$(runuser -u boreas -- cat "$store/active.version")
systemctl is-active --quiet boreas.service || fail 'service exited after readiness'
[ "$active" = "$expected" ] || fail "candidate not confirmed; service is running retained $active"
printf 'Confirmed %s after daemon readiness.\n' "$active"
