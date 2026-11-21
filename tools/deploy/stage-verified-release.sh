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
usage='usage: stage-verified-release verify MANIFEST ARTIFACT ED25519_SIG MLDSA65_SIG
       stage-verified-release apply --confirm-manifest-sha256 SHA256 MANIFEST ARTIFACT ED25519_SIG MLDSA65_SIG'
mode=${1-}
approved=
case "$mode" in
  verify) [ "$#" -eq 5 ] || fail "$usage"; shift ;;
  apply)
    [ "$#" -eq 7 ] && [ "$2" = --confirm-manifest-sha256 ] || fail "$usage"
    approved=$3
    [ "${#approved}" -eq 64 ] || fail 'approval must be a lowercase SHA-256'
    case "$approved" in *[!0-9a-f]*) fail 'approval must be a lowercase SHA-256' ;; esac
    shift 3 ;;
  *) fail "$usage" ;;
esac
for input in "$@"; do
  case "$input" in /*) : ;; *) fail 'all candidate inputs must be absolute local paths' ;; esac
done
unit=/etc/systemd/system/boreas.service
sup=/usr/local/libexec/boreas/boreas-supervisor
store=/var/lib/boreas/releases
trust=/etc/boreas/release-trust
manager() { /usr/bin/env -i PATH="$PATH" systemctl --system "$@" 9<&-; }
property() { manager show --property="$1" --value boreas.service; }
[ "$(property FragmentPath)" = "$unit" ] || fail 'verified unit not installed'
drop_ins=$(property DropInPaths) || fail 'cannot inspect unit drop-ins'
[ -z "$drop_ins" ] || fail 'review and migrate unit drop-ins explicitly'
[ "$(property Type)" = notify ] && [ "$(property NotifyAccess)" = main ] \
  && [ "$(property User)" = boreas ] && [ "$(property Group)" = boreas ] \
  && [ "$(id -u boreas)" -gt 0 ] || fail 'expected dedicated non-root notify unit'
case "$(property ExecStart)" in
  *'path=/usr/local/libexec/boreas/boreas-service ; argv[]=/usr/local/libexec/boreas/boreas-service ;'*) : ;;
  *) fail 'refusing to operate on a different service' ;;
esac
for dir in /usr /usr/local /usr/local/libexec /usr/local/libexec/boreas /etc /etc/boreas; do
  [ -d "$dir" ] && [ ! -L "$dir" ] && [ "$(stat -c '%u' "$dir")" = 0 ] \
    || fail 'deployment path has an untrusted ancestor'
  [ $((0$(stat -c '%a' "$dir") & 022)) -eq 0 ] \
    || fail 'deployment path has a writable ancestor'
done
for executable in "$sup" /usr/local/libexec/boreas/boreas-service; do
  if [ ! -f "$executable" ] || [ -L "$executable" ] || [ ! -x "$executable" ] \
    || [ "$(stat -c '%u %a' "$executable")" != '0 755' ]; then
    fail 'trusted supervisor or service launcher missing or not root-owned 0755'
  fi
done
if [ ! -d "$trust" ] || [ -L "$trust" ] || [ "$(stat -c '%u %a' "$trust")" != '0 700' ]; then
  fail 'invalid release trust directory'
fi
for name in key-id min-sequence ed25519.der mldsa65.der; do
  file=$trust/$name
  if [ ! -f "$file" ] || [ -L "$file" ] || [ "$(stat -c '%u %a' "$file")" != '0 600' ]; then
    fail "invalid release trust input: $name"
  fi
done
IFS= read -r key_id <"$trust/key-id" || fail 'missing release key ID'
IFS= read -r min_sequence <"$trust/min-sequence" || fail 'missing admission floor'

# root handles only independent trust inputs. Candidate files are opened by
# the non-root staging process; put them in a boreas-readable offline spool.
# Hold an operator lock across stop, stage and start; the Rust writer lock is
# independent and protects the journal itself.
# /run/lock can be world-writable on some distributions. The mode-0700
# independent trust directory is already validated and root controls /run.
exec 9<"$trust"
flock -n 9 || fail 'another deployment operation is active'
work=$(mktemp -d /run/boreas-release.XXXXXX)
was_active=0
stopped=0
cleanup() {
  rc=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "$work" || printf '%s\n' 'WARNING: cannot remove temporary public-key spool' >&2
  if [ "$rc" -ne 0 ] && [ "$stopped" -eq 1 ] && [ "$was_active" -eq 1 ]; then
    manager start boreas.service || printf '%s\n' 'ERROR: could not restore previously running service; inspect journal and active pointer' >&2
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
admit() (
  command=$1; shift
  manifest=$1 artifact=$2 ed=$3 mldsa=$4; shift 4
  # Do not pass the root lock, caller environment, cwd or stdin to this UID.
  cd /
  runuser -u boreas -- /usr/bin/env -i PATH=/usr/bin:/bin "$sup" "$command" \
    --store "$store" --manifest "$manifest" --artifact "$artifact" \
    --ed25519-signature "$ed" --mldsa65-signature "$mldsa" --root-key-id "$key_id" \
    --root-ed25519-der "$work/ed25519.der" --root-mldsa65-der "$work/mldsa65.der" \
    --min-sequence "$min_sequence" "$@" 9<&- </dev/null
)
if [ "$mode" = verify ]; then
  admit verify-stage "$@"
  exit
fi
verified=$(admit verify-stage "$@" --confirm-manifest-sha256 "$approved") \
  || fail 'preflight rejected; the service was not stopped'
case "$verified" in "verified release-"*" $approved") : ;; *) fail 'unexpected verifier output' ;; esac
expected=${verified#verified }
expected=${expected% *}
# Refuse a unit that is currently activating/deactivating or restarting.
case "$(property ActiveState)" in
  active) was_active=1 ;;
  inactive|failed) : ;;
  *) fail 'service is transitioning; inspect its status and retry' ;;
esac
if [ "$was_active" -eq 1 ]; then
  active=$(runuser -u boreas -- /bin/cat "$store/active.version" 9<&-)
  if [ "$active" = "$expected" ]; then
    manager is-active --quiet boreas.service || fail 'service exited after readiness'
    printf 'Already running %s; no restart.\n' "$expected"
    exit
  fi
fi
stopped=1
manager stop boreas.service
# Reopen only as boreas. Re-verify every byte and the same approved raw
# manifest under the stage path; a swap after preflight cannot authorize
# another release or different ELF. Publication uses the verified buffer.
[ "$(admit stage "$@" --confirm-manifest-sha256 "$approved")" = "staged $expected" ] \
  || fail 'candidate not staged'
manager start boreas.service || fail 'service did not report readiness; inspect journal'
stopped=0
active=$(runuser -u boreas -- /bin/cat "$store/active.version" 9<&-)
manager is-active --quiet boreas.service || fail 'service exited after readiness'
[ "$active" = "$expected" ] || fail "candidate not confirmed; service is running retained $active"
printf 'Confirmed %s after daemon readiness.\n' "$active"
