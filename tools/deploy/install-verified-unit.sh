#!/bin/sh
# Installs the authenticated Linux/systemd service framework, not a candidate.
# Run from an independently trusted copy of these deployment tools.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

fail() { printf 'install-verified-unit: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'administrator required to install the unit (the service never runs as root)'
[ "$#" -eq 1 ] || fail 'usage: install-verified-unit.sh <independently-trusted-installed-supervisor>'
case "$1" in /*) ;; *) fail 'trusted supervisor path must be absolute' ;; esac
[ -f "$1" ] && [ ! -L "$1" ] && [ -x "$1" ] || fail 'trusted supervisor must be a regular executable'
[ "$(stat -c '%u' -- "$1")" = 0 ] || fail 'trusted supervisor must be owned by root'
if [ $((0$(stat -c '%a' -- "$1") & 022)) -ne 0 ]; then fail 'trusted supervisor is writable by group/other'; fi
src=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
unit=/etc/systemd/system/boreas.service
libexec=/usr/local/libexec/boreas
[ ! -e "$unit" ] && [ ! -L "$unit" ] || fail 'boreas.service already exists; use explicit migration, not overwrite'
unit_state=$(systemctl show --property=LoadState --value boreas.service) || fail 'systemd required'
[ "$unit_state" = not-found ] || fail 'an existing service definition must be migrated explicitly'
[ ! -e /etc/init.d/boreas ] && [ ! -L /etc/init.d/boreas ] || fail 'existing procd/service deployment must be migrated explicitly'
[ ! -e "$libexec" ] && [ ! -L "$libexec" ] || fail 'trusted libexec directory already exists'
[ ! -e /var/lib/boreas ] && [ ! -L /var/lib/boreas ] || fail 'state already exists; do not reinitialize or change its owner'
[ ! -e /etc/boreas ] && [ ! -L /etc/boreas ] || fail 'existing configuration must be migrated explicitly'
if getent passwd boreas >/dev/null || getent group boreas >/dev/null; then
  fail 'boreas user/group already exists; dedicated account ownership needs explicit migration'
fi
useradd --system --user-group --home-dir /var/lib/boreas --shell /usr/sbin/nologin boreas
install -d -m 0755 -o root -g root "$libexec"
install -m 0755 -o root -g root "$1" "$libexec/boreas-supervisor"
install -m 0755 -o root -g root "$src/boreas-service" "$libexec/boreas-service"
install -m 0755 -o root -g root "$src/stage-verified-release.sh" "$libexec/stage-verified-release"
install -d -m 0750 -o root -g boreas /var/lib/boreas /etc/boreas /etc/boreas/materials
install -d -m 0700 -o root -g root /etc/boreas/release-trust
install -d -m 0700 -o boreas -g boreas /var/lib/boreas/releases /var/lib/boreas/state
tmp=$(mktemp -d /etc/systemd/system/.boreas-install.XXXXXX)
trap 'rm -rf -- "$tmp"' EXIT
install -m 0644 -o root -g root "$src/boreas.verified.service" "$tmp/boreas.service"
systemd-analyze verify "$tmp/boreas.service"
ln -- "$tmp/boreas.service" "$unit"
systemctl daemon-reload
printf '%s\n' 'Boreas unit installed but NOT started. Provision policy, node, TUN, and independent release trust before staging a candidate.'
