#!/bin/sh
# Actions-only integration harness: install a freshly compiled static candidate
# using the production installer and real host id/stat/readelf/hash utilities.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
DEPLOY=$ROOT/tools/deploy
BIN=${1:?usage: test-real-install.sh STATIC_BOREAS_BINARY}
[ -f "$BIN" ] && [ ! -L "$BIN" ] || { echo 'candidate must be a regular file' >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || { echo 'run harness unprivileged; it invokes sudo only for installation' >&2; exit 1; }
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'real-install harness is restricted to GitHub Actions' >&2; exit 1; }
command -v sudo >/dev/null 2>&1 || { echo 'sudo required' >&2; exit 1; }
command -v readelf >/dev/null 2>&1 || { echo 'readelf required' >&2; exit 1; }
# The installer walks every ancestor; give it a genuinely root-owned, private
# tree rather than weakening the production ownership/mode gate.
# RUNNER_TEMP is normally below /home/runner and therefore fails the installer's
# required root-owned-ancestor check. Use a fresh root-owned /var/cache child;
# every existing ancestor there is root-owned and non-writable to group/other.
T=$(sudo mktemp -d /var/cache/boreas-real-install.XXXXXX)
BAD=$(mktemp)
trap 'sudo rm -rf -- "$T"; rm -f -- "$BAD"' EXIT HUP INT TERM
# Keep generated inputs private under root-owned, mode-0700 T. Run the
# installer/inspection operations through sudo so the tree remains closed.
ROOT_BIN=$T/candidate
sudo cp -- "$BIN" "$ROOT_BIN"
sudo chmod 0700 "$ROOT_BIN"
BIN=$ROOT_BIN
P=$T/prefix
B=$T/bindir
sudo mkdir -m 0700 "$P" "$B"
# Make real, internally consistent node bundles with the candidate itself.
# local.signed and peer.signed must carry two independent node identities.
NET=0123456789abcdef0123456789abcdef
CORE=$T/materials-core
EDGE=$T/materials-edge
sudo "$BIN" pki init-ca --ca-dir "$T/ca" --net-id "$NET" --validity-days 30
sudo "$BIN" pki issue-node --ca-dir "$T/ca" --out-dir "$CORE" --role core --home-core 1 --vip-octet 1 --validity-hours 12 --outer-san wss.example.net
sudo "$BIN" pki issue-node --ca-dir "$T/ca" --out-dir "$EDGE" --role edge --home-core 1 --vip-octet 2 --validity-hours 12
# Peer exchange is normally bidirectional; only the core bundle is installed below.
sudo cp "$EDGE/local.signed" "$CORE/peer.signed"
sudo cp "$CORE/local.signed" "$EDGE/peer.signed"
sudo "$BIN" pki verify-bundle --material-dir "$CORE" --require-peer >/dev/null
sudo cp -- "$ROOT/docs/config/config.legacy-v1.example.toml" "$T/config.toml"
# Config's absolute input paths are references only; installer canonicalizes
# and relocates its three path fields into the temporary prefix.
HASH=$(sudo sha256sum -- "$BIN" | awk '{print $1}')
REL=gha-${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-1}
set -- --binary "$BIN" --sha256 "$HASH" --release "$REL" --materials "$CORE" --config "$T/config.toml" --prefix "$P" --bindir "$B" --service none
sudo sh "$DEPLOY/install.sh" "$@"
ACTIVE=$(sudo sed -n '1p' "$P/active")
[ "$ACTIVE" = "$REL" ]
[ "$(sudo sha256sum "$P/releases/$ACTIVE/boreas" | awk '{print $1}')" = "$HASH" ]
sudo readelf -h "$P/releases/$ACTIVE/boreas" | grep -q ELF64
# Inspect program-header type fields, not the whole line (which always contains
# the word INTERP in GNU readelf's column heading).
PH=$(sudo readelf -l "$P/releases/$ACTIVE/boreas")
if printf '%s\n' "$PH" | awk '$1 == "INTERP" { found=1 } END { exit !found }'; then
  echo 'candidate unexpectedly has a PT_INTERP program header' >&2; exit 1
fi
sudo "$B/boreas" --help >/dev/null
sudo "$B/boreas" doctor >/dev/null
# Wrong digest must fail before candidate execution or changing active pointer.
if sudo sh "$DEPLOY/install.sh" --binary "$BIN" --sha256 "$(printf '%064d' 0)" --release "$REL" --materials "$CORE" --config "$T/config.toml" --prefix "$P" --bindir "$B" --service none >"$BAD" 2>&1; then
  echo 'wrong hash unexpectedly accepted' >&2; exit 1
fi
grep -q 'SHA-256 mismatch' "$BAD"
[ "$(sudo sed -n '1p' "$P/active")" = "$REL" ]
# Same release with a different binary must reject a conflicting bundle. Change
# one byte in a copied executable while retaining a valid ELF (tail append).
sudo cp -- "$BIN" "$T/conflict"
printf '\nconflict\n' | sudo tee -a "$T/conflict" >/dev/null
CH=$(sudo sha256sum "$T/conflict" | awk '{print $1}')
if sudo sh "$DEPLOY/install.sh" --binary "$T/conflict" --sha256 "$CH" --release "$REL" --materials "$CORE" --config "$T/config.toml" --prefix "$P" --bindir "$B" --service none >"$BAD" 2>&1; then
  echo 'conflicting existing release unexpectedly accepted' >&2; exit 1
fi
grep -q 'already exists with a different bundle' "$BAD"
[ "$(sudo sed -n '1p' "$P/active")" = "$REL" ]
# Negative prefix-security gates on the real install path. Every input except
# --prefix is the same valid set used above; --service none means no service
# manager runs and /etc is not written. Snapshot the genuine successful install
# so each refusal must leave the pointer and active binary byte-identical.
GOOD_INSTALL=$(sudo sha256sum -- "$P/active" "$P/releases/$ACTIVE/boreas")
expect_unsafe_prefix_rejected() { # $1=prefix, $2=exact production error line
  if sudo sh "$DEPLOY/install.sh" --binary "$BIN" --sha256 "$HASH" --release "$REL" \
      --materials "$CORE" --config "$T/config.toml" --prefix "$1" --bindir "$B" --service none >"$BAD" 2>&1; then
    echo "installer accepted unsafe --prefix: $1" >&2; exit 1
  fi
  # Whole-line, case-sensitive production message: an earlier unrelated failure
  # must not satisfy the gate.
  grep -Fqx -- "$2" "$BAD" || {
    echo "installer refused unsafe --prefix for an unexpected reason: $1" >&2
    sed -n '1,80p' "$BAD" >&2
    exit 1
  }
  [ "$(sudo sha256sum -- "$P/active" "$P/releases/$ACTIVE/boreas")" = "$GOOD_INSTALL" ] || {
    echo "existing good installation changed after refusing: $1" >&2; exit 1
  }
}
# Only these fresh children of the root-owned 0700 T are deliberately weakened.
UNSAFE=$T/unsafe-writable
sudo mkdir -m 0700 -- "$UNSAFE"
sudo chmod 0777 -- "$UNSAFE"
NONROOT=$T/nonroot-owner
sudo mkdir -m 0700 -- "$NONROOT"
sudo chown "$(id -u):$(id -g)" -- "$NONROOT"
sudo ln -s -- "$P" "$T/prefix-symlink"
expect_unsafe_prefix_rejected "$UNSAFE/prefix" \
  "install: error: --prefix must not be group/other writable: $UNSAFE"
# The non-root case is an empty fresh directory; node material ownership and
# modes (including private keys) are never weakened for the unprivileged user.
expect_unsafe_prefix_rejected "$NONROOT/prefix" \
  "install: error: --prefix must be owned by root (uid 0): $NONROOT"
expect_unsafe_prefix_rejected "$T/prefix-symlink" \
  "install: error: --prefix must not be a symbolic link: $T/prefix-symlink"
LEFTOVERS=$(sudo find "$UNSAFE" "$NONROOT" -mindepth 1 -maxdepth 1 -print -quit) || {
  echo 'cannot verify unsafe prefixes stayed unwritten' >&2; exit 1
}
[ -z "$LEFTOVERS" ] || { echo 'installer wrote beneath an unsafe prefix ancestor' >&2; exit 1; }
# Undo the deliberate 0777 and remove only this run's temporary children; the
# EXIT trap still removes T itself.
sudo chmod 0700 -- "$UNSAFE"
sudo rm -rf -- "$UNSAFE" "$NONROOT"
sudo rm -f -- "$T/prefix-symlink"
echo "unsafe --prefix gates passed; existing good install preserved (active $ACTIVE, sha256 $HASH)"
[ ! -e /etc/systemd/system/boreas.service ] && [ ! -e /etc/init.d/boreas ] || { echo 'unexpected service unit on host' >&2; exit 1; }
echo 'real installer integration passed (development candidate; no service start)'
