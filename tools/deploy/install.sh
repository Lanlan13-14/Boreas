#!/bin/sh
# Boreas POSIX deployment helper. Installs an already-built static binary; it never builds one.
#
# What this script proves: the staged bytes match an operator-supplied SHA-256, the
# ELF is statically linked and matches this host architecture, and node materials
# contain no CA/authority private keys. What it does NOT prove: that the digest or
# the binary came from a trusted publisher. The digest must arrive through a channel
# independent of the binary source.
set -eu
umask 077

SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
PREFIX=/opt/boreas
BINDIR=/usr/local/bin
LOCAL_BIN=
URL=
SHA256=
WEAK_HTTPS=0
MATERIALS=
CONFIG=
RELEASE_ID=
SERVICE=none
START=0
DRY_RUN=0

# Exact node-material file names produced by `boreas pki issue-node`, plus the
# `peer.signed` object added by peer exchange. Anything else is refused.
MATERIAL_ALLOW='identity.pem identity.key identity.ed25519.key identity-ca.pem outer.pem outer.key outer-ca.pem issuer.key-id issuer.generation issuer.ed25519.der issuer.mldsa.der local.signed peer.signed status.signed roots.cbor'
# CA/authority private keys created by `boreas pki init-ca`. These names are the
# real ones (see crates/boreas-pki/src/provisioning.rs); they must never travel
# to a node.
CA_DENY='root.ed25519.key root.mldsa65.key ia.ed25519.key ia.mldsa65.key status.ed25519.key status.mldsa65.key outer-ca.key'

usage() {
  cat <<'EOF'
Usage: install.sh (--binary FILE | --url HTTPS_URL) --sha256 HEX64
       --release ID --materials DIR --config FILE [options]
Options:
  --prefix DIR                 installation root (default /opt/boreas)
  --bindir DIR                 existing directory for the `boreas`/`boreas-easy`
                               symlinks (default /usr/local/bin)
  --accept-weak-https          acknowledge that a --url digest is not independent
  --service none|systemd|procd install service template (default none)
  --start                      explicitly enable and (re)start selected service
  --dry-run                    inspect local inputs and print the plan; no writes
                               and no candidate execution

Requirements and limits:
  * --sha256 must be exactly 64 hexadecimal characters and must be obtained
    through a channel other than the binary download itself.
  * --release must match [A-Za-z0-9][A-Za-z0-9._+-]{0,127}; "." and ".." are
    refused because the id is used as a directory name.
  * --prefix/--bindir must be absolute, must not be a system directory, must not
    contain or traverse symbolic links, must be owned by root and must not be
    group/other writable. Target /opt/boreas or another dedicated directory.
  * --materials must be a flat directory of regular files whose names are the
    exact node-material names. CA/authority private keys, symlinks, sub-
    directories, devices and FIFOs are refused.
  * The config is canonicalized with `boreas config-migrate` and installed as
    release `config.toml` (mode 0600). The staged source copy is discarded.
  * Re-running with the same --release is accepted only when the whole bundle
    (binary, canonical config and every material file) is byte-identical.
  * A failed run after the active pointer moved rolls the pointer back to the
    previously active release.
EOF
}

fail() { printf '%s\n' "install: error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) [ "$#" -ge 2 ] || fail '--binary needs a path'; LOCAL_BIN=$2; shift 2 ;;
    --url) [ "$#" -ge 2 ] || fail '--url needs an HTTPS URL'; URL=$2; shift 2 ;;
    --sha256) [ "$#" -ge 2 ] || fail '--sha256 needs a digest'; SHA256=$2; shift 2 ;;
    --release) [ "$#" -ge 2 ] || fail '--release needs an id'; RELEASE_ID=$2; shift 2 ;;
    --materials) [ "$#" -ge 2 ] || fail '--materials needs a directory'; MATERIALS=$2; shift 2 ;;
    --config) [ "$#" -ge 2 ] || fail '--config needs a file'; CONFIG=$2; shift 2 ;;
    --prefix) [ "$#" -ge 2 ] || fail '--prefix needs a path'; PREFIX=$2; shift 2 ;;
    --bindir) [ "$#" -ge 2 ] || fail '--bindir needs a path'; BINDIR=$2; shift 2 ;;
    --accept-weak-https) WEAK_HTTPS=1; shift ;;
    --service) [ "$#" -ge 2 ] || fail '--service needs none, systemd or procd'; SERVICE=$2; shift 2 ;;
    --start) START=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

[ -n "$SHA256" ] || fail 'explicit --sha256 is required'
case "$SHA256" in *[!0123456789abcdefABCDEF]*|'') fail '--sha256 must be exactly 64 hexadecimal characters' ;; esac
[ "${#SHA256}" -eq 64 ] || fail '--sha256 must be exactly 64 hexadecimal characters'

[ -n "$RELEASE_ID" ] || fail '--release is required'
[ "${#RELEASE_ID}" -le 128 ] || fail '--release is longer than 128 characters'
case "$RELEASE_ID" in
  .|..) fail '--release must not be "." or ".."' ;;
  [A-Za-z0-9]*) : ;;
  *) fail '--release must start with an alphanumeric character' ;;
esac
case "$RELEASE_ID" in *[!A-Za-z0-9._+-]*) fail '--release contains unsafe characters' ;; esac

[ -n "$MATERIALS" ] || fail '--materials must name an existing local directory'
[ -d "$MATERIALS" ] || fail '--materials must name an existing local directory'
[ -n "$CONFIG" ] || fail '--config must name an existing local file'
[ -f "$CONFIG" ] || fail '--config must name an existing local file'

case "$SERVICE" in none|systemd|procd) ;; *) fail '--service must be none, systemd or procd' ;; esac
[ "$START" -eq 0 ] || [ "$SERVICE" != none ] || fail '--start requires --service systemd or procd'
if [ -n "$LOCAL_BIN" ] && [ -n "$URL" ]; then fail 'choose --binary or --url, not both'; fi
if [ -z "$LOCAL_BIN" ] && [ -z "$URL" ]; then fail 'exactly one of --binary or --url is required'; fi
if [ -n "$URL" ]; then
  case "$URL" in https://*) ;; *) fail '--url must use HTTPS' ;; esac
  [ "$WEAK_HTTPS" -eq 1 ] || fail 'HTTPS URL plus a same-origin digest is not independent trust; pass --accept-weak-https to acknowledge that the digest must come from elsewhere'
fi

# Absolute, non-system, traversal-free path. Used for --prefix and --bindir.
validate_path_string() { # $1=option name, $2=value
  case "$2" in /*) ;; *) fail "$1 must be an absolute path" ;; esac
  case "$2" in /) fail "$1 must not be the filesystem root" ;; esac
  case "$2" in *[!A-Za-z0-9._/+-]*) fail "$1 contains unsafe characters" ;; esac
  case "$2/" in *'/../'*|*'/./'*|*'//'*) fail "$1 contains empty or traversal components" ;; esac
  [ "${#2}" -le 200 ] || fail "$1 is longer than 200 characters"
  case "$2" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib32|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/usr/local|/var)
      fail "$1 must not be a top-level system directory" ;;
    /usr/bin|/usr/sbin|/usr/lib|/usr/lib32|/usr/lib64|/usr/libexec|/usr/share|/usr/include|/usr/src|/var/log|/var/run)
      fail "$1 must not be a system directory" ;;
    /bin/*|/boot/*|/dev/*|/etc/*|/lib/*|/proc/*|/sbin/*|/sys/*|/run/*|/root/*|/var/log/*|/var/run/*)
      fail "$1 must not be inside a system directory" ;;
    /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib32/*|/usr/lib64/*|/usr/libexec/*|/usr/share/*|/usr/include/*|/usr/src/*)
      fail "$1 must not be inside a system directory" ;;
  esac
  return 0
}

strip_trailing_slashes() { # $1=path -> prints the path without trailing slashes
  case "$1" in
    /) printf '%s' /; return 0 ;;
  esac
  _sts=$1
  while [ "${_sts%/}" != "$_sts" ]; do _sts=${_sts%/}; done
  printf '%s' "$_sts"
}

PREFIX=$(strip_trailing_slashes "$PREFIX")
BINDIR=$(strip_trailing_slashes "$BINDIR")
validate_path_string --prefix "$PREFIX"
validate_path_string --bindir "$BINDIR"
[ "$BINDIR" != "$PREFIX" ] || fail '--bindir must differ from --prefix'

# Read-only structural check. Runs in --dry-run too, so unsafe inputs are caught
# before anything is written.
check_root_dir() { # $1=option name, $2=directory
  _cr_path=$2
  while :; do
    if [ -e "$_cr_path" ] || [ -L "$_cr_path" ]; then
      [ ! -L "$_cr_path" ] || fail "$1 must not be a symbolic link: $_cr_path"
      [ -d "$_cr_path" ] || fail "$1 is not a directory: $_cr_path"
      _cr_resolved=$(readlink -f -- "$_cr_path") || fail "cannot resolve $1: $_cr_path"
      [ "$_cr_resolved" = "$_cr_path" ] || fail "$1 traverses a symbolic link: $_cr_path"
      _cr_state=$(stat -c '%u %a' -- "$_cr_path") || fail "cannot stat $1: $_cr_path"
      [ "${_cr_state%% *}" = 0 ] || fail "$1 must be owned by root (uid 0): $_cr_path"
      [ $(( 0${_cr_state##* } & 0022 )) -eq 0 ] || fail "$1 must not be group/other writable: $_cr_path"
    fi
    [ "$_cr_path" != / ] || break
    _cr_path=${_cr_path%/*}
    [ -n "$_cr_path" ] || _cr_path=/
  done
  return 0
}

# Materials: flat directory of regular files with exact node-material names.
check_materials() { # $1=option name, $2=directory
  [ -d "$2" ] || fail "$1 must name a directory"
  [ ! -L "$2" ] || fail "$1 must not be a symbolic link"
  base=${2%/}
  [ -n "$base" ] || base=/
  [ "${base##*/}" != ca ] || fail "refusing to copy a CA directory as node materials: $2"
  special=$(find "$2" '!' -type f '!' -type d -print 2>/dev/null | sed -n '1p')
  [ -z "$special" ] || fail "materials must contain only regular files and directories; found $special"
  subdir=$(find "$2" -mindepth 1 -type d -print 2>/dev/null | sed -n '1p')
  [ -z "$subdir" ] || fail "materials must be a flat directory; found subdirectory $subdir"
  [ -n "$(find "$2" -mindepth 1 -maxdepth 1 -type f -print 2>/dev/null | sed -n '1p')" ] || fail "$1 is empty: no node materials found"
  # -exec passes whole names (including dotfiles/newlines), never line-splits.
  find "$2" -mindepth 1 -maxdepth 1 -type f -exec sh -c '
    allow=$1; deny=$2; shift 2
    for path do
      name=${path##*/}
      case "$name" in *[!A-Za-z0-9._-]*) echo "install: error: unexpected material file $name (unsafe filename)" >&2; exit 1 ;; esac
      case " $deny " in *" $name "*) echo "install: error: refusing CA/authority private-key material: $name" >&2; exit 1 ;; esac
      case " $allow " in *" $name "*) ;; *) echo "install: error: unexpected material file $name (not a node material name)" >&2; exit 1 ;; esac
    done
  ' sh "$MATERIAL_ALLOW" "$CA_DENY" {} + || fail 'material file allowlist validation failed'
  return 0
}

# Static-ELF policy, shared by --dry-run and the real install so both paths are
# covered by the same tests.
check_static_elf() { # $1=path
  elf_header=$(readelf -h "$1") || fail 'readelf -h failed (not an ELF object?)'
  elf_programs=$(readelf -l "$1") || fail 'readelf -l failed'
  # binutils releases disagree on the exit status for a static object with no
  # .dynamic section: some print a note and exit 0, some exit non-zero. Accept
  # both, but only when the message says there is no dynamic section.
  elf_dynamic=
  dyn_status=0
  elf_dynamic=$(readelf -d "$1" 2>&1) || dyn_status=$?
  if [ "$dyn_status" -ne 0 ]; then
    case "$elf_dynamic" in
      *'no dynamic section'*|*'No dynamic section'*) elf_dynamic='' ;;
      *) fail "readelf -d failed: $elf_dynamic" ;;
    esac
  fi
  printf '%s\n' "$elf_header" | grep -q 'ELF64' || fail 'ELF must be a 64-bit object'
  machine=$(printf '%s\n' "$elf_header" | sed -n '/Machine:/{s/.*Machine:[[:space:]]*//;p;q;}')
  [ -n "$machine" ] || fail 'readelf -h produced no Machine field'
  case "$machine" in
    'Advanced Micro Devices X86-64') want_arch=x86_64 ;;
    'AArch64') want_arch=aarch64 ;;
    'RISC-V') want_arch=riscv64 ;;
    *) fail "unsupported ELF machine: $machine" ;;
  esac
  [ "$want_arch" = "$(uname -m)" ] || fail "binary architecture $want_arch does not match this host ($(uname -m))"
  printf '%s\n' "$elf_programs" | grep -q 'INTERP' && fail 'ELF has an INTERP program header'
  printf '%s\n' "$elf_programs" | grep -qi 'Requesting program interpreter' && fail 'ELF requests an interpreter'
  printf '%s\n' "$elf_dynamic" | grep -q '(NEEDED)' && fail 'ELF has DT_NEEDED dependencies'
  return 0
}

hash_of() { # $1=file
  line=$(sha256sum -- "$1") || fail "sha256sum failed for $1"
  printf '%s' "${line%% *}"
}

require_env_file() {
  env_dir=/etc/boreas
  env_file=$env_dir/boreas.env
  [ ! -L "$env_dir" ] || fail "$env_dir must not be a symbolic link"
  [ -d "$env_dir" ] || fail "create $env_dir (mode 0700, owner root) before --start"
  [ -f "$env_file" ] || fail "create $env_file (mode 0600, owner root) before --start"
  [ ! -L "$env_file" ] || fail "$env_file must be a regular file, not a symbolic link"
  state=$(stat -c '%u %a' -- "$env_file") || fail "cannot stat $env_file"
  [ "${state%% *}" = 0 ] || fail "$env_file must be owned by root"
  [ "${state##* }" = 600 ] || fail "$env_file must have mode 0600"
  return 0
}

# ---------------------------------------------------------------------------
# Dry run: read-only inspection, no candidate execution, no writes
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" -eq 1 ]; then
  need sha256sum
  need readelf
  need stat
  need readlink
  need find
  need sed
  need grep
  need tr
  need uname
  [ -n "$LOCAL_BIN" ] || fail '--dry-run requires --binary FILE (the network is never used in a dry run)'
  [ ! -L "$LOCAL_BIN" ] || fail '--binary must not be a symbolic link'
  [ -f "$LOCAL_BIN" ] || fail 'local binary does not exist'
  [ ! -L "$CONFIG" ] || fail '--config must not be a symbolic link'
  check_root_dir --prefix "$PREFIX"
  for sub in releases bin state; do check_root_dir "install subdirectory" "$PREFIX/$sub"; done
  check_root_dir --bindir "$BINDIR"
  check_materials --materials "$MATERIALS"
  [ "$(hash_of "$LOCAL_BIN")" = "$(printf '%s' "$SHA256" | tr 'A-F' 'a-f')" ] || fail 'SHA-256 mismatch'
  check_static_elf "$LOCAL_BIN"
  printf '%s\n' "DRY RUN: SHA-256, static-ELF, architecture, path and material checks passed for $LOCAL_BIN"
  printf '%s\n' "DRY RUN: would install release $RELEASE_ID under $PREFIX, canonicalize the config with config-migrate, copy materials, run doctor/config-check/verify-bundle, write a bundle manifest and atomically move the active pointer."
  [ "$SERVICE" = none ] || printf '%s\n' "DRY RUN: would render and install the $SERVICE template; would start only if --start was supplied."
  printf '%s\n' 'DRY RUN: no candidate binary, service manager or filesystem write was performed.'
  exit 0
fi

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || fail 'installation requires root (use sudo)'
need mkdir; need chmod; need cp; need mv; need ln; need rm; need mktemp
need readelf; need grep; need tr; need cmp; need sed; need find; need sort
need sha256sum; need stat; need readlink; need uname; need id; need dirname; need awk
[ ! -L "$CONFIG" ] || fail '--config must not be a symbolic link'
[ ! -L "$LOCAL_BIN" ] || fail '--binary must not be a symbolic link'
check_materials --materials "$MATERIALS"
[ -d "$BINDIR" ] || fail "--bindir must already exist: $BINDIR"
check_root_dir --bindir "$BINDIR"

if [ -n "$URL" ]; then
  if command -v curl >/dev/null 2>&1; then FETCH_TOOL=curl
  elif command -v wget >/dev/null 2>&1; then FETCH_TOOL=wget
  else fail 'required command not found: curl or wget'; fi
  printf '%s\n' 'install: WARNING: the --url digest is only an integrity check against whatever that origin served; it is not provenance. Verify the digest through a separate channel.' >&2
fi
case "$SERVICE" in
  systemd) need systemctl ;;
  procd) [ -r /etc/rc.common ] || fail 'required OpenWrt procd file not found: /etc/rc.common' ;;
esac
if [ "$START" -eq 1 ]; then require_env_file; fi

# Prefix must be root-owned, non-symlink, mode 0700 *before* anything is written
# into it, so a pre-planted entry cannot redirect a root write.
check_root_dir --prefix "$PREFIX"
mkdir -p -- "$PREFIX" || fail "cannot create install root: $PREFIX"
check_root_dir --prefix "$PREFIX"
chmod 0700 -- "$PREFIX" || fail "cannot restrict $PREFIX to 0700"
for sub in releases bin state; do
  check_root_dir "install subdirectory" "$PREFIX/$sub"
  mkdir -p -- "$PREFIX/$sub" || fail "cannot create $PREFIX/$sub"
  check_root_dir "install subdirectory" "$PREFIX/$sub"
  chmod 0700 -- "$PREFIX/$sub"
done

FINAL=$PREFIX/releases/$RELEASE_ID
STAGE=$(mktemp -d "$PREFIX/.stage.XXXXXX") || fail 'cannot create same-filesystem staging directory'
COMMITTED=0
OLD_ACTIVE=
cleanup() { [ -z "${STAGE:-}" ] || rm -rf -- "$STAGE"; }
restore_active() {
  [ "$COMMITTED" -eq 1 ] || return 0
  if [ -n "$OLD_ACTIVE" ]; then
    rollback_tmp=$(mktemp "$PREFIX/.rollback.XXXXXX") || return 0
    printf '%s\n' "$OLD_ACTIVE" > "$rollback_tmp" || return 0
    chmod 0600 -- "$rollback_tmp" || return 0
    mv -f -- "$rollback_tmp" "$PREFIX/active" || return 0
    printf '%s\n' "install: rolled the active release pointer back to $OLD_ACTIVE" >&2
  else
    rm -f -- "$PREFIX/active"
    printf '%s\n' 'install: removed the active release pointer (no previous release)' >&2
  fi
  return 0
}
on_exit() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then restore_active; fi
  cleanup
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 129' HUP
trap 'exit 143' TERM

CANDIDATE=$STAGE/boreas
if [ -n "$LOCAL_BIN" ]; then
  [ -f "$LOCAL_BIN" ] || fail 'local binary does not exist'
  cp -- "$LOCAL_BIN" "$CANDIDATE" || fail 'cannot stage local binary'
else
  case "$FETCH_TOOL" in
    curl) curl --fail --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
            --tlsv1.2 --output "$CANDIDATE" "$URL" || fail 'HTTPS download failed' ;;
    wget) wget --https-only -O "$CANDIDATE" "$URL" || fail 'HTTPS download failed' ;;
  esac
fi
chmod 0755 -- "$CANDIDATE"
# Hash first, then ELF policy; nothing is executed before both pass.
[ "$(hash_of "$CANDIDATE")" = "$(printf '%s' "$SHA256" | tr 'A-F' 'a-f')" ] || fail 'SHA-256 mismatch'
check_static_elf "$CANDIDATE"

cp -R -- "$MATERIALS" "$STAGE/materials" || fail 'cannot stage local materials'
check_materials --materials "$STAGE/materials" || fail 'staged materials failed validation'
find "$STAGE/materials" -mindepth 1 -type d -exec chmod 0700 {} + || fail 'cannot restrict material directories'
find "$STAGE/materials" -mindepth 1 -type f -exec chmod 0600 {} + || fail 'cannot restrict material files'

cp -- "$CONFIG" "$STAGE/config.source.toml" || fail 'cannot stage config'
chmod 0600 -- "$STAGE/config.source.toml"
# Canonical config only: `config-migrate` prints version = 2 and never edits the
# source file, so the release carries exactly one reviewed document.
"$CANDIDATE" config-migrate "$STAGE/config.source.toml" > "$STAGE/config.canonical.toml" || fail 'candidate config-migrate failed'
awk -v final="$FINAL" -v prefix="$PREFIX" -f "$SELF_DIR/relocate-config.awk" \
  "$STAGE/config.canonical.toml" > "$STAGE/config.toml" || fail 'unsupported canonical [paths] layout; refusing unsafe relocation'
rm -f -- "$STAGE/config.canonical.toml"
chmod 0600 -- "$STAGE/config.toml"
[ -s "$STAGE/config.toml" ] || fail 'canonical config is empty'
rm -f -- "$STAGE/config.source.toml"

# Only after hash, ELF and canonical-config checks may the candidate be executed.
"$CANDIDATE" doctor >/dev/null || fail 'candidate doctor failed'
"$CANDIDATE" config-check "$STAGE/config.toml" >/dev/null || fail 'candidate config-check failed'
"$CANDIDATE" pki verify-bundle --material-dir "$STAGE/materials" --require-peer >/dev/null || fail 'candidate verify-bundle failed'

# Deterministic bundle manifest: binary, canonical config and every material
# file. Re-entry is accepted only when all three are byte-identical.
bundle_manifest() { # $1=directory containing boreas, config.toml and materials/
  ( cd "$1" || exit 1
    sha256sum -- boreas || exit 1
    sha256sum -- config.toml || exit 1
    find materials -type f -print | LC_ALL=C sort | while IFS= read -r rel; do
      sha256sum -- "$rel" || exit 1
    done
  )
}
bundle_manifest "$STAGE" > "$STAGE/bundle.sha256" || fail 'cannot compute bundle manifest'
chmod 0600 -- "$STAGE/bundle.sha256"

FINAL=$PREFIX/releases/$RELEASE_ID
if [ -e "$FINAL" ] || [ -L "$FINAL" ]; then
  if [ ! -d "$FINAL" ] || [ -L "$FINAL" ]; then
    fail "release path exists but is not a plain directory: $FINAL"
  fi
  [ -f "$FINAL/bundle.sha256" ] || fail "existing release $RELEASE_ID has no bundle manifest; install it under a new --release"
  cmp -s -- "$STAGE/bundle.sha256" "$FINAL/bundle.sha256" || fail "release $RELEASE_ID already exists with a different bundle (binary, canonical config or materials differ); use a new --release"
else
  mv -- "$STAGE" "$FINAL" || fail 'same-filesystem release promotion failed'
  STAGE=
fi
chmod 0700 -- "$FINAL"
chmod 0600 -- "$FINAL/config.toml"

# Stable dispatcher with the real prefix baked in: the runtime path is not
# operator-overridable, so an injected BOREAS_PREFIX cannot redirect a root exec.
render() { # $1=template, $2=destination, $3=mode
  sed -e "s|@@PREFIX@@|$PREFIX|g" -- "$1" > "$2" || fail "cannot render $1"
  chmod "$3" -- "$2"
}
tmp_dispatch=$(mktemp "$PREFIX/.dispatch.XXXXXX") || fail 'cannot create dispatcher temporary file'
cat > "$tmp_dispatch" <<'DISPATCH'
#!/bin/sh
set -eu
PREFIX=@@PREFIX@@
case "$PREFIX" in *'@'*) echo 'dispatcher was not rendered by install.sh' >&2; exit 1 ;; esac
[ -f "$PREFIX/active" ] || { echo 'active release pointer missing' >&2; exit 1; }
IFS= read -r ACTIVE < "$PREFIX/active" || { echo 'cannot read active release pointer' >&2; exit 1; }
case "$ACTIVE" in ''|.|..|*[!A-Za-z0-9._+-]*) echo 'unsafe active release pointer' >&2; exit 1 ;; esac
BIN=$PREFIX/releases/$ACTIVE/boreas
[ -x "$BIN" ] || { echo "active release is not executable: $BIN" >&2; exit 1; }
case "${0##*/}" in
  boreas-easy)
    case "${1-}" in ''|-*) set -- console "$@" ;; esac
    ;;
esac
exec "$BIN" "$@"
DISPATCH
sed -e "s|@@PREFIX@@|$PREFIX|g" -- "$tmp_dispatch" > "$PREFIX/.dispatch.rendered" || fail 'cannot render dispatcher'
chmod 0755 -- "$PREFIX/.dispatch.rendered"
mv -f -- "$PREFIX/.dispatch.rendered" "$PREFIX/boreas-dispatch" || fail 'cannot install dispatcher'
rm -f -- "$tmp_dispatch"

for name in boreas boreas-easy; do
  link_tmp=$(mktemp "$BINDIR/.boreas-link.XXXXXX") || fail "cannot create a temporary link in $BINDIR"
  rm -f -- "$link_tmp"
  ln -s "$PREFIX/boreas-dispatch" "$link_tmp" || fail 'cannot create dispatcher symlink'
  mv -f -- "$link_tmp" "$BINDIR/$name" || fail "cannot install $BINDIR/$name"
done

# Service wrapper carries the same baked prefix.
tmp_run=$(mktemp "$PREFIX/.run.XXXXXX") || fail 'cannot create wrapper temporary file'
render "$SELF_DIR/boreas-run" "$tmp_run" 0755
mv -f -- "$tmp_run" "$PREFIX/boreas-run" || fail 'cannot install service wrapper'

case "$SERVICE" in
  systemd)
    mkdir -p -- /etc/systemd/system
    tmp_unit=$(mktemp /etc/systemd/system/.boreas.service.XXXXXX) || fail 'cannot create unit temporary file'
    render "$SELF_DIR/boreas.service" "$tmp_unit" 0644
    mv -f -- "$tmp_unit" /etc/systemd/system/boreas.service || fail 'cannot install systemd unit'
    ;;
  procd)
    mkdir -p -- /etc/init.d
    tmp_init=$(mktemp /etc/init.d/.boreas.XXXXXX) || fail 'cannot create init script temporary file'
    render "$SELF_DIR/boreas.openwrt" "$tmp_init" 0755
    mv -f -- "$tmp_init" /etc/init.d/boreas || fail 'cannot install procd init script'
    ;;
esac

# Commit the pointer only after every validated artefact and the service
# template exist; any later failure restores the previous pointer.
if [ -f "$PREFIX/active" ]; then OLD_ACTIVE=$(sed -n '1p' "$PREFIX/active"); fi
active_tmp=$(mktemp "$PREFIX/.active.XXXXXX") || fail 'cannot create active pointer temporary file'
printf '%s\n' "$RELEASE_ID" > "$active_tmp" || fail 'cannot write active pointer'
chmod 0600 -- "$active_tmp"
mv -f -- "$active_tmp" "$PREFIX/active" || fail 'cannot move active pointer into place'
COMMITTED=1

if [ "$START" -eq 1 ]; then
  case "$SERVICE" in
    systemd)
      systemctl daemon-reload || fail 'systemctl daemon-reload failed'
      systemctl enable boreas.service || fail 'systemctl enable failed'
      systemctl restart boreas.service || fail 'systemctl restart failed (the pointer was rolled back)'
      ;;
    procd)
      /etc/init.d/boreas enable || fail 'procd enable failed'
      /etc/init.d/boreas restart || fail 'procd restart failed (the pointer was rolled back)'
      ;;
  esac
fi
COMMITTED=0

start_note='not requested'
if [ "$START" -eq 1 ]; then start_note=requested; fi
printf '%s\n' "Installed verified release $RELEASE_ID under $PREFIX."
printf '%s\n' "Previous releases were retained; the active pointer is $PREFIX/active. Service start: $start_note."
if [ -n "$URL" ]; then
  printf '%s\n' 'WARNING: this install used an HTTPS URL; the digest was only an integrity check, not provenance.' >&2
fi
