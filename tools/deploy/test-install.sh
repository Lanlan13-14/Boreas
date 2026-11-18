#!/bin/sh
# Actions-only regression harness for tools/deploy/**. Do not run on a real host:
# it fabricates root tooling (id/stat/readelf/sha256sum/systemctl/ip) inside a
# throw-away directory and never touches /etc, /opt or the network.
#
# It is deliberately *not* proof that a real deployment works: see
# docs/deployment/ONE_CLICK.md section 5 for what still needs a real device.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
DEPLOY=$ROOT/tools/deploy
INSTALL=$DEPLOY/install.sh
WRAPPER=$DEPLOY/boreas-run
UNIT=$DEPLOY/boreas.service
PROCD=$DEPLOY/boreas.openwrt

[ "$(id -u)" -ne 0 ] || { echo 'refusing to run as root' >&2; exit 1; }
[ ! -e /etc/boreas/boreas.env ] || { echo 'refusing: /etc/boreas/boreas.env exists on this host' >&2; exit 1; }
[ ! -e /etc/systemd/system/boreas.service ] || { echo 'refusing: a real boreas unit exists' >&2; exit 1; }

T=$(mktemp -d "${TMPDIR:-/tmp}/boreas-deploy-test.XXXXXX")
trap 'rm -rf "$T"' EXIT HUP INT TERM
T=$(CDPATH='' cd -- "$T" && pwd -P)
FAKE=$T/fake
mkdir -p "$FAKE" "$T/bindir"
REAL_SHA=$(command -v sha256sum) || { echo 'sha256sum is required for the harness' >&2; exit 1; }
REAL_STAT=$(command -v stat) || { echo 'stat is required for the harness' >&2; exit 1; }
for tool in mktemp find sed grep cut sort cmp mkfifo uname; do
  command -v "$tool" >/dev/null 2>&1 || { echo "the harness needs $tool" >&2; exit 1; }
done

GOOD=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BAD=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
CAND_LOG=$T/candidate.log
HASH_LOG=$T/hash.log
SYSTEM_LOG=$T/system.log
: > "$CAND_LOG"
: > "$HASH_LOG"
: > "$SYSTEM_LOG"
# Exported so the fake candidate keeps logging when it is reached through the
# installed dispatcher rather than through `invoke`.
export TEST_CAND_LOG="$CAND_LOG"
passed=0

pass() { passed=$((passed + 1)); printf 'ok - %s\n' "$*"; }
bail() { printf 'FAIL - %s\n' "$*" >&2; exit 1; }
dump() { sed -n '1,20p' "$T/err" >&2; }

expect_fail_msg() { # desc, message-substring, command...
  desc=$1
  pattern=$2
  shift 2
  if "$@" > "$T/out" 2> "$T/err"; then
    printf 'FAIL - %s: unexpectedly succeeded\n' "$desc" >&2
    exit 1
  fi
  grep -q -- "$pattern" "$T/err" || {
    printf 'FAIL - %s: stderr lacks %s\n' "$desc" "$pattern" >&2
    dump
    exit 1
  }
  pass "$desc"
}

expect_ok() { # desc, command...
  desc=$1
  shift
  if ! "$@" > "$T/out" 2> "$T/err"; then
    printf 'FAIL - %s: exited non-zero\n' "$desc" >&2
    dump
    exit 1
  fi
  pass "$desc"
}

assert_file() { [ -f "$1" ] || bail "expected file missing: $1"; pass "exists: $1"; }
assert_symlink() { [ -L "$1" ] || bail "expected symlink missing: $1"; pass "symlink: $1"; }
assert_mode() {
  actual=$($REAL_STAT -c '%a' -- "$1")
  [ "$actual" = "$2" ] || bail "mode of $1 is $actual, expected $2"
  pass "mode $2: $1"
}
assert_absent() { [ ! -e "$1" ] || bail "unexpectedly present: $1"; pass "absent: $1"; }
assert_contains() {
  grep -q -- "$2" "$1" || bail "$1 lacks '$2'"
  pass "'$2' in $1"
}
assert_not_contains() {
  if grep -q -- "$2" "$1"; then bail "$1 unexpectedly contains '$2'"; fi
  pass "no '$2' in $1"
}

# ---------------------------------------------------------------------------
# Fake toolchain
# ---------------------------------------------------------------------------

cat > "$FAKE/id" <<'EOF'
#!/bin/sh
printf '%s\n' 0
EOF

cat > "$FAKE/stat" <<'EOF'
#!/bin/sh
# Model a safe root-owned hierarchy without inheriting the runner's uid or
# writable /tmp mode. Targeted fault injection must affect only that path;
# otherwise --bindir or an unrelated ancestor can mask the intended failure.
# `-c %h` is real: hard-link detection must be proven on a real hard link, not
# a constant. TEST_FAKE_LINKS can still force a value for a pure-fault case.
fmt=
target=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -c) fmt=$2; shift 2 ;;
    --) shift ;;
    *) target=$1; shift ;;
  esac
done
[ -n "$target" ] || { echo 'fake stat: no path' >&2; exit 2; }
if [ "$fmt" = '%h' ]; then
  if [ -n "${TEST_FAKE_LINKS:-}" ]; then printf '%s\n' "$TEST_FAKE_LINKS"; exit 0; fi
  exec "${TEST_REAL_STAT:?}" -c '%h' -- "$target"
fi
if [ -n "${TEST_MODE_PATH:-}" ] && [ "$target" = "$TEST_MODE_PATH" ]; then
  printf '0 %s\n' "${TEST_MODE_VALUE:-644}"
  exit 0
fi
if [ -n "${TEST_OWNER_PATH:-}" ] && [ "$target" = "$TEST_OWNER_PATH" ]; then
  printf '%s 700\n' "${TEST_OWNER_UID_VALUE:-1000}"
  exit 0
fi
if [ -n "${TEST_STAT_PATH:-}" ] && [ "$target" != "$TEST_STAT_PATH" ]; then
  printf '0 700\n'
else
  printf '%s %s\n' "${TEST_FAKE_UID:-0}" "${TEST_FAKE_MODE:-700}"
fi
EOF

cat > "$FAKE/sha256sum" <<'EOF'
#!/bin/sh
# Constant digest for the binary fixtures (so a mismatch case is expressible),
# real hashing for config/materials (so bundle-manifest comparisons stay
# content-sensitive). It fails loudly on a non-file, which is how "the installer
# hashed the wrong thing" would surface.
target=
for arg in "$@"; do
  [ "$arg" = "--" ] && continue
  target=$arg
done
[ -n "$target" ] || { echo 'fake sha256sum: no argument' >&2; exit 1; }
[ -f "$target" ] || { echo "fake sha256sum: not a file: $target" >&2; exit 1; }
printf '%s\n' "$*" >> "${TEST_HASH_LOG:?}"
case "${target##*/}" in
  boreas|boreas-src)
    if [ -n "${TEST_HASH_CONST:-}" ]; then
      printf '%s  %s\n' "$TEST_HASH_CONST" "$target"
      exit 0
    fi
    ;;
esac
exec "${TEST_REAL_SHA:?}" "$@"
EOF

cat > "$FAKE/readelf" <<'EOF'
#!/bin/sh
mode=${TEST_ELF_MODE:-static}
case "$1" in
  -h)
    case "$mode" in
      # Always a machine that differs from the runner's own architecture.
      arch)
        if [ "$TEST_ELF_MACHINE" = 'AArch64' ]; then
          machine='Advanced Micro Devices X86-64'
        else
          machine='AArch64'
        fi
        ;;
      *) machine=${TEST_ELF_MACHINE:?} ;;
    esac
    printf '%s\n' 'ELF Header:' '  Class:                             ELF64' \
      "  Machine:                           $machine"
    ;;
  -l)
    case "$mode" in
      interp_header) printf '%s\n' 'Program Headers:' '  INTERP         0x000318 0x000318' ;;
      interp_request) printf '%s\n' 'Program Headers:' '      [Requesting program interpreter: /lib/ld-musl-x86_64.so.1]' ;;
      *) printf '%s\n' 'Program Headers:' '  LOAD           0x000000 0x000000' ;;
    esac
    ;;
  -d)
    case "$mode" in
      needed) printf '%s\n' 'Dynamic section at offset 0x1000 contains 1 entries:' \
        ' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]' ;;
      *) printf '%s\n' 'There is no dynamic section in this file.' ;;
    esac
    ;;
  *) echo 'fake readelf: unsupported option' >&2; exit 2 ;;
esac
EOF

cat > "$FAKE/systemctl" <<'EOF'
#!/bin/sh
printf 'systemctl %s\n' "$*" >> "${TEST_SYSTEM_LOG:?}"
exit 0
EOF

cat > "$FAKE/ip" <<'EOF'
#!/bin/sh
# Fake iproute2. Every call is logged so ownership and ordering can be asserted.
# `link show` returns "absent" for the first call (the wrapper's pre-flight
# check) and "present" afterwards, which models the daemon creating the device
# without a scheduling race.
printf '%s\n' "$*" >> "${TEST_IP_LOG:?}"
mode=${TEST_IP_MODE:-free}
count=${TEST_IP_COUNT:?}
if [ "$1" = "-4" ] && [ "$2" = "-o" ] && [ "$3" = "addr" ]; then
  case "$mode" in
    local_vip) echo '2: eth0    inet 10.20.1.1/32 scope global eth0' ;;
    local_peer) echo '2: eth0    inet 10.20.1.2/32 scope global eth0' ;;
  esac
  exit 0
fi
if [ "$1" = "-4" ] && [ "$2" = "route" ] && [ "$3" = "show" ]; then
  case "$mode" in
    route_exists) echo '10.20.1.2/32 dev eth0 scope link' ;;
  esac
  exit 0
fi
if [ "$1" = "link" ] && [ "$2" = "show" ]; then
  case "$mode" in
    tun_exists) exit 0 ;;
    *)
      n=0
      if [ -f "$count" ]; then
        IFS= read -r n < "$count"
      fi
      n=$((n + 1))
      printf '%s\n' "$n" > "$count"
      [ "$n" -ge 2 ] && exit 0
      exit 1
      ;;
  esac
fi
case "$1 $2" in
  'link set') exit 0 ;;
  'addr add') exit 0 ;;
  'addr del') exit 0 ;;
  'route add') [ "$mode" = add_fails ] && exit 2; exit 0 ;;
  'route del') exit 0 ;;
esac
exit 0
EOF

cat > "$FAKE/sleep" <<'EOF'
#!/bin/sh
# Never sleep: the ready/stop loops are bounded by iteration counts.
exit 0
EOF

chmod 0755 "$FAKE"/*

case "$(uname -m)" in
  x86_64) ELF_MACHINE='Advanced Micro Devices X86-64' ;;
  aarch64) ELF_MACHINE='AArch64' ;;
  *) echo "unsupported test runner architecture: $(uname -m)" >&2; exit 1 ;;
esac

CAND=$T/fake-candidate
cat > "$CAND" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${TEST_CAND_LOG:?}"
case "$1" in
  # The canonical output depends on the input so a changed source config is
  # observable in the bundle manifest, exactly like the real config-migrate.
  config-migrate)
    printf '%s\n' '# canonical' 'version = 2' '[node]' \
      'net_id = "0123456789abcdef0123456789abcdef"'
    sed '/^version = /d; /^net_id = /d' "$2"
    printf '%s\n' '[paths]' 'identity_key = "/source/identity.key"' \
      'roots = ["/source/roots.cbor", "/another/root.cbor"]' 'state_dir = "/source/state"'
    case "${TEST_CANON_MODE:-good}" in
      extra) printf '%s\n' 'unexpected = "unsafe"' ;;
      duplicate) printf '%s\n' '[paths]' ;;
      malformed) printf '%s\n' 'state_dir = "unterminated' ;;
    esac
    printf '\n%s\n%s\n' '[uplink]' 'primary = "wan"'
    ;;
  config-check) [ -f "$2" ] || { echo 'fake config-check: missing file' >&2; exit 3; } ;;
  *) exit 0 ;;
esac
exit 0
EOF
chmod 0755 "$CAND"

# invoke <install.sh args...> with the fake root toolchain in front of PATH.
invoke() {
  PATH="$FAKE:$PATH" \
  TEST_FAKE_UID=${FAKE_UID:-0} TEST_FAKE_MODE=${FAKE_MODE:-700} \
   TEST_STAT_PATH=${STAT_PATH:-} TEST_CANON_MODE=${CANON_MODE:-good} \
  TEST_REAL_STAT="$REAL_STAT" TEST_FAKE_LINKS=${FAKE_LINKS:-} \
  TEST_MODE_PATH=${MODE_PATH:-} TEST_MODE_VALUE=${MODE_VALUE:-644} \
  TEST_OWNER_PATH=${OWNER_PATH:-} TEST_OWNER_UID_VALUE=${OWNER_UID:-1000} \
  TEST_HASH_CONST=${HASH_CONST-$GOOD} TEST_ELF_MODE=${ELF_MODE:-static} \
  TEST_ELF_MACHINE="$ELF_MACHINE" TEST_CAND_LOG="$CAND_LOG" \
  TEST_HASH_LOG="$HASH_LOG" TEST_SYSTEM_LOG="$SYSTEM_LOG" \
  TEST_REAL_SHA="$REAL_SHA" \
  sh "$INSTALL" "$@"
}

mkmat() { # name -> path of a fresh, valid node-material directory
  _dir=$T/materials.$1
  mkdir -p "$_dir"
  for _f in identity.pem identity.key identity.ed25519.key identity-ca.pem \
            outer.pem outer.key outer-ca.pem issuer.key-id issuer.generation \
            issuer.ed25519.der issuer.mldsa.der local.signed peer.signed \
            status.signed roots.cbor; do
    printf 'fixture\n' > "$_dir/$_f"
  done
  printf '%s\n' "$_dir"
}

printf 'version = 1\n' > "$T/config.toml"
cp "$CAND" "$T/boreas-src"
chmod 0755 "$T/boreas-src"

# The standard install invocation; extra arguments are appended.
# A function (not a word-split string) so no unquoted expansion is needed.
POLICY=$T/policy
mkdir -m 0700 "$POLICY"
# The three signed policy inputs live in --policy-dir; the two NetworkRoot pins
# are separate, independently provisioned files outside it.
for policy_file in policy.tbs policy.ed25519.sig policy.mldsa65.sig; do
  printf 'trusted policy fixture %s\n' "$policy_file" > "$POLICY/$policy_file"
  chmod 0600 "$POLICY/$policy_file"
done
for pin_file in root.ed25519.der root.mldsa65.der; do
  printf 'independently provisioned pin %s\n' "$pin_file" > "$T/$pin_file"
  chmod 0600 "$T/$pin_file"
done
run_release() { # release id, extra arguments...
  rel=$1
  shift
  invoke --sha256 "$GOOD" --release "$rel" --config "$T/config.toml" \
    --binary "$T/boreas-src" --policy-dir "$POLICY" --network-id 0123456789abcdef0123456789abcdef \
    --network-root-ed25519-der "$T/root.ed25519.der" \
    --network-root-mldsa65-der "$T/root.mldsa65.der" "$@"
}
run_base() { run_release test.1 "$@"; }

P=$T/opt/boreas

# Missing policy/pin inputs are fail-closed, never silently legacy behavior.
# A valid materials directory keeps the failure on the policy input under test.
MAT_EARLY=$(mkmat early)
expect_fail_msg 'missing NetworkRoot pin is refused' 'both separately provisioned NetworkRoot pins' \
  invoke --sha256 "$GOOD" --release test.0 --materials "$MAT_EARLY" --config "$T/config.toml" \
  --binary "$T/boreas-src" --policy-dir "$POLICY" --network-id 0123456789abcdef0123456789abcdef --dry-run
expect_fail_msg 'missing policy directory is refused' 'policy is mandatory' \
  invoke --sha256 "$GOOD" --release test.0 --materials "$MAT_EARLY" --config "$T/config.toml" \
  --binary "$T/boreas-src" --dry-run

# Policy/NetworkRoot inputs are fail-closed on every property the installer
# claims to check: presence, regular non-symlink type, no hard links, invoking
# user ownership, no group/other access, distinctness, and a stable set.
MAT_POL=$(mkmat policy)
copy_policy() { # directory -> fresh copy of the three valid policy inputs
  mkdir -m 0700 "$1"
  cp "$POLICY/policy.tbs" "$POLICY/policy.ed25519.sig" "$POLICY/policy.mldsa65.sig" "$1/"
}
policy_invocation() { # policy dir, ed pin, pq pin, extra args...
  pdir=$1 ed_pin=$2 pq_pin=$3
  shift 3
  invoke --sha256 "$GOOD" --release test.0 --materials "$MAT_POL" --config "$T/config.toml" \
    --binary "$T/boreas-src" --policy-dir "$pdir" --network-id 0123456789abcdef0123456789abcdef \
    --network-root-ed25519-der "$ed_pin" --network-root-mldsa65-der "$pq_pin" --dry-run "$@"
}
expect_fail_msg 'short --network-id is refused' '32 hexadecimal' \
  policy_invocation "$POLICY" "$T/root.ed25519.der" "$T/root.mldsa65.der" --network-id abc
expect_fail_msg 'missing NetworkRoot pin file is refused' 'regular non-symlink file' \
  policy_invocation "$POLICY" "$T/no-such-pin" "$T/root.mldsa65.der"
ln -s "$T/root.ed25519.der" "$T/root.ed.link"
expect_fail_msg 'symlinked NetworkRoot pin is refused' 'regular non-symlink file' \
  policy_invocation "$POLICY" "$T/root.ed.link" "$T/root.mldsa65.der"
expect_fail_msg 'the two NetworkRoot pins must be distinct files' 'must be distinct files' \
  policy_invocation "$POLICY" "$T/root.ed25519.der" "$T/root.ed25519.der"

POLICY_MISSING=$T/policy-missing
mkdir -m 0700 "$POLICY_MISSING"
cp "$POLICY/policy.ed25519.sig" "$POLICY/policy.mldsa65.sig" "$POLICY_MISSING/"
expect_fail_msg 'missing policy input is refused' 'must be a regular non-symlink file' \
  policy_invocation "$POLICY_MISSING" "$T/root.ed25519.der" "$T/root.mldsa65.der"

POLICY_SYM=$T/policy-sym
copy_policy "$POLICY_SYM"
rm -f "$POLICY_SYM/policy.tbs"
ln -s "$POLICY/policy.tbs" "$POLICY_SYM/policy.tbs"
expect_fail_msg 'symlinked policy input is refused' 'must be a regular non-symlink file' \
  policy_invocation "$POLICY_SYM" "$T/root.ed25519.der" "$T/root.mldsa65.der"

POLICY_EXTRA=$T/policy-extra
copy_policy "$POLICY_EXTRA"
printf 'unexpected\n' > "$POLICY_EXTRA/notes.txt"
expect_fail_msg 'extra --policy-dir entry is refused' 'unexpected entry' \
  policy_invocation "$POLICY_EXTRA" "$T/root.ed25519.der" "$T/root.mldsa65.der"

POLICY_HL=$T/policy-hardlink
copy_policy "$POLICY_HL"
ln -- "$POLICY_HL/policy.tbs" "$T/policy.tbs.hardlink"
expect_fail_msg 'hard-linked policy input is refused' 'must not be hard-linked' \
  policy_invocation "$POLICY_HL" "$T/root.ed25519.der" "$T/root.mldsa65.der"
rm -f "$T/policy.tbs.hardlink"

# Fault injection is scoped to one call: the fake stat sees the injected value
# only while these helpers run, so later checks keep the safe defaults.
mode_case() {
  MODE_PATH=$1
  MODE_VALUE=$2
  shift 2
  policy_invocation "$@"
  rc=$?
  MODE_PATH=
  MODE_VALUE=
  return "$rc"
}
owner_case() {
  OWNER_PATH=$1
  OWNER_UID=$2
  shift 2
  policy_invocation "$@"
  rc=$?
  OWNER_PATH=
  OWNER_UID=
  return "$rc"
}
expect_fail_msg 'group/other-readable policy input is refused' 'group/other accessible' \
  mode_case "$POLICY/policy.tbs" 644 "$POLICY" "$T/root.ed25519.der" "$T/root.mldsa65.der"
expect_fail_msg 'policy input owned by another user is refused' 'owned by the invoking user' \
  owner_case "$POLICY/policy.mldsa65.sig" 1000 "$POLICY" "$T/root.ed25519.der" "$T/root.mldsa65.der"
# A writable or foreign-owned input directory would let the verified bytes be
# swapped before the installer copies them; the same applies to every ancestor.
PIN_DIR=$T/pin-dir
mkdir -m 0700 "$PIN_DIR"
cp "$T/root.ed25519.der" "$T/root.mldsa65.der" "$PIN_DIR/"
expect_fail_msg 'group/other-writable --policy-dir is refused' 'must not be group/other writable' \
  mode_case "$POLICY" 777 "$POLICY" "$T/root.ed25519.der" "$T/root.mldsa65.der"
expect_fail_msg '--policy-dir owned by another user is refused' 'owned by the invoking user' \
  owner_case "$POLICY" 1000 "$POLICY" "$T/root.ed25519.der" "$T/root.mldsa65.der"
# Ancestors keep the strict owner rule but must not be misreported as the final
# directory: they get their own diagnostic.
expect_fail_msg 'an input ancestor owned by another user is refused' \
  'has an ancestor owned by another user' \
  owner_case "$T" 1000 "$POLICY" "$T/root.ed25519.der" "$T/root.mldsa65.der"
expect_fail_msg 'group/other-writable NetworkRoot pin directory is refused' \
  'must not be group/other writable' \
  mode_case "$PIN_DIR" 777 "$POLICY" "$PIN_DIR/root.ed25519.der" "$PIN_DIR/root.mldsa65.der"
expect_fail_msg 'a non-sticky group/other-writable ancestor is refused' \
  'ancestor without the sticky bit' \
  mode_case "$T" 777 "$POLICY" "$T/root.ed25519.der" "$T/root.mldsa65.der"
ln -s "$T" "$T/ancestor-link"
expect_fail_msg 'a symlinked ancestor is refused' 'must not traverse a symbolic link' \
  policy_invocation "$T/ancestor-link/policy" "$T/root.ed25519.der" "$T/root.mldsa65.der"
# Sticky /tmp is acceptable: a non-owner cannot rename a root-0700 child out of
# it. Inject the mode only for this invocation.
MODE_PATH=$T MODE_VALUE=1777
expect_ok 'a sticky group/other-writable ancestor is accepted' \
  policy_invocation "$POLICY" "$PIN_DIR/root.ed25519.der" "$PIN_DIR/root.mldsa65.der"
MODE_PATH=; MODE_VALUE=

PNET=$T/net-id-prefix/boreas
expect_fail_msg '--network-id must match the canonical config net_id' \
  'does not match the canonical config' \
  run_release test.9 --materials "$MAT_POL" --prefix "$PNET" --bindir "$T/bindir" \
  --network-id ffffffffffffffffffffffffffffffff
assert_absent "$PNET/active"
assert_absent "$PNET/releases/test.9"

# ---------------------------------------------------------------------------
# 1. --dry-run: read-only, never executes the candidate
# ---------------------------------------------------------------------------

# The network-id mismatch case above intentionally executes config-migrate
# before refusing the canonical config. Start a new execution-audit window for
# dry-run and the following pre-execution rejection cases; do not attribute
# those earlier, expected setup calls to this dry-run.
: > "$CAND_LOG"
MAT=$(mkmat dry)
expect_ok 'dry-run accepts valid local inputs' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir" --dry-run
assert_absent "$P"
grep -q 'no candidate binary' "$T/out" || bail 'dry run did not state that nothing was executed'
pass 'dry run states that nothing was executed'
[ ! -s "$CAND_LOG" ] || bail 'dry-run executed the candidate'
pass 'dry-run never executed the candidate'

MAT_CA=$(mkmat caca)
printf 'secret\n' > "$MAT_CA/root.mldsa65.key"
expect_fail_msg 'dry-run refuses real CA private key names' 'CA/authority private-key material' \
  run_base --materials "$MAT_CA" --prefix "$P" --bindir "$T/bindir" --dry-run

# G-1: the weak-HTTPS acknowledgement gate must be observable by its message.
expect_fail_msg 'HTTPS URL without acknowledgement is refused, by message' \
  'not independent trust' \
  invoke --url https://example.invalid/boreas --sha256 "$GOOD" --release test.3 \
  --materials "$MAT" --config "$T/config.toml" --prefix "$P" --bindir "$T/bindir" --dry-run
expect_fail_msg 'acknowledged URL still refuses to fetch during a dry run' \
  '--dry-run requires --binary' \
  invoke --url https://example.invalid/boreas --accept-weak-https --sha256 "$GOOD" \
  --release test.3 --materials "$MAT" --config "$T/config.toml" \
  --prefix "$P" --bindir "$T/bindir" --dry-run
expect_fail_msg 'plain HTTP URLs are refused' '--url must use HTTPS' \
  invoke --url http://example.invalid/boreas --accept-weak-https --sha256 "$GOOD" \
  --release test.3 --materials "$MAT" --config "$T/config.toml" \
  --prefix "$P" --bindir "$T/bindir" --dry-run

# ---------------------------------------------------------------------------
# 2. Argument and path validation
# ---------------------------------------------------------------------------

expect_fail_msg 'short digest is refused' '64 hexadecimal' \
  invoke --sha256 abc --release test.1 --materials "$MAT" --config "$T/config.toml" \
  --binary "$T/boreas-src" --prefix "$P" --bindir "$T/bindir" --dry-run
expect_fail_msg 'non-hex digest is refused' '64 hexadecimal' \
  invoke --sha256 "zz$GOOD" --release test.1 --materials "$MAT" --config "$T/config.toml" \
  --binary "$T/boreas-src" --prefix "$P" --bindir "$T/bindir" --dry-run

for rel in '..' '.' '-leading'; do
  expect_fail_msg "release id '$rel' is refused" '--release' \
    invoke --sha256 "$GOOD" --release "$rel" --materials "$MAT" --config "$T/config.toml" \
    --binary "$T/boreas-src" --prefix "$P" --bindir "$T/bindir" --dry-run
done
expect_fail_msg 'over-long release id is refused' '128 characters' \
  invoke --sha256 "$GOOD" --release "$(printf '%0129d' 0)" --materials "$MAT" \
  --config "$T/config.toml" --binary "$T/boreas-src" --prefix "$P" --bindir "$T/bindir" --dry-run

for bad_prefix in / /etc /usr /usr/bin /opt "$P/../etc" relative; do
  expect_fail_msg "prefix '$bad_prefix' is refused" '--prefix' \
    invoke --sha256 "$GOOD" --release test.1 --materials "$MAT" --config "$T/config.toml" \
    --binary "$T/boreas-src" --prefix "$bad_prefix" --bindir "$T/bindir" --dry-run
done
expect_fail_msg 'unknown option is refused' 'unknown option' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir" --dry-run --force

# ---------------------------------------------------------------------------
# 3. Materials policy: real CA names, symlinks, special files, allowlist
# ---------------------------------------------------------------------------

for ca in root.ed25519.key root.mldsa65.key ia.ed25519.key ia.mldsa65.key \
          status.ed25519.key status.mldsa65.key outer-ca.key; do
  m=$(mkmat "ca-$ca")
  printf 'secret\n' > "$m/$ca"
  expect_fail_msg "materials with $ca are refused" 'CA/authority private-key material' \
    run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run
done

m=$(mkmat extra)
printf 'notes\n' > "$m/notes.txt"
expect_fail_msg 'unknown material file is refused' 'unexpected material file' \
  run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run

m=$(mkmat hidden)
printf 'secret\n' > "$m/.hidden.key"
expect_fail_msg 'hidden material file is refused' 'unexpected material file' \
  run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run
m=$(mkmat newline)
printf 'secret\n' > "$m/identity.key
roots.cbor"
expect_fail_msg 'newline material filename is refused' 'unexpected material file' \
  run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run

m=$(mkmat link)
ln -s /etc/passwd "$m/identity.link"
expect_fail_msg 'symlink inside materials is refused' 'regular files' \
  run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run

m=$(mkmat fifo)
mkfifo "$m/identity.pipe"
expect_fail_msg 'FIFO inside materials is refused' 'regular files' \
  run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run

m=$(mkmat nested)
mkdir -p "$m/ca"
printf 'secret\n' > "$m/ca/root.mldsa65.key"
expect_fail_msg 'sub-directory in materials is refused' 'flat directory' \
  run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run

m=$(mkmat empty)
rm -f "$m"/*
expect_fail_msg 'empty materials directory is refused' 'is empty' \
  run_base --materials "$m" --prefix "$P" --bindir "$T/bindir" --dry-run

ln -s "$MAT" "$T/mat-link"
expect_fail_msg 'symlinked materials directory is refused' 'symbolic link' \
  run_base --materials "$T/mat-link" --prefix "$P" --bindir "$T/bindir" --dry-run

ln -s "$T/config.toml" "$T/cfg-link"
expect_fail_msg 'symlinked config file is refused' 'symbolic link' \
  invoke --sha256 "$GOOD" --release test.1 --config "$T/cfg-link" \
  --materials "$MAT" --binary "$T/boreas-src" --prefix "$P" --bindir "$T/bindir" --dry-run

# ---------------------------------------------------------------------------
# 4. Digest and ELF policy on the real (non-dry-run) path
# ---------------------------------------------------------------------------

PNEG=$T/neg-opt/boreas
HASH_CONST=$BAD expect_fail_msg 'digest mismatch fails closed' 'SHA-256 mismatch' \
  run_base --materials "$MAT" --prefix "$PNEG" --bindir "$T/bindir"
HASH_CONST=$GOOD
[ ! -s "$CAND_LOG" ] || bail 'a candidate was executed after a digest mismatch'
pass 'no candidate execution before the digest check passes'
# A failed run must release its own lock; otherwise every later attempt fails.
assert_absent "$PNEG/.install.lock"
pass 'a failed install releases its own lock'

ELF_MODE=interp_request expect_fail_msg 'requested program interpreter is refused' \
  'requests an interpreter' \
  run_base --materials "$MAT" --prefix "$PNEG" --bindir "$T/bindir"
ELF_MODE=interp_header expect_fail_msg 'INTERP program header is refused' 'INTERP' \
  run_base --materials "$MAT" --prefix "$PNEG" --bindir "$T/bindir"
ELF_MODE=needed expect_fail_msg 'DT_NEEDED is refused' 'DT_NEEDED' \
  run_base --materials "$MAT" --prefix "$PNEG" --bindir "$T/bindir"
ELF_MODE=arch expect_fail_msg 'foreign architecture is refused' 'does not match this host' \
  run_base --materials "$MAT" --prefix "$PNEG" --bindir "$T/bindir"
ELF_MODE=static
[ ! -s "$CAND_LOG" ] || bail 'a candidate was executed despite failing ELF policy'
pass 'no candidate execution before ELF policy passes'

# ---------------------------------------------------------------------------
# 5. Full install with fake root: layout, permissions, canonical config
# ---------------------------------------------------------------------------

MAT=$(mkmat install)
printf 'version = 1\n' > "$T/config.toml"
expect_ok 'full install succeeds' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
assert_mode "$P" 700
assert_mode "$P/releases" 700
assert_mode "$P/state" 700
assert_contains "$P/releases/test.1/config.toml" "identity_key = \"$P/releases/test.1/materials/identity.key\""
assert_contains "$P/releases/test.1/config.toml" "roots = \\[\"$P/releases/test.1/materials/roots.cbor\"\\]"
assert_contains "$P/releases/test.1/config.toml" "state_dir = \"$P/state\""
assert_not_contains "$P/releases/test.1/config.toml" '/source/'
assert_not_contains "$P/releases/test.1/config.toml" '.stage.'
assert_contains "$P/releases/test.1/config.toml" 'primary = "wan"'
assert_file "$P/releases/test.1/boreas"
assert_mode "$P/releases/test.1/boreas" 755
assert_file "$P/releases/test.1/config.toml"
assert_mode "$P/releases/test.1/config.toml" 600
assert_file "$P/releases/test.1/bundle.sha256"
grep -q ' boreas$' "$P/releases/test.1/bundle.sha256" || bail 'bundle manifest does not cover the binary'
pass 'bundle manifest covers the binary'
grep -q ' config.toml$' "$P/releases/test.1/bundle.sha256" || bail 'bundle manifest does not cover the config'
pass 'bundle manifest covers the canonical config'
grep -q 'materials/identity.pem$' "$P/releases/test.1/bundle.sha256" || bail 'bundle manifest does not cover materials'
pass 'bundle manifest covers every material file'
assert_absent "$P/releases/test.1/config.source.toml"
assert_file "$P/releases/test.1/materials/identity.pem"
assert_mode "$P/releases/test.1/materials" 700
assert_mode "$P/releases/test.1/materials/identity.key" 600
# The five signed inputs are published once under release-scoped names directly
# in state/ (runtime requires direct children), byte-identical to the verified
# staging copies, and the shared durable stores are NOT pre-created.
for input in policy.tbs policy.ed25519.sig policy.mldsa65.sig root.ed25519.der root.mldsa65.der; do
  assert_file "$P/state/test.1.$input"
  assert_mode "$P/state/test.1.$input" 600
done
cmp -s "$POLICY/policy.tbs" "$P/state/test.1.policy.tbs" || bail 'published TBS differs from the verified input'
cmp -s "$T/root.mldsa65.der" "$P/state/test.1.root.mldsa65.der" || bail 'published pin differs from the verified pin'
pass 'published policy inputs are byte-identical to the verified inputs'
# The publish step hard-links into state/ and then drops the staging name, so the
# final file must have exactly one link (a second name would be an unnoticed alias
# that re-entry rejects).
for input in policy.tbs policy.ed25519.sig policy.mldsa65.sig root.ed25519.der root.mldsa65.der; do
  [ "$($REAL_STAT -c '%h' -- "$P/state/test.1.$input")" = 1 ] \
    || bail "published policy input has more than one link: $input"
done
pass 'published policy inputs have exactly one link'
grep -q 'policy-inputs/policy.tbs$' "$P/releases/test.1/bundle.sha256" \
  || bail 'bundle manifest does not cover the policy inputs'
pass 'bundle manifest covers every policy input'
assert_absent "$P/state/status.state"
assert_absent "$P/state/policy.state"
pass 'durable stores are left for the daemon to create'
# An empty placeholder would be read back as a corrupt store, so an existing
# zero-length store is refused rather than silently accepted.
: > "$P/state/status.state"
chmod 0600 "$P/state/status.state"
expect_fail_msg 'an empty pre-existing durable store is refused' 'is empty; remove it' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
rm -f "$P/state/status.state"
[ "$(sed -n '1p' "$P/active")" = 'test.1' ] || bail 'a refused store check changed the active pointer'
assert_contains "$P/releases/test.1/config.toml" 'net_id = "0123456789abcdef0123456789abcdef"'
assert_file "$P/active"
[ "$(sed -n '1p' "$P/active")" = 'test.1' ] || bail 'active pointer does not name the release'
pass 'active pointer names the release'
# The whole mutating run is serialized by a create-only lock removed on success.
# A pre-existing lock (another installer, or a stale one) must fail before
# staging and must never be removed by a run that did not create it.
assert_absent "$P/.install.lock"
mkdir -m 0700 "$P/.install.lock"
expect_fail_msg 'a held installation lock is refused' 'installation lock is held' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
[ "$(sed -n '1p' "$P/active")" = 'test.1' ] || bail 'a refused installation lock changed the active pointer'
[ -d "$P/.install.lock" ] || bail 'the installer removed a lock it did not create'
pass 'a foreign installation lock is left untouched'
[ -z "$(find "$P" -mindepth 1 -maxdepth 1 -name '.stage.*' -print)" ] \
  || bail 'a refused installation lock still created a staging directory'
pass 'a refused installation lock fails before staging'
rmdir "$P/.install.lock"
assert_file "$P/boreas-dispatch"
assert_mode "$P/boreas-dispatch" 755
assert_contains "$P/boreas-dispatch" "PREFIX=$P"
assert_not_contains "$P/boreas-dispatch" '@@PREFIX@@'
assert_not_contains "$P/boreas-dispatch" 'BOREAS_PREFIX'
assert_file "$P/boreas-run"
assert_contains "$P/boreas-run" "PREFIX=$P"
assert_not_contains "$P/boreas-run" '@@PREFIX@@'
assert_not_contains "$P/boreas-run" 'BOREAS_PREFIX'
assert_symlink "$T/bindir/boreas"
[ "$(readlink -- "$T/bindir/boreas")" = "$P/boreas-dispatch" ] || bail 'dispatcher symlink target differs'
pass 'dispatcher symlink targets the rendered dispatcher'
assert_symlink "$T/bindir/boreas-easy"
assert_contains "$CAND_LOG" 'config-migrate'
assert_contains "$CAND_LOG" 'config-check'
# config-check must receive the canonical file, never the discarded source copy.
grep '^config-check ' "$CAND_LOG" | grep -q 'config\.toml' || bail 'config-check did not receive config.toml'
pass 'config-check received the canonical config.toml'
if grep '^config-check ' "$CAND_LOG" | grep -q 'config\.source\.toml'; then
  bail 'config-check was pointed at the discarded source config'
fi
pass 'config-check was not pointed at config.source.toml'
assert_contains "$CAND_LOG" 'verify-bundle'
assert_not_contains "$SYSTEM_LOG" 'systemctl'

for mode in extra duplicate malformed; do
  CANON_MODE=$mode expect_fail_msg "canonical paths $mode fails closed" \
    'unsupported canonical' run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
done
CANON_MODE=good
# Compare every non-path byte with the original canonical stream.
TEST_CAND_LOG="$CAND_LOG" "$CAND" config-migrate "$T/config.toml" > "$T/canonical.original"
sed '/^identity_key = /d; /^roots = /d; /^state_dir = /d' "$T/canonical.original" > "$T/other.expected"
sed '/^identity_key = /d; /^roots = /d; /^state_dir = /d' "$P/releases/test.1/config.toml" > "$T/other.actual"
cmp -s "$T/other.expected" "$T/other.actual" || bail 'relocation changed unrelated canonical settings'
pass 'relocation preserves every other canonical line'
before=$(wc -l < "$CAND_LOG")
"$T/bindir/boreas" doctor > "$T/dispatch.out" 2>&1 || bail 'dispatcher failed on a valid pointer'
grep -q '^doctor$' "$CAND_LOG" || bail 'dispatcher did not reach the release binary'
pass 'dispatcher execs the active release'
"$T/bindir/boreas-easy" doctor >> "$T/dispatch.out" 2>&1 || bail 'boreas-easy dispatcher failed'
after=$(wc -l < "$CAND_LOG")
[ "$after" -gt "$before" ] || bail 'boreas-easy dispatcher did not reach the release binary'
pass 'boreas-easy dispatcher works'
"$T/bindir/boreas-easy" --socket /run/boreas.sock --service boreas > "$T/dispatch.out" 2>&1 || bail 'easy options dispatch failed'
assert_contains "$CAND_LOG" '^console --socket /run/boreas.sock --service boreas$'
"$T/bindir/boreas-easy" > "$T/dispatch.out" 2>&1 || bail 'easy default dispatch failed'
assert_contains "$CAND_LOG" '^console$'
assert_contains "$CAND_LOG" '^doctor$'
printf '%s\n' '..' > "$P/active"
expect_fail_msg 'dispatcher rejects a traversal pointer' 'unsafe active release pointer' \
  "$T/bindir/boreas" doctor
printf '%s\n' 'test.1' > "$P/active"

# ---------------------------------------------------------------------------
# 6. Idempotent re-entry: whole-bundle comparison
# ---------------------------------------------------------------------------

expect_ok 're-entry with an identical bundle is idempotent' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
[ "$(find "$P/releases" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ] || bail 're-entry created a second release'
pass 're-entry created no second release'

printf 'version = 1\n# different\n' > "$T/config.toml"
expect_fail_msg 're-entry with a different config is refused' 'different bundle' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
printf 'version = 1\n' > "$T/config.toml"

printf 'changed\n' > "$MAT/local.signed"
expect_fail_msg 're-entry with different materials is refused' 'different bundle' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
printf 'fixture\n' > "$MAT/local.signed"
expect_ok 're-entry works again once the bundle matches' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"

# Release-scoped publication never overwrites. A tampered existing generation is
# a release-id conflict; an identical one is reused so re-entry stays idempotent.
printf 'tampered\n' > "$P/state/test.1.policy.tbs"
expect_fail_msg 'a conflicting published policy input is refused' \
  'already published with a different policy input' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
grep -q 'tampered' "$P/state/test.1.policy.tbs" \
  || bail 'a conflicting re-entry overwrote the published input'
pass 'a conflicting re-entry did not overwrite the published input'
cp "$POLICY/policy.tbs" "$P/state/test.1.policy.tbs"
expect_ok 're-entry reuses a byte-identical published generation' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir"

# ---------------------------------------------------------------------------
# 6b. Upgrade publication: per-generation files, no partial publish, rollback
# ---------------------------------------------------------------------------

expect_ok 'upgrade installs release test.2' \
  run_release test.2 --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
[ "$(sed -n '1p' "$P/active")" = 'test.2' ] || bail 'upgrade did not move the active pointer'
for input in policy.tbs policy.ed25519.sig policy.mldsa65.sig root.ed25519.der root.mldsa65.der; do
  assert_file "$P/state/test.2.$input"
done
cmp -s "$POLICY/policy.tbs" "$P/state/test.1.policy.tbs" \
  || bail 'upgrade mutated the previous policy generation'
pass 'upgrade leaves the previous generation untouched'

# Half-finished upgrade: test.3's third input already exists with different
# bytes. Publication must fail without overwriting it, must remove the inputs it
# already linked for test.3, and must leave the active pointer on test.2.
printf 'conflict\n' > "$P/state/test.3.policy.mldsa65.sig"
chmod 0600 "$P/state/test.3.policy.mldsa65.sig"
expect_fail_msg 'a conflicting upgrade conflicts instead of overwriting' \
  'already published with a different policy input' \
  run_release test.3 --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
[ "$(sed -n '1p' "$P/active")" = 'test.2' ] || bail 'a failed upgrade changed the active pointer'
assert_absent "$P/state/test.3.policy.tbs"
assert_absent "$P/state/test.3.policy.ed25519.sig"
grep -q 'conflict' "$P/state/test.3.policy.mldsa65.sig" \
  || bail 'a failed upgrade overwrote an existing input'
cmp -s "$POLICY/policy.tbs" "$P/state/test.2.policy.tbs" \
  || bail 'a failed upgrade damaged the previous generation'
pass 'a failed upgrade cleans up only its own partial publication'

# The same upgrade succeeds once the conflict is gone, and writing the previous
# id back into the pointer re-selects the previous unmodified inputs: no
# re-publish is needed for a rollback.
rm -f "$P/state/test.3.policy.mldsa65.sig"
expect_ok 'the upgrade succeeds once the conflict is removed' \
  run_release test.3 --materials "$MAT" --prefix "$P" --bindir "$T/bindir"
[ "$(sed -n '1p' "$P/active")" = 'test.3' ] || bail 'upgrade pointer is not test.3'
printf '%s\n' 'test.2' > "$P/active"
cmp -s "$POLICY/policy.tbs" "$P/state/test.2.policy.tbs" \
  || bail 'rollback would not find the previous generation inputs'
pass 'pointer rollback re-selects the previous inputs without re-publishing'
printf '%s\n' 'test.1' > "$P/active"

# ---------------------------------------------------------------------------
# 7. Prefix ownership gates, --start ordering, --bindir
# ---------------------------------------------------------------------------

for sub in releases bin state; do
  evil=$T/evil-$sub
  mkdir -p "$evil" "$T/victim-$sub"
  ln -s "$T/victim-$sub" "$evil/$sub"
  expect_fail_msg "preplanted $sub symlink is refused" 'symbolic link' \
    run_base --materials "$MAT" --prefix "$evil" --bindir "$T/bindir"
  assert_absent "$T/victim-$sub/test.1"
done
mkdir -p "$T/unsafe-ancestor"
STAT_PATH=$T/unsafe-ancestor FAKE_MODE=777 expect_fail_msg 'writable ancestor of missing prefix is refused' \
  'group/other writable' run_base --materials "$MAT" --prefix "$T/unsafe-ancestor/new/boreas" --bindir "$T/bindir"
STAT_PATH=$T/unsafe-ancestor FAKE_UID=1000 expect_fail_msg 'non-root ancestor is refused' \
  'owned by root' run_base --materials "$MAT" --prefix "$T/unsafe-ancestor/new/boreas" --bindir "$T/bindir"
STAT_PATH=; FAKE_UID=0; FAKE_MODE=700
POWN=$T/own-opt/boreas
# Scope the injected uid/mode to the prefix path so the policy-input checks keep
# their safe fake defaults and the failure under test is the prefix gate.
STAT_PATH=$POWN FAKE_UID=1000 expect_fail_msg 'prefix owned by a non-root user is refused' 'owned by root' \
  run_base --materials "$MAT" --prefix "$POWN" --bindir "$T/bindir"
STAT_PATH=; FAKE_UID=0
STAT_PATH=$POWN FAKE_MODE=0777 expect_fail_msg 'group/other-writable prefix is refused' 'group/other writable' \
  run_base --materials "$MAT" --prefix "$POWN" --bindir "$T/bindir"
STAT_PATH=; FAKE_MODE=700

expect_fail_msg '--start without a service is refused' '--start requires' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir" --start
expect_fail_msg '--start without /etc/boreas fails before any system write' '/etc/boreas' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/bindir" \
  --service systemd --start
assert_not_contains "$SYSTEM_LOG" 'systemctl'
assert_absent /etc/systemd/system/boreas.service
[ "$(sed -n '1p' "$P/active")" = 'test.1' ] || bail 'a refused --start changed the active pointer'
pass 'a refused --start left the active pointer untouched'

expect_fail_msg 'non-existent --bindir is refused instead of created' 'must already exist' \
  run_base --materials "$MAT" --prefix "$P" --bindir "$T/no-such-bindir"

# ---------------------------------------------------------------------------
# 8. Rendered service wrapper: configuration and route-ownership policy
# ---------------------------------------------------------------------------

WP=$T/wr
mkdir -p "$WP/releases/r1/materials"
printf 'version = 2\n' > "$WP/releases/r1/config.toml"
printf 'fixture\n' > "$WP/releases/r1/materials/local.signed"
# The wrapper must resolve the five inputs from the active release id, so each
# release owns a generation under state/ while the durable stores stay shared.
mkdir -m 0700 "$WP/state"
for name in policy.tbs policy.ed25519.sig policy.mldsa65.sig root.ed25519.der root.mldsa65.der; do
  printf 'wrapper fixture %s\n' "$name" > "$WP/state/r1.$name"
  chmod 0600 "$WP/state/r1.$name"
done
cat > "$WP/releases/r1/boreas" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${TEST_DAEMON_LOG:?}"
exit "${TEST_DAEMON_RC:-7}"
EOF
chmod 0755 "$WP/releases/r1/boreas"
printf '%s\n' 'r1' > "$WP/active"
WRUN=$T/boreas-run-rendered
sed -e "s|@@PREFIX@@|$WP|g" "$WRAPPER" > "$WRUN"
chmod 0755 "$WRUN"
IP_LOG=$T/ip.log
IP_COUNT=$T/ip.count

run_wrapper() {
  # Each invocation models a fresh host: no historical link probes or commands
  # may turn a later policy case into a false pre-existing-TUN failure.
  printf '0\n' > "$IP_COUNT"
  : > "$IP_LOG"
  PATH="$FAKE:$PATH" TEST_IP_MODE=${IP_MODE:-free} TEST_IP_LOG="$IP_LOG" \
  TEST_IP_COUNT="$IP_COUNT" TEST_DAEMON_RC=${DAEMON_RC:-7} \
  TEST_DAEMON_LOG="$T/daemon.log" \
  BOREAS_ROLE=${ROLE:-core} BOREAS_VIP=${VIP-10.20.1.1} \
  BOREAS_PEER_VIP=${PEER-10.20.1.2} BOREAS_LISTEN=${LISTEN-0.0.0.0:8443} \
  BOREAS_CONNECT=${CONNECT:-} BOREAS_TLS_NAME=${TLS_NAME:-} \
  BOREAS_TUN_NAME=${TUN_NAME:-btun0} BOREAS_MTU=${M_MTU:-1360} \
  sh "$WRUN"
}
reset_wrapper() { ROLE=core; VIP=10.20.1.1; PEER=10.20.1.2; LISTEN=0.0.0.0:8443; M_MTU=1360; TUN_NAME=btun0; CONNECT=''; TLS_NAME=''; }
reset_wrapper

expect_fail_msg 'unrendered wrapper refuses to run' 'not rendered' \
  env PATH="$FAKE:$PATH" BOREAS_ROLE=core BOREAS_VIP=10.0.0.1 BOREAS_PEER_VIP=10.0.0.2 \
  BOREAS_LISTEN=0.0.0.0:1 sh "$WRAPPER"

ROLE=sidecar expect_fail_msg 'invalid role is refused' 'invalid BOREAS_ROLE' run_wrapper
reset_wrapper
VIP=010.0.0.1 expect_fail_msg 'leading-zero IPv4 is refused' 'canonical dotted-quad' run_wrapper
reset_wrapper
VIP=10.0.0 expect_fail_msg 'short IPv4 is refused' 'canonical dotted-quad' run_wrapper
reset_wrapper
VIP=100.64.0.1 expect_fail_msg 'CGNAT VIP is refused' 'RFC1918' run_wrapper
reset_wrapper
PEER=100.127.255.254 expect_fail_msg 'CGNAT peer is refused' 'RFC1918' run_wrapper
reset_wrapper
VIP=8.8.8.8 expect_fail_msg 'public VIP is refused' 'RFC1918' run_wrapper
reset_wrapper
VIP=10.20.1.2 expect_fail_msg 'identical VIP and peer VIP are refused' 'must differ' run_wrapper
reset_wrapper
LISTEN=10.20.1.1 expect_fail_msg 'LISTEN without a port is refused' 'IPv4:port' run_wrapper
reset_wrapper
LISTEN=10.20.1.1:70000 expect_fail_msg 'out-of-range port is refused' 'IPv4:port' run_wrapper
reset_wrapper
M_MTU=1401 expect_fail_msg 'MTU above the supported range is refused' 'MTU must be' run_wrapper
reset_wrapper
M_MTU=abc expect_fail_msg 'non-numeric MTU is refused' 'invalid BOREAS_MTU' run_wrapper
reset_wrapper
TUN_NAME=bad/name expect_fail_msg 'unsafe TUN name is refused' 'BOREAS_TUN_NAME' run_wrapper
reset_wrapper
TUN_NAME=abcdefghijklmnop expect_fail_msg 'over-long TUN name is refused' 'IFNAMSIZ' run_wrapper
reset_wrapper
ROLE=edge expect_fail_msg 'edge role without CONNECT is refused' 'BOREAS_CONNECT' run_wrapper
reset_wrapper
ROLE=edge CONNECT=10.20.1.2:8443 TLS_NAME=wss.example.net \
  expect_fail_msg 'edge peer equal to the transport host is refused' \
  'must not be the BOREAS_CONNECT host' run_wrapper
reset_wrapper

IP_MODE=tun_exists expect_fail_msg 'pre-existing TUN is refused' 'pre-existing interface' run_wrapper
IP_MODE=local_vip expect_fail_msg 'VIP already configured locally is refused' 'already configured' run_wrapper
IP_MODE=local_peer expect_fail_msg 'peer VIP that is a local address is refused' 'is a local address' run_wrapper
IP_MODE=route_exists expect_fail_msg 'pre-existing peer /32 route is refused' 'already exists' run_wrapper

IP_MODE=tun_exists
set +e
run_wrapper > /dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 78 ] || bail "pre-existing TUN exit code is $rc, expected 78"
pass 'pre-existing TUN exits 78 (EX_CONFIG)'

# The wrapper resolves all five signed inputs from the active release id, so a
# missing/symlinked generation must be a configuration error (78) before any TUN
# probe or route change. The wrapper contract is exit 78 (EX_CONFIG), not just
# the message: a supervisor must be able to prevent a hot restart loop.
expect_config_error() { # desc, command...
  desc=$1
  shift
  set +e
  "$@" > "$T/out" 2> "$T/err"
  _config_rc=$?
  set -e
  [ "$_config_rc" -eq 78 ] || {
    printf 'FAIL - %s: exit %s, expected 78\n' "$desc" "$_config_rc" >&2
    dump
    exit 1
  }
  grep -q 'missing or unsafe policy input for active release r1' "$T/err" || {
    printf 'FAIL - %s: stderr lacks the policy-input diagnostic\n' "$desc" >&2
    dump
    exit 1
  }
  pass "$desc"
}
mv "$WP/state/r1.policy.tbs" "$T/r1.policy.tbs.hidden"
expect_config_error 'a missing active-release policy input is refused' run_wrapper
mv "$T/r1.policy.tbs.hidden" "$WP/state/r1.policy.tbs"
rm -f "$WP/state/r1.root.mldsa65.der"
ln -s /etc/passwd "$WP/state/r1.root.mldsa65.der"
expect_config_error 'a symlinked policy input is refused' run_wrapper
[ ! -s "$IP_LOG" ] || bail 'a policy input failure reached the ip command'
pass 'policy input failures happen before any ip command'
rm -f "$WP/state/r1.root.mldsa65.der"
printf 'wrapper fixture %s\n' root.mldsa65.der > "$WP/state/r1.root.mldsa65.der"
chmod 0600 "$WP/state/r1.root.mldsa65.der"

# A second generation is selected purely by the pointer; the wrapper must not
# keep reading the previous release's files.
mkdir -p "$WP/releases/r2/materials"
printf 'version = 2\n' > "$WP/releases/r2/config.toml"
printf 'fixture\n' > "$WP/releases/r2/materials/local.signed"
cp "$WP/releases/r1/boreas" "$WP/releases/r2/boreas"
chmod 0755 "$WP/releases/r2/boreas"
for name in policy.tbs policy.ed25519.sig policy.mldsa65.sig root.ed25519.der root.mldsa65.der; do
  printf 'wrapper fixture r2 %s\n' "$name" > "$WP/state/r2.$name"
  chmod 0600 "$WP/state/r2.$name"
done
printf '%s\n' 'r2' > "$WP/active"
: > "$T/daemon.log"
IP_MODE=free DAEMON_RC=0
set +e
run_wrapper > /dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || bail "second-generation wrapper run exited $rc"
assert_contains "$T/daemon.log" "--network-policy-tbs $WP/state/r2.policy.tbs"
assert_not_contains "$T/daemon.log" 'r1.policy.tbs'
pass 'the wrapper resolves policy inputs from the active release id'
printf '%s\n' 'r1' > "$WP/active"

# Successful path: address before route, daemon status propagated, and only the
# objects this invocation added are removed (route, then address).
IP_MODE=free DAEMON_RC=7
set +e
run_wrapper > /dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 7 ] || bail "daemon status was not propagated (got $rc)"
pass 'daemon exit status is propagated'
assert_contains "$T/daemon.log" "--network-policy-tbs $WP/state/r1.policy.tbs"
assert_contains "$T/daemon.log" "--network-policy-ed25519-signature $WP/state/r1.policy.ed25519.sig"
assert_contains "$T/daemon.log" "--network-policy-mldsa65-signature $WP/state/r1.policy.mldsa65.sig"
assert_contains "$T/daemon.log" "--network-root-ed25519-der $WP/state/r1.root.ed25519.der"
assert_contains "$T/daemon.log" "--network-root-mldsa65-der $WP/state/r1.root.mldsa65.der"
assert_contains "$T/daemon.log" "--status-state-file $WP/state/status.state"
assert_contains "$T/daemon.log" "--network-policy-state-file $WP/state/policy.state"
pass 'the wrapper passes every policy option with the active generation paths'
assert_contains "$IP_LOG" 'addr add 10.20.1.1/32 dev btun0'
assert_contains "$IP_LOG" 'route add 10.20.1.2/32 dev btun0'
addr_line=$(grep -n 'addr add' "$IP_LOG" | sed -n '1p' | cut -d: -f1)
route_line=$(grep -n 'route add' "$IP_LOG" | sed -n '1p' | cut -d: -f1)
[ "$addr_line" -lt "$route_line" ] || bail 'the peer route was added before the VIP address'
pass 'VIP address is added before the peer route'
assert_contains "$IP_LOG" 'route del 10.20.1.2/32 dev btun0'
assert_contains "$IP_LOG" 'addr del 10.20.1.1/32 dev btun0'
assert_not_contains "$IP_LOG" 'flush'
assert_not_contains "$IP_LOG" 'default'
assert_not_contains "$IP_LOG" 'link del'

# Route add failure: our address must be removed again, and no route deleted.
IP_MODE=add_fails DAEMON_RC=0
set +e
run_wrapper > /dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || bail "route-add failure exited $rc, expected 1"
pass 'route-add failure is a runtime failure (exit 1)'
assert_contains "$IP_LOG" 'addr del 10.20.1.1/32 dev btun0'
if grep -q 'route del' "$IP_LOG"; then bail 'a route that was never added was deleted'; fi
pass 'no route deletion after a failed route add'

# ---------------------------------------------------------------------------
# 9. Service templates: static security properties and the procd env parser
# ---------------------------------------------------------------------------

assert_contains "$UNIT" 'RestartPreventExitStatus=78'
assert_contains "$UNIT" 'NoNewPrivileges=yes'
assert_contains "$UNIT" 'ProtectSystem=strict'
assert_contains "$UNIT" 'ReadWritePaths=@@PREFIX@@/state'
assert_contains "$UNIT" 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE'
assert_contains "$UNIT" 'ExecStart=@@PREFIX@@/boreas-run'
assert_contains "$UNIT" 'TimeoutStopSec=20'
assert_not_contains "$UNIT" 'ExecStart=/opt/boreas'

assert_contains "$PROCD" '@@PREFIX@@/boreas-run'
# Match executable command starts, not prose or the chmod example in comments.
# A bare '.' is a regex wildcard and incorrectly matches '600 /etc/boreas'.
assert_not_contains "$PROCD" '^[[:space:]]*\.[[:space:]]'
assert_not_contains "$PROCD" '^[[:space:]]*source[[:space:]]'
assert_not_contains "$PROCD" '^[[:space:]]*eval[[:space:]]'
assert_not_contains "$PROCD" 'ExecStart='

# shellcheck disable=SC1091 # the procd template is an input file, not a library
. "$PROCD"
printf '%s\n' 'BOREAS_ROLE=core' 'BOREAS_VIP=10.20.1.1' 'BOREAS_PEER_VIP=10.20.1.2' \
  'BOREAS_LISTEN=0.0.0.0:8443' 'BOREAS_MTU=1360' > "$T/env.good"
chmod 0600 "$T/env.good"
BOREAS_ENV_FILE=$T/env.good
expect_ok 'procd env parser accepts a valid file' _boreas_env_parse
grep -q '^BOREAS_ROLE=core$' "$T/out" || bail 'parser did not emit the role'
pass 'procd env parser emits validated KEY=VALUE lines'

printf 'BOREAS_VIP=$(touch %s/pwned)\n' "$T" > "$T/env.inject"
BOREAS_ENV_FILE=$T/env.inject
expect_fail_msg 'procd env parser rejects command substitution' 'unsafe value' _boreas_env_parse
[ ! -e "$T/pwned" ] || bail 'env parsing executed a command substitution'
pass 'env parsing executed nothing (no eval, no sourcing)'

printf '%s\n' 'BOREAS_ROLE=core;reboot' > "$T/env.semi"
BOREAS_ENV_FILE=$T/env.semi
expect_fail_msg 'procd env parser rejects metacharacters' 'unsafe value' _boreas_env_parse

printf '%s\n' 'UNKNOWN_KEY=1' > "$T/env.unknown"
BOREAS_ENV_FILE=$T/env.unknown
expect_fail_msg 'procd env parser rejects unknown keys' 'unsupported key' _boreas_env_parse

printf 'BOREAS_VIP=10.20.1.1\r\n' > "$T/env.crlf"
BOREAS_ENV_FILE=$T/env.crlf
expect_fail_msg 'procd env parser rejects CRLF line endings' 'unsafe value' _boreas_env_parse

printf '%s\n' 'BOREAS_ROLE=core' 'BOREAS_VIP=x' > "$T/env.perms"
chmod 0644 "$T/env.perms"
expect_fail_msg 'procd world-readable env file is refused (exact 0600 required)' \
  'mode 0600' \
  env PATH="$FAKE:$PATH" TEST_FAKE_UID=0 TEST_FAKE_MODE=644 TEST_ENV="$T/env.perms" \
  sh -c '. "$1"; BOREAS_ENV_FILE=$TEST_ENV; _boreas_env_perms' sh "$PROCD"
for mode in 640 660 400 4600; do
  expect_fail_msg "procd env mode $mode is refused" 'mode 0600' \
    env PATH="$FAKE:$PATH" TEST_FAKE_UID=0 TEST_FAKE_MODE="$mode" TEST_ENV="$T/env.perms" \
    sh -c '. "$1"; BOREAS_ENV_FILE=$TEST_ENV; _boreas_env_perms' sh "$PROCD"
done
expect_fail_msg 'procd env owned by uid1000 is refused' 'owned by root' \
  env PATH="$FAKE:$PATH" TEST_FAKE_UID=1000 TEST_FAKE_MODE=600 TEST_ENV="$T/env.perms" \
  sh -c '. "$1"; BOREAS_ENV_FILE=$TEST_ENV; _boreas_env_perms' sh "$PROCD"
assert_contains "$INSTALL" 'env_file must have mode 0600'
assert_contains "$WRAPPER" 'ENV_FILE must have mode 0600'
chmod 0600 "$T/env.perms"
expect_ok 'procd env file at 0600 root-owned is accepted' \
  env PATH="$FAKE:$PATH" TEST_FAKE_UID=0 TEST_FAKE_MODE=600 TEST_ENV="$T/env.perms" \
  sh -c '. "$1"; BOREAS_ENV_FILE=$TEST_ENV; _boreas_env_perms' sh "$PROCD"

# A realistic procd mock replaces each parameter, rather than appending it.
# Repeated `procd_set_param env` therefore loses settings and fails this check.
procd_open_instance() { :; }
procd_close_instance() { :; }
procd_set_param() {
  _param=$1; shift
  if [ "$_param" = env ]; then
    printf '%s\n' "$@" > "$T/procd.env"
    printf 'call\n' >> "$T/procd.env.calls"
  fi
}
BOREAS_ENV_FILE=$T/env.good
: > "$T/procd.env.calls"
# These mocks affect stat only, never the harness's real uid.
_boreas_env_perms() {
  env PATH="$FAKE:$PATH" TEST_FAKE_UID=0 TEST_FAKE_MODE=600 TEST_ENV="$BOREAS_ENV_FILE" \
    sh -c '. "$1"; BOREAS_ENV_FILE=$TEST_ENV; _boreas_env_perms' sh "$PROCD"
}
expect_ok 'procd start accumulates all env arguments in one call' start_service
[ "$(wc -l < "$T/procd.env.calls")" -eq 1 ] || bail 'procd env parameter was set more than once'
cmp -s "$T/env.good" "$T/procd.env" || bail 'procd did not receive every env setting'
pass 'procd receives the complete env vector exactly once'

printf 'ok - %s deployment assertions passed\n' "$passed"
