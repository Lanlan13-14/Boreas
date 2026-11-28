#!/bin/sh
# Pure argument-routing tests: copied entrypoint delegates to a fake installer.
# No candidate execution, services, network, privileges or host installation.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
T=$(mktemp -d "${TMPDIR:-/tmp}/boreas-one-click-test.XXXXXXXX")
trap 'rm -rf "$T"' EXIT HUP INT TERM
cp "$HERE/one-click.sh" "$T/one-click.sh"
cat > "$T/install.sh" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$TEST_ARGS"
EOF
TEST_ARGS=$T/args
export TEST_ARGS
run() { sh "$T/one-click.sh" "$@"; }
reject() {
  rm -f "$TEST_ARGS"
  if run "$@" > "$T/out" 2>&1; then echo 'unexpected success' >&2; exit 1; fi
  [ ! -e "$TEST_ARGS" ] || { echo 'rejected input reached installer' >&2; exit 1; }
}
BASE_STAGE='/private/stage with spaces'
run --stage "$BASE_STAGE" --network-id abc --sha256 def --release r1 --service none --dry-run
cat > "$T/expected" <<'EOF'
--binary
/private/stage with spaces/boreas
--sha256
def
--release
r1
--materials
/private/stage with spaces/material
--config
/private/stage with spaces/node.toml
--policy-dir
/private/stage with spaces/policy
--network-id
abc
--network-root-ed25519-der
/private/stage with spaces/pins/root.ed25519.der
--network-root-mldsa65-der
/private/stage with spaces/pins/root.mldsa65.der
--prefix
/opt/boreas
--service
none
--dry-run
EOF
cmp "$T/expected" "$TEST_ARGS"
run --stage /private/stage/ --network-id abc --sha256 def --release r1 --service systemd --accept-legacy-service --apply
[ "$(tail -n 3 "$TEST_ARGS")" = "$(printf '%s\n' --service systemd --accept-legacy-service)" ]
reject --stage relative --network-id abc --sha256 def --release r --service none --dry-run
reject --stage / --network-id abc --sha256 def --release r --service none --dry-run
reject --stage //// --network-id abc --sha256 def --release r --service none --dry-run
reject --stage /x --network-id abc --sha256 def --release r --service systemd --apply
reject --stage /x --network-id abc --sha256 def --release r --service none --accept-legacy-service --apply
reject --stage /x --network-id abc --sha256 def --release r --service none
reject --stage /x --network-id abc --sha256 def --release r --service none --apply --dry-run
reject --stage /x --network-id abc --sha256 def --release r --service none --apply --url https://example.test
reject --stage /x --network-id abc --sha256 def --release r --service none --apply --start
reject --stage /x --stage /y --network-id abc --sha256 def --release r --service none --apply
printf '%s\n' 'one-click routing tests passed (fake installer only)'
