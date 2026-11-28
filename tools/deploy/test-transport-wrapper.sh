#!/bin/sh
# Isolated wrapper tests with fake ip/stat/daemon; never touches real networking.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
if [ -e /etc/boreas/boreas.env ] || [ -L /etc/boreas/boreas.env ]; then
  echo 'refusing: real boreas.env exists' >&2; exit 1
fi
T=$(mktemp -d "${TMPDIR:-/tmp}/boreas-transport-test.XXXXXXXX")
trap 'rm -rf "$T"' EXIT HUP INT TERM
P=$T/prefix
mkdir -p "$T/bin" "$P/releases/r/materials" "$P/state"
printf '%s\n' r > "$P/active"
: > "$P/releases/r/config.toml"
for f in policy.tbs policy.ed25519.sig policy.mldsa65.sig root.ed25519.der root.mldsa65.der; do
  : > "$P/state/r.$f"
done
# The temp path comes from mktemp, not external user input.
sed "s|@@PREFIX@@|$P|g" "$HERE/boreas-run" > "$T/run"
cat > "$T/bin/stat" <<'EOF'
#!/bin/sh
printf '%s\n' '0 600'
EOF
cat > "$T/bin/ip" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$TEST_IP_LOG"
if [ "$*" = 'link show btun0' ]; then
  if [ ! -e "$TEST_IP_SEEN" ]; then : > "$TEST_IP_SEEN"; exit 1; fi
  exit 0
fi
exit 0
EOF
cat > "$P/releases/r/boreas" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$TEST_DAEMON_LOG"
EOF
chmod 700 "$T/bin/stat" "$T/bin/ip" "$P/releases/r/boreas"
run() {
  rm -f "$T/seen" "$T/iplog" "$T/daemonlog"
  env -i PATH="$T/bin:$PATH" TEST_IP_SEEN="$T/seen" TEST_IP_LOG="$T/iplog" \
    TEST_DAEMON_LOG="$T/daemonlog" BOREAS_VIP=10.20.1.1 \
    BOREAS_PEER_VIP=10.20.1.2 "$@" sh "$T/run"
}
run BOREAS_ROLE=core BOREAS_LISTEN=0.0.0.0:8443
[ "$(tail -n 2 "$T/daemonlog")" = "$(printf '%s\n' --transport wss)" ]
run BOREAS_ROLE=core BOREAS_LISTEN=0.0.0.0:8443 BOREAS_TRANSPORT=direct
[ "$(tail -n 2 "$T/daemonlog")" = "$(printf '%s\n' --transport direct)" ]
run BOREAS_ROLE=edge BOREAS_CONNECT=192.0.2.1:8443 BOREAS_TLS_NAME=example.test BOREAS_WS_HOST=example.test:8443 BOREAS_TRANSPORT=wss
[ "$(tail -n 2 "$T/daemonlog")" = "$(printf '%s\n' --transport wss)" ]
run BOREAS_ROLE=edge BOREAS_CONNECT=192.0.2.1:8443 BOREAS_TLS_NAME=example.test BOREAS_TRANSPORT=direct
[ "$(tail -n 2 "$T/daemonlog")" = "$(printf '%s\n' --transport direct)" ]
if run BOREAS_ROLE=core BOREAS_LISTEN=0.0.0.0:8443 BOREAS_TRANSPORT=auto; then
  echo 'invalid mode accepted' >&2; exit 1
fi
[ ! -e "$T/daemonlog" ] && [ ! -e "$T/iplog" ]
printf '%s\n' 'wrapper transport routing tests passed (fake daemon and ip only)'
