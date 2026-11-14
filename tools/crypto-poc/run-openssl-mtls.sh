#!/usr/bin/env bash
# Backend-only OpenSSL TLS 1.3 ML-DSA/hybrid PoC. Run only in GitHub Actions.
set -Eeuo pipefail
umask 077
: "${OPENSSL_PREFIX:?set OPENSSL_PREFIX to the private OpenSSL install prefix}"
OPENSSL_BIN="${OPENSSL_PREFIX}/bin/openssl"
[[ -x "$OPENSSL_BIN" ]] || { echo "missing OpenSSL binary: $OPENSSL_BIN" >&2; exit 2; }
SAFE_OUT="${ARTIFACT_DIR:-$PWD/artifacts}"
mkdir -p "$SAFE_OUT"
WORK="$(mktemp -d)"
RAW_LOGS="$WORK/raw-logs"
mkdir -p "$RAW_LOGS"
# Keep TLS command output private: verbose s_client/s_server diagnostics can print session PSKs.
# Only allowlisted, sanitized summary lines are copied from RAW_LOGS into SAFE_OUT on EXIT.
OUT="$SAFE_OUT"
# install_sw doesn't install openssl.cnf. Use an explicit minimal config that activates only
# OpenSSL's built-in default provider; no modules/providers from the host or PATH are trusted.
cat > "$WORK/openssl.cnf" <<'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1
EOF
export OPENSSL_CONF="$WORK/openssl.cnf"
[[ -s "$OPENSSL_CONF" ]] || { echo 'explicit OPENSSL_CONF was not created' >&2; exit 2; }
cp "$OPENSSL_CONF" "$SAFE_OUT/openssl-test-config.cnf"
printf '[crypto-poc] OPENSSL_CONF=%s (explicit minimal default-provider config)\n' "$OPENSSL_CONF" | tee -a "$OUT/run.log"
SERVER_PID=""
SERVER_PORT=""
SERVER_STDIN_FD=""
sanitize_logs() {
  local raw base safe
  shopt -s nullglob
  for raw in "$RAW_LOGS"/*.log; do
    base="${raw##*/}"
    safe="$SAFE_OUT/${base%.log}.sanitized.txt"
    # Allowlist only handshake summary, verifier depth/result, alerts, and the test marker.
    # Never copy SSL-Session / PSK / master-secret or cert dump blocks into artifacts.
    awk '
      /^(CONNECTION ESTABLISHED|Protocol version:|Ciphersuite:|Requested Signature Algorithms:|Peer certificate:|Hash used:|Signature type:|Peer signature type:|Verification:|Verified peername:|Negotiated TLS1\.3 group:|New, TLSv1\.3, Cipher is|BOREAS_TLS_PLAINTEXT_OK|HTTP\/1\.0 200)/ {print; next}
      /^depth=[0-9]+:/ {print; next}
      /^verify return:[01]$/ {print; next}
      /^SSL3 alert (read|write):/ {print; next}
      /certificate required|certificate verify failed|certificate has expired|no suitable key share|no shared group|no ciphers available|no shared cipher|handshake failure/ {print; next}
      END { }
    ' "$raw" > "$safe"
  done
  shopt -u nullglob
  if grep -Eqi 'Resumption PSK:|Early Exporter Master Secret|CLIENT_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET|^-----BEGIN .*PRIVATE KEY-----' "$SAFE_OUT"/*.sanitized.txt 2>/dev/null; then
    echo 'Refusing to retain sensitive TLS key material in artifacts' >&2
    rm -f "$SAFE_OUT"/*.sanitized.txt
    return 1
  fi
}
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n "$SERVER_PID" ]]; then kill -TERM "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; fi
  if [[ -n "$SERVER_STDIN_FD" ]]; then exec {SERVER_STDIN_FD}>&-; SERVER_STDIN_FD=""; fi
  if ! sanitize_logs; then
    echo 'Sensitive-output guard or log sanitization failed; no raw TLS logs will be published.' >&2
    [[ $rc -ne 0 ]] || rc=1
  fi
  rm -rf "$WORK" || { echo 'Unable to remove private TLS test workspace' >&2; [[ $rc -ne 0 ]] || rc=1; }
  return "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
log() { printf '[crypto-poc] %s\n' "$*" | tee -a "$OUT/run.log"; }
fail() { log "FAIL: $*"; exit 1; }

"$OPENSSL_BIN" version -a | tee "$SAFE_OUT/openssl-version.txt"
"$OPENSSL_BIN" list -signature-algorithms | tee "$SAFE_OUT/signature-algorithms.txt"
"$OPENSSL_BIN" list -kem-algorithms | tee "$SAFE_OUT/kem-algorithms.txt"
"$OPENSSL_BIN" list -tls-groups | tee "$SAFE_OUT/tls-groups.txt"
"$OPENSSL_BIN" ciphers -s -tls1_3 | tee "$SAFE_OUT/tls13-ciphers.txt"
grep -qi 'ML-DSA-65' "$OUT/signature-algorithms.txt" || fail 'ML-DSA-65 primitive missing'
grep -qi 'ML-KEM-768' "$OUT/kem-algorithms.txt" || fail 'ML-KEM-768 primitive missing'
grep -qi 'X25519MLKEM768' "$OUT/tls-groups.txt" || fail 'hybrid group missing'
grep -q 'TLS_AES_256_GCM_SHA384' "$OUT/tls13-ciphers.txt" || fail 'AES-256-GCM suite missing'
grep -q 'TLS_CHACHA20_POLY1305_SHA256' "$OUT/tls13-ciphers.txt" || fail 'ChaCha suite missing'

cd "$WORK"
printf 'BOREAS_TLS_PLAINTEXT_OK\n' > tls-response.txt
"$OPENSSL_BIN" genpkey -algorithm ML-DSA-65 -out root.key
"$OPENSSL_BIN" req -new -x509 -key root.key -out root.pem -days 365 \
  -subj '/CN=Boreas PoC ML-DSA Root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
make_leaf() {
  local name="$1" cn="$2" serial="$3" eku="$4" days="${5:-14}"
  "$OPENSSL_BIN" genpkey -algorithm ML-DSA-65 -out "$name.key"
  "$OPENSSL_BIN" req -new -key "$name.key" -out "$name.csr" -subj "/CN=$cn"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=DNS:%s\n' "$eku" "$cn" > "$name.ext"
  "$OPENSSL_BIN" x509 -req -in "$name.csr" -CA root.pem -CAkey root.key -set_serial "$serial" -days "$days" -extfile "$name.ext" -out "$name.pem"
  "$OPENSSL_BIN" verify -CAfile root.pem "$name.pem"
}
make_leaf server server.boreas.invalid 1001 serverAuth
make_leaf client client.boreas.invalid 1002 clientAuth
make_leaf expired-client expired.boreas.invalid 1003 clientAuth 1
for name in root server client expired-client; do
  "$OPENSSL_BIN" x509 -in "$name.pem" -noout -text > "$OUT/$name-certificate.txt"
  grep -q 'ML-DSA-65' "$OUT/$name-certificate.txt" || fail "expected ML-DSA-65 certificate OID: $name"
done

start_server() {
  local cipher="$1" tag="$2" attime="${3:-}" fifo="$WORK/server-$tag.stdin"
  SERVER_PORT=$((20000 + RANDOM % 30000))
  mkfifo "$fifo"
  # Open read-write before starting server: no EOF and no test command reaches stdin.
  exec {SERVER_STDIN_FD}<>"$fifo"
  local -a verify_args=(-CAfile root.pem -Verify 1 -verify_return_error)
  [[ -z "$attime" ]] || verify_args+=(-attime "$attime")
  timeout --signal=TERM --kill-after=3s 40s "$OPENSSL_BIN" s_server -accept "127.0.0.1:$SERVER_PORT" -naccept 1 -WWW \
    -cert server.pem -key server.key "${verify_args[@]}" \
    -tls1_3 -groups X25519MLKEM768 -sigalgs mldsa65 -ciphersuites "$cipher" \
    -state -verify_verbose -no_ticket -num_tickets 0 <&"$SERVER_STDIN_FD" >"$RAW_LOGS/server-$tag.log" 2>&1 &
  SERVER_PID=$!
  local ready=0
  for _ in $(seq 1 150); do
    kill -0 "$SERVER_PID" 2>/dev/null || break
    if ss -H -ltn "sport = :$SERVER_PORT" | grep -q .; then ready=1; break; fi
    sleep 0.1
  done
  [[ "$ready" == 1 ]] || fail "server failed to listen ($tag)"
}
stop_server() {
  if [[ -n "$SERVER_PID" ]]; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
  if [[ -n "$SERVER_STDIN_FD" ]]; then exec {SERVER_STDIN_FD}>&-; SERVER_STDIN_FD=""; fi
}
client_test() {
  local cipher="$1" tag="$2" group="$3" identity="$4"
  local -a args=( -connect "127.0.0.1:$SERVER_PORT" -servername server.boreas.invalid
    -verify_hostname server.boreas.invalid -verify_return_error -CAfile root.pem -ign_eof
    -no_ticket -tls1_3 -groups "$group" -sigalgs mldsa65 -ciphersuites "$cipher" -brief -state )
  case "$identity" in
    client) args+=( -cert client.pem -key client.key ) ;;
    expired-client) args+=( -cert expired-client.pem -key expired-client.key ) ;;
    none) ;;
    *) fail "unknown client identity selection: $identity" ;;
  esac
  local rc=0
  printf 'GET /tls-response.txt HTTP/1.0\r\nHost: server.boreas.invalid\r\nConnection: close\r\n\r\n' |
    timeout --signal=TERM --kill-after=3s 25s "$OPENSSL_BIN" s_client "${args[@]}" >"$RAW_LOGS/client-$tag.log" 2>&1 || rc=$?
  printf '%s' "$rc"
}
reject_case() {
  local tag="$1" pattern="$2" cipher="$3" group="$4" identity="$5" attime="${6:-}"
  start_server TLS_AES_256_GCM_SHA384 "negative-$tag" "$attime"
  local rc
  rc="$(client_test "$cipher" "negative-$tag" "$group" "$identity")"
  stop_server
  [[ "$rc" != 0 && "$rc" != 124 && "$rc" != 137 && "$rc" != 143 ]] || fail "not a prompt TLS rejection ($tag, rc=$rc)"
  grep -Eiq "$pattern" "$RAW_LOGS/client-negative-$tag.log" "$RAW_LOGS/server-negative-$tag.log" || fail "expected TLS rejection reason absent ($tag)"
  if grep -Eqi 'unknown option|unrecognized option|address already in use|unable to load|no such file|error setting private key|error setting certificate' "$RAW_LOGS/client-negative-$tag.log" "$RAW_LOGS/server-negative-$tag.log"; then fail "test setup/CLI error ($tag)"; fi
  log "PASS expected TLS rejection ($tag)"
}
success_case() {
  local cipher="$1" tag="$2"
  start_server "$cipher" "$tag"
  local rc
  rc="$(client_test "$cipher" "$tag" X25519MLKEM768 client)"
  [[ "$rc" == 0 ]] || fail "mTLS failed or timed out ($tag rc=$rc)"
  local server_wait=0
  for _ in $(seq 1 400); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if kill -0 "$SERVER_PID" 2>/dev/null; then fail "server did not finish within 40 seconds ($tag)"; fi
  wait "$SERVER_PID" || server_wait=$?
  [[ "$server_wait" == 0 ]] || fail "server exited unsuccessfully ($tag rc=$server_wait)"
  SERVER_PID=""
  if [[ -n "$SERVER_STDIN_FD" ]]; then exec {SERVER_STDIN_FD}>&-; SERVER_STDIN_FD=""; fi
  grep -Fq 'Protocol version: TLSv1.3' "$RAW_LOGS/client-$tag.log" || fail "TLS 1.3 not observed ($tag)"
  grep -Fq "Ciphersuite: $cipher" "$RAW_LOGS/client-$tag.log" || fail "cipher not observed ($tag)"
  grep -Fq 'Negotiated TLS1.3 group: X25519MLKEM768' "$RAW_LOGS/client-$tag.log" || fail "hybrid group not observed ($tag)"
  grep -Eiq 'Peer signature type: (mldsa65|ML-DSA-65)' "$RAW_LOGS/client-$tag.log" || fail "ML-DSA peer signature not observed ($tag)"
  grep -Fq 'Verification: OK' "$RAW_LOGS/client-$tag.log" || fail "server chain not verified ($tag)"
  grep -Fq 'BOREAS_TLS_PLAINTEXT_OK' "$RAW_LOGS/client-$tag.log" || fail "TLS plaintext response marker missing ($tag)"
  grep -Eqi '^depth=1:' "$RAW_LOGS/server-$tag.log" || fail "server did not report issuer verification depth ($tag)"
  grep -Eqi '^depth=0:' "$RAW_LOGS/server-$tag.log" || fail "server did not report client leaf verification depth ($tag)"
  grep -Eqi '^verify return:1$' "$RAW_LOGS/server-$tag.log" || fail "server did not log successful client chain verification ($tag)"
  log "PASS TLS1.3 mTLS group=X25519MLKEM768 sigalg=mldsa65 cipher=$cipher HTTP-response ($tag)"
}

success_case TLS_AES_256_GCM_SHA384 aes256gcm
success_case TLS_CHACHA20_POLY1305_SHA256 chacha20
reject_case no-client-cert 'certificate required|peer did not return a certificate|no peer certificate' TLS_AES_256_GCM_SHA384 X25519MLKEM768 none
reject_case classical-kex 'no suitable key share|no shared group|handshake failure' TLS_AES_256_GCM_SHA384 X25519 client
reject_case aead-mismatch 'no ciphers available|no shared cipher|handshake failure' TLS_CHACHA20_POLY1305_SHA256 X25519MLKEM768 client
# Deterministic time check: the short-lived client cert is valid now, but is expired at +2 days.
reject_case expired-client 'certificate has expired|certificate verify failed|certificate expired|verify error' \
  TLS_AES_256_GCM_SHA384 X25519MLKEM768 expired-client "$(( $(date +%s) + 172800 ))"
log 'RESULT: backend-only OpenSSL s_server/s_client tests completed. No WebSocket-inner TLS or G-CRYPTO gate claimed.'
