#!/usr/bin/env bash
# Backend-only OpenSSL TLS 1.3 ML-DSA/hybrid PoC. Run only in GitHub Actions.
set -Eeuo pipefail
umask 077
: "${OPENSSL_PREFIX:?set OPENSSL_PREFIX to the private OpenSSL install prefix}"
OPENSSL_BIN="${OPENSSL_PREFIX}/bin/openssl"
[[ -x "$OPENSSL_BIN" ]] || { echo "missing OpenSSL binary: $OPENSSL_BIN" >&2; exit 2; }
OUT="${ARTIFACT_DIR:-$PWD/artifacts}"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
SERVER_PID=""
SERVER_PORT=""
SERVER_STDIN_FD=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then kill -TERM "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; fi
  if [[ -n "$SERVER_STDIN_FD" ]]; then exec {SERVER_STDIN_FD}>&-; SERVER_STDIN_FD=""; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
log() { printf '[crypto-poc] %s\n' "$*" | tee -a "$OUT/run.log"; }
fail() { log "FAIL: $*"; exit 1; }

"$OPENSSL_BIN" version -a | tee "$OUT/openssl-version.txt"
"$OPENSSL_BIN" list -signature-algorithms | tee "$OUT/signature-algorithms.txt"
"$OPENSSL_BIN" list -kem-algorithms | tee "$OUT/kem-algorithms.txt"
"$OPENSSL_BIN" list -tls-groups | tee "$OUT/tls-groups.txt"
"$OPENSSL_BIN" ciphers -s -tls1_3 | tee "$OUT/tls13-ciphers.txt"
grep -qi 'ML-DSA-65' "$OUT/signature-algorithms.txt" || fail 'ML-DSA-65 primitive missing'
grep -qi 'ML-KEM-768' "$OUT/kem-algorithms.txt" || fail 'ML-KEM-768 primitive missing'
grep -qi 'X25519MLKEM768' "$OUT/tls-groups.txt" || fail 'hybrid group missing'
grep -q 'TLS_AES_256_GCM_SHA384' "$OUT/tls13-ciphers.txt" || fail 'AES-256-GCM suite missing'
grep -q 'TLS_CHACHA20_POLY1305_SHA256' "$OUT/tls13-ciphers.txt" || fail 'ChaCha suite missing'

cd "$WORK"
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
  timeout --signal=TERM --kill-after=3s 40s "$OPENSSL_BIN" s_server -accept "127.0.0.1:$SERVER_PORT" -naccept 1 -www \
    -cert server.pem -key server.key "${verify_args[@]}" \
    -tls1_3 -groups X25519MLKEM768 -sigalgs mldsa65 -ciphersuites "$cipher" \
    -brief -state <&"$SERVER_STDIN_FD" >"$OUT/server-$tag.log" 2>&1 &
  SERVER_PID=$!
  local ready=0
  for _ in $(seq 1 150); do
    kill -0 "$SERVER_PID" 2>/dev/null || break
    if ss -H -ltn "sport = :$SERVER_PORT" | grep -q .; then ready=1; break; fi
    sleep 0.1
  done
  [[ "$ready" == 1 ]] || { cat "$OUT/server-$tag.log" >&2 || true; fail "server failed to listen ($tag)"; }
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
    -tls1_3 -groups "$group" -sigalgs mldsa65 -ciphersuites "$cipher" -brief -state )
  case "$identity" in
    client) args+=( -cert client.pem -key client.key ) ;;
    expired-client) args+=( -cert expired-client.pem -key expired-client.key ) ;;
    none) ;;
    *) fail "unknown client identity selection: $identity" ;;
  esac
  local rc=0
  printf 'GET / HTTP/1.0\r\nHost: server.boreas.invalid\r\nConnection: close\r\n\r\n' |
    timeout --signal=TERM --kill-after=3s 25s "$OPENSSL_BIN" s_client "${args[@]}" >"$OUT/client-$tag.log" 2>&1 || rc=$?
  printf '%s' "$rc"
}
reject_case() {
  local tag="$1" pattern="$2" cipher="$3" group="$4" identity="$5" attime="${6:-}"
  start_server TLS_AES_256_GCM_SHA384 "negative-$tag" "$attime"
  local rc
  rc="$(client_test "$cipher" "negative-$tag" "$group" "$identity")"
  stop_server
  [[ "$rc" != 0 && "$rc" != 124 && "$rc" != 137 && "$rc" != 143 ]] || fail "not a prompt TLS rejection ($tag, rc=$rc)"
  grep -Eiq "$pattern" "$OUT/client-negative-$tag.log" "$OUT/server-negative-$tag.log" || {
    cat "$OUT/client-negative-$tag.log" "$OUT/server-negative-$tag.log" >&2
    fail "expected rejection reason absent ($tag)"
  }
  if grep -Eqi 'unknown option|unrecognized option|address already in use|unable to load|no such file|error setting private key|error setting certificate' "$OUT/client-negative-$tag.log" "$OUT/server-negative-$tag.log"; then fail "test setup/CLI error ($tag)"; fi
  log "PASS expected TLS rejection ($tag)"
}
success_case() {
  local cipher="$1" tag="$2"
  start_server "$cipher" "$tag"
  local rc
  rc="$(client_test "$cipher" "$tag" X25519MLKEM768 client)"
  [[ "$rc" == 0 ]] || { cat "$OUT/client-$tag.log" "$OUT/server-$tag.log" >&2; fail "mTLS failed or timed out ($tag rc=$rc)"; }
  local server_wait=0
  for _ in $(seq 1 400); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if kill -0 "$SERVER_PID" 2>/dev/null; then fail "server did not finish within 40 seconds ($tag)"; fi
  wait "$SERVER_PID" || server_wait=$?
  [[ "$server_wait" == 0 ]] || { cat "$OUT/server-$tag.log" >&2; fail "server exited unsuccessfully ($tag rc=$server_wait)"; }
  SERVER_PID=""
  if [[ -n "$SERVER_STDIN_FD" ]]; then exec {SERVER_STDIN_FD}>&-; SERVER_STDIN_FD=""; fi
  grep -Fq 'Protocol version: TLSv1.3' "$OUT/client-$tag.log" || fail "TLS 1.3 not observed ($tag)"
  grep -Fq "Ciphersuite: $cipher" "$OUT/client-$tag.log" || fail "cipher not observed ($tag)"
  grep -Fq 'Negotiated TLS1.3 group: X25519MLKEM768' "$OUT/client-$tag.log" || fail "hybrid group not observed ($tag)"
  grep -Eiq 'Peer signature type: (mldsa65|ML-DSA-65)' "$OUT/client-$tag.log" || fail "ML-DSA peer signature not observed ($tag)"
  grep -Fq 'Verification: OK' "$OUT/client-$tag.log" || fail "server chain not verified ($tag)"
  grep -Fq 'HTTP/1.0 200' "$OUT/client-$tag.log" || fail "HTTP payload response missing ($tag)"
  grep -Eqi 'verify return:1|Verification: OK' "$OUT/server-$tag.log" || fail "client certificate not verified ($tag)"
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
