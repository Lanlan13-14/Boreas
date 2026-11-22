#!/usr/bin/env bash
# Sourced by netns_daemon_smoke.sh after two-node fixture provisioning.
cutover_offline() {
  local phase="$1"; shift
  local rc=0
  timeout --kill-after=2s 10s "$BIN" "$@" > "$WORK/$phase.out" 2> "$WORK/$phase.err" || rc=$?
  if (( rc != 0 )); then
    printf 'pool_cutover_phase=%s exit=%s\n' "$phase" "$rc" >&2
    cat "$WORK/$phase.out" "$WORK/$phase.err" >&2
  fi
  return "$rc"
}

cutover_reject() {
  local phase="$1" expected="$2"; shift 2
  local rc=0
  cutover_offline "$phase" "$@" || rc=$?
  if [[ "$rc" != 2 ]] || ! grep -F "$expected" "$WORK/$phase.err"; then
    cat "$WORK/$phase.out" "$WORK/$phase.err" >&2
    echo "ERROR: expected cutover rejection ($phase; exit $rc)" >&2
    return 1
  fi
}

cutover_no_network() {
  [[ ! -e "$CORE_STATE/control.sock" && ! -e "$EDGE_STATE/control.sock" ]]
  for ns in "$CORE_NS" "$EDGE_NS"; do
    ! ip -n "$ns" link show btun0 >/dev/null 2>&1 || return 1
    [[ -z "$(ip netns exec "$ns" ss -Hlt 'sport = :8443')" ]] || return 1
  done
}

cutover_file_hash() { sha256sum "$1" | cut -d ' ' -f1; }

pool_cutover_matrix() {
  local pinned="$1" policy="$WORK/target-policy" role old state old_cfg name identity_hash
  local source_core='' source_edge='' sign_out root source_policy target_policy approval_base core_floor edge_floor
  local -a args legacy_core legacy_edge core_args edge_args
  local -a legacy_core_policy=("${CORE_POLICY_ARGS[@]}") legacy_edge_policy=("${EDGE_POLICY_ARGS[@]}")
  root="$("$BIN" pki verify-bundle --material-dir "$CORE_MAT" --require-peer | jq -er .root_fingerprint)"
  source_policy="$(cutover_file_hash "$pinned/tbs.cbor")"
  "$BIN" pki sign-policy --ca-dir "$CA_DIR" --out-dir "$policy" \
    --overlay-prefix 172.19.0.0/16 --sequence 2 --ttl-seconds 3600 >/dev/null
  target_policy="$(cutover_file_hash "$policy/tbs.cbor")"

  # Start the old direct daemons in separate namespaces and let the genuine
  # admission path create the policy and status floors. Edge first boot uses a
  # guaranteed closed peer port, and must fail at TCP, after durable admission.
  legacy_core=(daemon serve --config "$WORK/core.toml" --material-dir "$CORE_MAT"
    --status-state-file "$CORE_STATE/status.state" --status-state-owner-uid "$STATE_OWNER_UID"
    "${legacy_core_policy[@]}" --listen 192.0.2.1:8443 --tun-name btun0 --max-seconds 30)
  legacy_edge=(daemon connect --config "$WORK/edge.toml" --material-dir "$EDGE_MAT"
    --status-state-file "$EDGE_STATE/status.state" --status-state-owner-uid "$STATE_OWNER_UID"
    "${legacy_edge_policy[@]}" --connect 192.0.2.1:8443 --tls-name wss.boreas.test --tun-name btun0)
  run_node "$EDGE_NS" "$BIN" "${legacy_edge[@]}" > "$WORK/old-edge.out" 2> "$WORK/old-edge.err" &
  echo $! > "$WORK/edge.pid"
  if wait "$(<"$WORK/edge.pid")" || ! grep -F 'TCP connect failed' "$WORK/old-edge.err"; then
    cat "$WORK/old-edge.err" >&2; return 1
  fi
  rm "$WORK/edge.pid"
  run_node "$CORE_NS" "$BIN" "${legacy_core[@]}" > "$WORK/old-core.out" 2> "$WORK/old-core.err" &
  echo $! > "$WORK/core.pid"
  for _ in $(seq 1 120); do
    [[ -n "$(ip netns exec "$CORE_NS" ss -Hlt 'sport = :8443')" ]] && break
    sleep .05
  done
  [[ -n "$(ip netns exec "$CORE_NS" ss -Hlt 'sport = :8443')" ]]
  kill "$(<"$WORK/core.pid")"
  wait "$(<"$WORK/core.pid")" || true
  rm "$WORK/core.pid"
  # SIGTERM cannot run the old control-socket destructor.
  rm -f "$CORE_STATE/control.sock"
  cutover_no_network
  core_floor="$(cutover_file_hash "$CORE_STATE/status.state")"
  edge_floor="$(cutover_file_hash "$EDGE_STATE/status.state")"

  for role in core edge; do
    old="$WORK/$role-mat"; state="$WORK/$role-state"; old_cfg="$WORK/$role.toml"
    cp -a "$old" "$WORK/$role-target"
    cp "$old/local.signed" "$WORK/$role-target/legacy-local.signed"
    cp "$old/peer.signed" "$WORK/$role-target/legacy-peer.signed"
    sign_out="$("$BIN" pki stage-pool-migration --ca-dir "$CA_DIR" --out "$WORK/$role-staged.signed" \
      --legacy-identity "$old/local.signed" --roots "$old/roots.cbor" --expected-root-fingerprint "$root" \
      --tbs-file "$policy/tbs.cbor" --ed25519-signature-file "$policy/ed25519.sig" \
      --mldsa65-signature-file "$policy/mldsa65.sig")"
    [[ "$(jq -er .identity_generation <<< "$sign_out")" == 2 ]]
    # SignedObject v1 uses a binary envelope around its canonical CBOR TBS.
    identity_hash="$(python3 - "$old/local.signed" <<'PY'
import hashlib, sys
from pathlib import Path
b = Path(sys.argv[1]).read_bytes()
assert b[4] == 1
pos = 5 + 68 + int.from_bytes(b[71:73], 'big')
n = int.from_bytes(b[pos:pos+4], 'big')
tbs = b[pos+4:]
assert len(tbs) == n and n > 0
print(hashlib.sha256(tbs).hexdigest())
PY
)"
    if [[ "$role" == core ]]; then source_core="$identity_hash"; else source_edge="$identity_hash"; fi
    python3 - "$old_cfg" "$WORK/$role-target.toml" <<'PY'
import os, sys
from pathlib import Path
src, dst = map(Path, sys.argv[1:])
s = src.read_text().replace('[node]\n', '[node]\noverlay_prefix = "172.19.0.0/16"\n')
s = s.replace('identity_generation = 1', 'identity_generation = 2').replace('paths = 4', 'paths = 1').replace('probe_paths = 1', 'probe_paths = 0')
dst.write_text(s)
os.chmod(dst, 0o600)
PY
    for name in tbs.cbor ed25519.sig mldsa65.sig; do
      install -m 0600 -o "$STATE_OWNER_UID" "$policy/$name" "$state/target-$name"
    done
  done
  "$BIN" pki sign-status --ca-dir "$CA_DIR" --out "$WORK/cutover-status.signed" --sequence 2 >/dev/null
  cp "$WORK/cutover-status.signed" "$WORK/core-target/status.signed"
  cp "$WORK/cutover-status.signed" "$WORK/edge-target/status.signed"
  cp "$WORK/core-staged.signed" "$WORK/core-target/local.signed"
  cp "$WORK/core-staged.signed" "$WORK/edge-target/peer.signed"
  cp "$WORK/edge-staged.signed" "$WORK/edge-target/local.signed"
  cp "$WORK/edge-staged.signed" "$WORK/core-target/peer.signed"
  approval_base="1:$source_policy:$target_policy:$source_core:$source_edge:2:$root"
  for role in core edge; do
    state="$WORK/$role-state"
    args=(--config "$WORK/$role-target.toml" --material-dir "$WORK/$role-target"
      --status-state-file "$state/status.state" --status-state-owner-uid "$STATE_OWNER_UID"
      --network-policy-tbs "$state/target-tbs.cbor"
      --network-policy-ed25519-signature "$state/target-ed25519.sig"
      --network-policy-mldsa65-signature "$state/target-mldsa65.sig"
      --network-root-ed25519-der "$state/root-ed25519.der"
      --network-root-mldsa65-der "$state/root-mldsa65.der"
      --network-policy-state-file "$state/network-policy.state" --network-policy-state-owner-uid "$STATE_OWNER_UID"
      --tun-name btun0 --max-seconds 25)
    if [[ "$role" == core ]]; then
      core_args=(daemon serve "${args[@]}" --listen 192.0.2.1:8443)
    else
      edge_args=(daemon connect "${args[@]}" --connect 192.0.2.1:8443 --tls-name wss.boreas.test)
    fi
  done
  cutover_reject no-opt-in 'overlay_prefix' "${core_args[@]}"
  core_args+=(--pool-cutover "$approval_base:$core_floor")
  edge_args+=(--pool-cutover "$approval_base:$edge_floor")
  cutover_reject no-commit 'CutoverNotCommitted' "${core_args[@]}" --pool-cutover-action resume
  cutover_reject changed-status 'PoolCutoverMismatch' "${core_args[@]:0:${#core_args[@]}-1}" \
    "$approval_base:$target_policy" --pool-cutover-action check
  cutover_offline check-core "${core_args[@]}" --pool-cutover-action check
  cutover_offline check-edge "${edge_args[@]}" --pool-cutover-action check
  grep -Fx '{"pool_cutover":"checked","network_started":false}' "$WORK/check-core.out" "$WORK/check-edge.out"
  [[ "$core_floor" == "$(cutover_file_hash "$CORE_STATE/status.state")" ]]
  [[ "$edge_floor" == "$(cutover_file_hash "$EDGE_STATE/status.state")" ]]
  cutover_offline commit-core "${core_args[@]}" --pool-cutover-action commit
  cutover_offline commit-edge "${edge_args[@]}" --pool-cutover-action commit
  grep -Fx '{"pool_cutover":"committed","network_started":false}' "$WORK/commit-core.out" "$WORK/commit-edge.out"
  cutover_reject old-policy 'PrefixConflict' "${legacy_core[@]}"
  cutover_no_network
  echo 'pool_cutover_offline=check_and_commit_no_network_legacy_refused'

  run_node "$CORE_NS" "$BIN" "${core_args[@]}" --pool-cutover-action resume > "$WORK/core.out" 2> "$WORK/core.err" &
  echo $! > "$WORK/core.pid"
  for _ in $(seq 1 120); do
    [[ -n "$(ip netns exec "$CORE_NS" ss -Hlt 'sport = :8443')" ]] && break
    sleep .05
  done
  [[ -n "$(ip netns exec "$CORE_NS" ss -Hlt 'sport = :8443')" ]]
  run_node "$EDGE_NS" "$BIN" "${edge_args[@]}" --pool-cutover-action resume > "$WORK/edge.out" 2> "$WORK/edge.err" &
  echo $! > "$WORK/edge.pid"
  for _ in $(seq 1 120); do
    ip -n "$EDGE_NS" link show btun0 >/dev/null 2>&1 && break
    sleep .05
  done
  ip -n "$CORE_NS" addr add 172.19.1.1/32 dev btun0
  ip -n "$EDGE_NS" addr add 172.19.1.2/32 dev btun0
  ip -n "$CORE_NS" link set btun0 up
  ip -n "$EDGE_NS" link set btun0 up
  ip -n "$CORE_NS" route add 172.19.1.2/32 dev btun0
  ip -n "$EDGE_NS" route add 172.19.1.1/32 dev btun0
  local ready=0
  for _ in $(seq 1 120); do
    if "$BIN" ctl status --socket "$EDGE_STATE/control.sock" 2>/dev/null | jq -e '.daemon_connected' >/dev/null &&
       "$BIN" ctl status --socket "$CORE_STATE/control.sock" 2>/dev/null | jq -e '.daemon_connected' >/dev/null; then
      ready=1
      break
    fi
    kill -0 "$(<"$WORK/core.pid")" "$(<"$WORK/edge.pid")" 2>/dev/null || break
    sleep .05
  done
  if (( ready != 1 )); then
    echo 'ERROR: resumed cutover never confirmed both endpoints' >&2
    report_failure_evidence
    return 1
  fi
  ip -n "$CORE_NS" -4 route get 172.19.1.2 from 172.19.1.1
  ip -n "$EDGE_NS" -4 route get 172.19.1.1 from 172.19.1.2
  ip netns exec "$CORE_NS" ping -c 2 -W 2 -I 172.19.1.1 172.19.1.2
  ip netns exec "$EDGE_NS" ping -c 2 -W 2 -I 172.19.1.2 172.19.1.1
  # Even if operators mistakenly put the old addresses back on the TUN,
  # the authenticated packet path must not carry either old peer VIP.
  ip -n "$CORE_NS" addr add 10.20.1.1/32 dev btun0
  ip -n "$EDGE_NS" addr add 10.20.1.2/32 dev btun0
  ip -n "$CORE_NS" route add 10.20.1.2/32 dev btun0
  ip -n "$EDGE_NS" route add 10.20.1.1/32 dev btun0
  ! ip netns exec "$CORE_NS" ping -c 1 -W 1 -I 10.20.1.1 10.20.1.2 || return 1
  ! ip netns exec "$EDGE_NS" ping -c 1 -W 1 -I 10.20.1.2 10.20.1.1 || return 1
  ip netns exec "$CORE_NS" ping -c 1 -W 2 172.19.1.2
  echo 'pool_cutover_data=bidirectional_new_vips_and_old_vips_dropped'

  python3 "$DNS_FIXTURE" pool-revoke "$CA_DIR" "$TEST_NET_ID" "$WORK/pool-revocation.new"
  mv "$WORK/pool-revocation.new" "$WORK/core-target/identity-revocation.signed"
  for _ in $(seq 1 120); do
    ! kill -0 "$(<"$WORK/core.pid")" 2>/dev/null && break
    sleep .05
  done
  ! kill -0 "$(<"$WORK/core.pid")" 2>/dev/null || return 1
  if wait "$(<"$WORK/core.pid")" || ! grep -F 'node 2 generation 2 revoked' "$WORK/core.err"; then
    cat "$WORK/core.err" >&2; return 1
  fi
  rm "$WORK/core.pid" "$WORK/core-target/identity-revocation.signed"
  cutover_reject retained-source-denial 'node 2 generation 1 revoked' \
    "${core_args[@]}" --pool-cutover-action resume
  echo 'pool_cutover_revocation=source_denial_halted_successor_and_survived_restart'
}
