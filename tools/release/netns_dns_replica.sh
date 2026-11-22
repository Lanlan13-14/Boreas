#!/usr/bin/env bash
# Sourced only by netns_daemon_smoke.sh; uses its signed PKI fixtures and cleanup.

replica_wait() {
  local pid="$1"; shift
  for _ in $(seq 1 150); do
    kill -0 "$pid" 2>/dev/null || return 1
    if "$@"; then return 0; fi
    sleep 0.05
  done
  return 1
}

replica_status() {
  local state="$1" path="$2" epoch="$3" promotions="$4" json
  json=$("$BIN" ctl status --socket "$state/control.sock" 2>/dev/null) || return 1
  [[ "$json" == *'"daemon_connected":true'* && "$json" == *"\"active_path\":\"$path\""* &&
     "$json" == *"\"path_epoch\":$epoch,"* && "$json" == *"\"failover_events\":$promotions,"* ]]
}

replica_listener() {
  [[ -n "$(ip netns exec "$1" ss -Hln 'sport = :8443')" ]]
}

replica_start_core() {
  local ns="$1" tag="$2" label="$3" address="$4" vip="$5" budget="$6" objects="$7" pin="$8"
  local state="$WORK/$label-state" material="$WORK/$label-mat"
  run_node "$ns" "$BIN" daemon serve --config "$WORK/$label.toml" --material-dir "$material" \
    --status-state-file "$state/status.state" --status-state-owner-uid "$STATE_OWNER_UID" \
    --network-policy-tbs "$state/tbs.cbor" --network-policy-ed25519-signature "$state/ed25519.sig" \
    --network-policy-mldsa65-signature "$state/mldsa65.sig" --network-root-ed25519-der "$state/root-ed25519.der" \
    --network-root-mldsa65-der "$state/root-mldsa65.der" --network-policy-state-file "$state/network-policy.state" \
    --network-policy-state-owner-uid "$STATE_OWNER_UID" --private-dns-only --private-dns-dir "$objects" \
    --private-dns-pin "$pin" --listen "$address:8443" --tun-name btun0 --mtu 1280 --max-seconds "$budget" \
    >"$WORK/$tag.out" 2>"$WORK/$tag.err" &
  NODE_PID=$!
  replica_wait "$NODE_PID" replica_listener "$ns"
  ip -n "$ns" addr add "$vip/32" dev btun0
  ip -n "$ns" link set btun0 up
  ip -n "$ns" route add 10.20.1.2/32 dev btun0 src "$vip"
}

replica_start_edge() {
  local tag="$1" tls="$2" objects="$3" pin="$4"
  run_node "$EDGE_NS" "$BIN" daemon connect --config "$WORK/edge.toml" --material-dir "$EDGE_MAT" \
    --status-state-file "$EDGE_STATE/status.state" --status-state-owner-uid "$STATE_OWNER_UID" \
    "${EDGE_POLICY_ARGS[@]}" --private-dns-only --private-dns-dir "$objects" --private-dns-pin "$pin" \
    --connect 192.0.2.1:8443 --tls-name "$tls" --ws-host wss.boreas.test:8443 \
    --private-dns-backup 198.51.100.1:8443 --private-dns-backup-identity "$BACKUP_MAT/local.signed" \
    --tun-name btun0 --mtu 1280 --max-seconds 40 >"$WORK/$tag.out" 2>"$WORK/$tag.err" &
  EDGE_PID=$!
}

replica_edge_routes() {
  ip -n "$EDGE_NS" addr add 10.20.1.2/32 dev btun0
  ip -n "$EDGE_NS" link set btun0 up
  for vip in 10.20.0.53 10.20.1.1 10.20.2.1; do
    ip -n "$EDGE_NS" route add "$vip/32" dev btun0 src 10.20.1.2 advmss 600
  done
}

replica_expect_failure() {
  local pid="$1" tag="$2" needle="$3"
  for _ in $(seq 1 150); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.05
  done
  if kill -0 "$pid" 2>/dev/null || wait "$pid" || [[ "$(<"$WORK/$tag.err")" != *"$needle"* ]]; then
    cat "$WORK/$tag.err" >&2
    return 1
  fi
  # The backup is a one-accept daemon: without any dial it is still
  # available to authenticate a later positive case on the exact endpoint.
  [[ "$(<"$WORK/$tag.err")" != *'selecting configured backup'* ]]
}

replica_kill() {
  kill -KILL "$1"
  wait "$1" 2>/dev/null || true
}

replica_query() {
  ip netns exec "$EDGE_NS" python3 "$DNS_FIXTURE" "$@"
}

replica_require_ping_denial() {
  if ip netns exec "$1" ping -I btun0 -q -c 1 -W 1 "$2"; then
    echo "ERROR: DNS-only profile forwarded ordinary overlay ICMP" >&2
    return 1
  fi
}

replica_new_pins() {
  for label in core backup edge; do
    cp -- "$REPLICA_PIN" "$WORK/replica-$label.pin"
    chmod 0400 "$WORK/replica-$label.pin"
  done
}

# DNS private answers use one anycast-shaped VIP in the application's route
# table but one exclusive authenticated source at a time. No kernel DNS daemon.
dns_replica_matrix() {
  local replica_ns="boreas-dns-replica-$$" edge_veth="bre-$$" core_veth="brc-$$"
  local primary_pid backup_pid old_tcp_pid
  BACKUP_MAT="$WORK/backup-mat"
  REPLICA_OBJECTS="$WORK/dns-replica-objects"
  REPLICA_PIN="$WORK/dns-replicas.pin"
  local other_objects="$WORK/dns-other-objects" other_pin="$WORK/dns-other.pin"
  python3 "$DNS_FIXTURE" "$CA_DIR" "$POLICY_FIXTURE_DIR/tbs.cbor" \
    "$REPLICA_OBJECTS" "$REPLICA_PIN" "$TEST_NET_ID" --replica
  python3 "$DNS_FIXTURE" "$CA_DIR" "$POLICY_FIXTURE_DIR/tbs.cbor" \
    "$other_objects" "$other_pin" "$TEST_NET_ID" --replica
  replica_new_pins

  "$BIN" pki issue-node --ca-dir "$CA_DIR" --out-dir "$BACKUP_MAT" \
    --role core --home-core 2 --vip-octet 1 --outer-san wss.boreas.test
  cp -- "$EDGE_MAT/local.signed" "$BACKUP_MAT/peer.signed"
  "$BIN" pki verify-bundle --material-dir "$BACKUP_MAT" --require-peer
  mkdir -m 0700 "$WORK/backup-state"
  for name in tbs.cbor ed25519.sig mldsa65.sig root-ed25519.der root-mldsa65.der; do
    install -m 0600 -o "$STATE_OWNER_UID" "$POLICY_FIXTURE_DIR/$name" "$WORK/backup-state/$name"
  done
  cat > "$WORK/backup.toml" <<EOF
version = 2
[node]
net_id = "$TEST_NET_ID"
role = "core"
home_core_id = 2
vip_octet = 1
node_id = 257
identity_generation = 1
security_mode = "e2e-required"
suite = "pq768"
[paths]
identity_key = "$BACKUP_MAT/identity.key"
roots = ["$BACKUP_MAT/roots.cbor"]
state_dir = "$WORK/backup-state"
[uplink]
primary = "wss.boreas.test:8443"
paths = 4
probe_paths = 1
[dns]
zone = "private.boreas.test"
listen_vip = "10.20.0.53"
tcp = true
EOF
  chmod 0600 "$WORK/backup.toml"
  ip netns add "$replica_ns"
  REPLICA_NS="$replica_ns"
  ip netns exec "$replica_ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  ip netns exec "$replica_ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  ip -n "$replica_ns" link set lo up
  ip link add "$edge_veth" netns "$EDGE_NS" type veth peer name "$core_veth" netns "$replica_ns"
  ip -n "$replica_ns" addr add 198.51.100.1/24 dev "$core_veth"
  ip -n "$replica_ns" link set "$core_veth" up
  ip -n "$EDGE_NS" addr add 198.51.100.2/24 dev "$edge_veth"
  ip -n "$EDGE_NS" link set "$edge_veth" up

  # Cold failover: no listener on primary, a distinct signed Core on backup.
  # Reject the same backup under a valid object set which grants only primary.
  replica_start_core "$replica_ns" backup-cold backup 198.51.100.1 10.20.2.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-backup.pin"
  backup_pid=$NODE_PID
  replica_start_edge edge-no-grant wss.boreas.test "$DNS_DIR" "$WORK/dns-edge.pin"
  replica_expect_failure "$EDGE_PID" edge-no-grant 'lacks a current DNS Replica grant'
  echo 'dns_replica_grant=ungranted_backup_rejected_before_dial'

  replica_start_edge edge-cold wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_wait "$EDGE_PID" replica_status "$EDGE_STATE" backup 1 0
  replica_edge_routes
  replica_query replica-udp
  replica_query replica-tcp
  echo 'dns_replica_startup=refused_primary_selected_distinct_authenticated_backup'
  replica_kill "$EDGE_PID"
  wait "$backup_pid" 2>/dev/null || true

  # Primary accepts TCP but presents the wrong outer TLS name. The same
  # backup remains available later: no fallback after authentication starts.
  replica_start_core "$CORE_NS" core-bad-tls core 192.0.2.1 10.20.1.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-core.pin"
  primary_pid=$NODE_PID
  replica_start_edge edge-bad-tls wrong.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_expect_failure "$EDGE_PID" edge-bad-tls 'replica WSS/hop rejected'
  wait "$primary_pid" 2>/dev/null || true
  echo 'dns_replica_tls=wrong_server_name_terminal_no_fallback'

  # The outer TLS name and CA are correct but the primary socket presents the
  # authorized *backup* Core's PQ identity. Never rebind a configured source.
  replica_start_core "$CORE_NS" core-bad-identity backup 192.0.2.1 10.20.2.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-backup.pin"
  primary_pid=$NODE_PID
  replica_start_edge edge-bad-identity wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_expect_failure "$EDGE_PID" edge-bad-identity 'replica WSS/hop rejected'
  wait "$primary_pid" 2>/dev/null || true
  echo 'dns_replica_identity=wrong_pq_peer_terminal_no_fallback'

  # Both independently signed sets are locally allowed, but they differ.
  replica_start_core "$CORE_NS" core-other-pin core 192.0.2.1 10.20.1.1 65 "$other_objects" "$other_pin"
  primary_pid=$NODE_PID
  replica_start_edge edge-other-pin wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_expect_failure "$EDGE_PID" edge-other-pin 'replica confirmation rejected'
  wait "$primary_pid" 2>/dev/null || true
  echo 'dns_replica_pin_match=different_valid_remote_pin_terminal_no_fallback'

  replica_start_core "$replica_ns" backup-live backup 198.51.100.1 10.20.2.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-backup.pin"
  backup_pid=$NODE_PID
  replica_start_core "$CORE_NS" core-live core 192.0.2.1 10.20.1.1 15 \
    "$REPLICA_OBJECTS" "$WORK/replica-core.pin"
  primary_pid=$NODE_PID
  replica_start_edge edge-live wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_wait "$EDGE_PID" replica_status "$EDGE_STATE" primary 1 0
  replica_edge_routes
  replica_query replica-udp
  replica_query replica-tcp
  replica_require_ping_denial "$EDGE_NS" 10.20.1.1
  replica_require_ping_denial "$CORE_NS" 10.20.1.2
  echo 'dns_replica_packet_scope=ordinary_overlay_denied_in_both_directions'
  replica_query replica-old-tcp "$WORK/old-ready" "$WORK/promoted" &
  old_tcp_pid=$!
  replica_wait "$old_tcp_pid" test -f "$WORK/old-ready"
  wait "$primary_pid"
  [[ "$(<"$WORK/core-live.out")" == *'"stop_reason":"max_seconds_reached"'* ]]
  replica_wait "$EDGE_PID" replica_status "$EDGE_STATE" backup 2 1
  replica_wait "$backup_pid" replica_status "$WORK/backup-state" primary 1 0
  touch "$WORK/promoted"
  wait "$old_tcp_pid"
  replica_query replica-udp
  replica_query replica-tcp
  echo 'dns_replica_live=authenticated_close_promoted_once_with_fresh_udp_and_tcp_only'
  mv -- "$WORK/replica-backup.pin" "$WORK/withdrawn-backup.pin"
  replica_expect_failure "$backup_pid" backup-live 'private DNS authorization lost'
  # Edge may have already emitted its one valid promotion; require a terminal
  # business failure, not a successful stop, with no third path available.
  if wait "$EDGE_PID"; then return 1; fi
  [[ "$(<"$WORK/edge-live.err")" == *'selected circuit failed (no failover)'* ]]
  echo 'dns_replica_exhausted=withdrawn_backup_did_not_reopen_primary'

  # With a viable alternate, primary withdrawal must NOT appear as a clean
  # TLS close. Verify backup is still available to authenticate a new Edge.
  replica_new_pins
  replica_start_core "$replica_ns" backup-denial backup 198.51.100.1 10.20.2.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-backup.pin"
  backup_pid=$NODE_PID
  replica_start_core "$CORE_NS" core-withdraw core 192.0.2.1 10.20.1.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-core.pin"
  primary_pid=$NODE_PID
  replica_start_edge edge-withdraw wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_wait "$EDGE_PID" replica_status "$EDGE_STATE" primary 1 0
  replica_edge_routes
  replica_query replica-tcp
  mv -- "$WORK/replica-core.pin" "$WORK/withdrawn-core.pin"
  replica_expect_failure "$primary_pid" core-withdraw 'private DNS authorization lost'
  replica_expect_failure "$EDGE_PID" edge-withdraw 'selected circuit failed (no failover)'
  replica_start_edge edge-last wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_wait "$EDGE_PID" replica_status "$EDGE_STATE" backup 1 0
  replica_edge_routes
  replica_query replica-tcp
  echo 'dns_replica_withdrawal=abrupt_primary_pin_loss_terminal_while_backup_available'
  replica_kill "$EDGE_PID"
  wait "$backup_pid" 2>/dev/null || true

  # A fresh signed status sequence retires the exact captured lease; it is
  # not authorization for automatic fallback or an in-place lease renewal.
  replica_new_pins
  replica_start_core "$CORE_NS" core-status core 192.0.2.1 10.20.1.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-core.pin"
  primary_pid=$NODE_PID
  replica_start_core "$replica_ns" backup-denials backup 198.51.100.1 10.20.2.1 65 \
    "$REPLICA_OBJECTS" "$WORK/replica-backup.pin"
  backup_pid=$NODE_PID
  replica_start_edge edge-status wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_wait "$EDGE_PID" replica_status "$EDGE_STATE" primary 1 0
  replica_edge_routes
  replica_query replica-tcp
  "$BIN" pki sign-status --ca-dir "$CA_DIR" --out "$WORK/status.new" --sequence 2 --ttl-seconds 600
  mv -- "$WORK/status.new" "$EDGE_MAT/status.signed"
  replica_expect_failure "$EDGE_PID" edge-status 'private DNS authorization lost'
  wait "$primary_pid" 2>/dev/null || true
  echo 'dns_replica_status=valid_new_sequence_retired_pinned_lease_without_fallback'

  # With primary TCP unavailable, an authenticated and durable IdentityAuthority
  # denial still wins over startup selection of an otherwise viable backup.
  python3 "$DNS_FIXTURE" replica-revoke "$CA_DIR" "$TEST_NET_ID" "$WORK/revocation.new"
  mv -- "$WORK/revocation.new" "$EDGE_MAT/identity-revocation.signed"
  replica_start_edge edge-revoked wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_expect_failure "$EDGE_PID" edge-revoked 'identity node 257 generation 1 revoked'
  rm -- "$EDGE_MAT/identity-revocation.signed"
  replica_start_edge edge-durable-revoked wss.boreas.test "$REPLICA_OBJECTS" "$WORK/replica-edge.pin"
  replica_expect_failure "$EDGE_PID" edge-durable-revoked 'identity node 257 generation 1 revoked'
  kill -0 "$backup_pid"
  replica_kill "$backup_pid"
  echo 'dns_replica_revocation=revoked_backup_denied_before_dial_and_after_mailbox_removal'
}
