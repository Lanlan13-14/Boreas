# Netem next experiment: handshake budget vs transport ramp

Status: design note for the next diagnostic run. It does not change a threshold,
does not claim a root cause, and does not turn any existing red result green.

## Evidence boundary

Tested binary: source `4ef5e37fd7b7d06712eb7ab4799019375bfa1b37` from successful
backend run `43899414586`. Performance run
[`43901434822`](https://github.com/Lanlan13-14/Boreas/actions/runs/43901434822)
completed failure. Its workflow head `02c958a` is not the tested source.

The netem profile is **one-way delay per veth**, so the observed overlay RTT is
twice the profile number. The smoke's nominal `100 x 50 ms` connected loop takes
about **7.53–7.54 s** on failure because each poll spawns `ctl status`; do not
call that loop a 5 s handshake deadline.

| Profile (one-way / actual RTT) | TUN observed Core / Edge | Edge launch -> connected | Connected wait | 1 MiB throughput Edge/Core | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| 50 ms / 100 ms, 0% | not extracted | 1120 ms | 1000 ms | 4.654 / 4.643 Mbps | pass |
| 200 ms / 400 ms, 0.1% | 70 / 60 ms | 4120 ms | 4010 ms | 2.438 / 2.309 Mbps | fail |
| 400 ms / 800 ms, 1% | 100 / 50 ms | 7650 ms | 7540 ms | not run | fail: never connected |
| 200 ms / 400 ms, 3% | not extracted | 7650 ms | 7530 ms | not run | fail: never connected |

Jobs: `133418900865` (50 ms), `133418900930` (200 ms strict), `133418900987`
(400 ms), `133418900812` (200 ms 3%), `133418900688` (1 MiB vs 8 MiB).

TUN creation at 400 ms took only 100 / 50 ms. The failure is after TUN, not in
TUN startup. Both post-window `ctl` probes still reported
`available-not-connected`; Edge reported `outbound_upstreams: 0`.

## What the completed run supports

- The connect procedure appears to consume roughly **10–11 RTT**:
  `1120 / 100 = 11.2`, `4120 / 400 = 10.3`. The failed 400 ms window is only
  `7540 / 800 = 9.4 RTT`; at 10.3 RTT it would need about **8.2 s**, roughly
  0.7 s beyond the window. This is a hypothesis, not a proven cause: the 400 ms
  case also has 1% loss, so RTT and loss are confounded.
- 200 ms / 3% reaches about **19 RTT** without connecting. That is not explained
  by the same 10–11 RTT baseline alone; loss recovery, a handshake stall, scheduling,
  and other causes still need to be distinguished, and current evidence is insufficient for attribution.
- The 200 ms / 0.1% job fails 1 MiB but the same-source 8 MiB diagnostic passed
  one trial at 3.989 / 6.075 Mbps. The 1 MiB result is therefore not a fixed
  3 Mbps ceiling. One 8 MiB pass is not steady state and not acceptance.

## `ss -tin` evidence, and its limit

Strict 200 ms / 0.1% / 100 Mbps, 1 MiB (`133418900930`):

- before: Core/Edge `cwnd:27/26`, `delivery_rate 374504/345288 bps`, both
  `app_limited`.
- after: Core `cwnd:1846`, Edge `cwnd:1055 ssthresh:1053`,
  `retrans:0/1`, `bytes_retrans:166`, `unacked:36`,
  `rwnd_limited:197ms(2.5%)`, `delivery_rate 25473600/24604288 bps`.
- measured average was only 2.438 / 2.309 Mbps.

Diagnostic (`133418900688`): 1 MiB was 1.985 / 1.893 Mbps; 8 MiB was
3.989 / 6.075 Mbps. At the 8 MiB end, Core had `cwnd:317 ssthresh:317`,
`retrans:0/28`, `bytes_retrans:19506`; Edge had `cwnd:154 ssthresh:138`,
`retrans:0/28`, `bytes_retrans:23268`. The directions are asymmetric.

The 400 ms job has **no `ss` evidence**: `ss_before/after_*_status=
unmeasured:no-snapshot`, because the transfer never ran. Do not infer cwnd,
retransmits, or a transport cause for that case from this run.

These are only two snapshots bracketing the transfer. They cannot show whether
the 1 MiB average is slow start, an application-limited burst, or loss recovery.
The 8 MiB end state suggests loss-driven cwnd reduction in at least one
direction, but one trial cannot separate that from the short window.

## Experiment A: attribute the handshake stages

Purpose: determine which protocol round trips consume the 10–11 RTT and whether
400 ms / 1% is a window-boundary miss or a loss/RTO stall. Diagnostic only; keep
the 3 Mbps bound and every existing gate unchanged.

Add monotonic stage timestamps, gated by an explicit diagnostic environment
variable and emitted once to stderr (no status or key material):

1. `crates/boreas-tunnel/src/runtime.rs:117-139` — after TCP is already
   connected, then after outer TLS (`:134`), WebSocket upgrade (`:135`), hop
   inner TLS (`:136`), and `SessionHello`/`SessionAccept` (`:138`).
2. `crates/boreas-tunnel/src/e2e.rs:854-889` — split `open_circuit` (`:869`)
   from `run_e2e` (`:870`) so circuit-open RTTs are not conflated with E2E TLS.
3. `crates/boreas-cli/src/daemon.rs:1231-1254` — after
   `connect_preconnected` (`:1231-1236`), after `open_e2e` (`:1248-1249`), and
   immediately before `drive_packet_path` (`:1254`). Serve-side counterparts:
   `:1132-1146`.
4. Early `ss -tin` sampler from Edge launch to connected, every 100–250 ms,
   retaining `SYN-SENT`/`ESTABLISHED` and `rtt/rto/retrans/cwnd`. The current
   smoke only samples before and after the transfer
   (`tools/release/netns_daemon_smoke.sh:349-443`), so a non-connected run has
   no transport evidence at all.

Diagnostic matrix, N >= 3, same binary and 1000 Mbps rate for handshake-only
runs: 400 ms / 0%, 400 ms / 0.1%, 400 ms / 1%, with 200 ms / 0.1%, 200 ms / 3%,
and 50 ms / 0% as controls. Extend only the diagnostic observation window (for
example 20 s) and mark it non-acceptance; do not report a longer wait as a pass.

Falsification criteria:

- 400 ms / 0% connects near 8.2–9 s and 400 ms / 1% near the same range:
  the 10–11 RTT handshake budget dominates; 1% loss adds little.
- 400 ms / 0% connects near 4 s but 400 ms / 1% exceeds 20 s: loss/RTO is the
  dominant cause, not the RTT count.
- both 400 ms / 0% and / 1% exceed 20 s: more than a 10-RTT handshake is
  involved; use the stage trace to name the stalled stage.

## Experiment B: measure the throughput trajectory

Purpose: decide whether the 200 ms / 0.1% failure is short-window slow start,
underlay loss/cwnd collapse, or per-packet serialization.

Run 1 / 8 / 32 MiB at 200 ms / 0.1% and 200 ms / 1%, N >= 3, unchanged 3 Mbps
floor. During the transfer, sample `ss -tin` every 250 ms on both namespaces and
derive per-interval `bytes_acked`/`bytes_received` deltas; retain cwnd, ssthresh,
retransmits, rto, delivery rate, `app_limited`, and `rwnd_limited`. Also capture
`tc -s qdisc show dev veth-core/veth-edge` and `ip -s link show btun0` so netem
backlog/drops and TUN drops are not guessed.

| Hypothesis | Discriminating observation | If supported |
| --- | --- | --- |
| H1 handshake budget | connect time scales with RTT at ~10–11 trips; data never starts in the window | measure stages; do not call it a throughput bug |
| H2 underlay loss / cwnd | cwnd collapses after retransmits, ssthresh drops, Edge/Core diverge | investigate loss recovery and socket behavior |
| H3 per-packet serialization | cwnd stays high, `app_limited`/`rwnd_limited` low, final `delivery_rate` high but average low | test batching/flush changes below |
| H4 short window | 1 MiB low, 8/32 MiB converge above 3 Mbps with monotonic cwnd growth | report short-window bias, not an SLA pass |

## Narrowest Rust modification candidates

Ranked by how directly they test the observations, not by expected win:

1. `crates/boreas-tunnel/src/packet_path.rs:901-921` — `outbound_once` writes
   one frame and calls `circuit.flush()` **per TUN packet** (`:917-919`). The
   narrow experiment is to flush at a drain boundary (for example after
   `read_packet()` returns `None`, or after a bounded batch), preserving the
   existing 2-byte framing. This directly tests H3 and the ~21–27% wire overhead
   visible in the 1 MiB/8 MiB byte counts, but adds latency risk and needs a
   bounded batch size.
2. `crates/boreas-cli/src/daemon.rs:1337-1418` — the loop performs one outbound
   step and one inbound step per iteration. A bounded multi-packet outbound
   drain would test whether per-packet loop/flush turnover is limiting. The loop
   already polls with zero timeout and has no per-packet sleep; do not re-add
   one.
3. `crates/boreas-tunnel/src/session.rs:39-45` — `READ_CHUNK = 8 KiB` and
   `MAX_PENDING_BYTES = 128 KiB`. Raising these to 64 KiB/1 MiB is an ingress
   batching test, but it changes memory bounds and must be kept inside the
   existing frame limit; do this only if periodic `ss` shows the receiver is the
   bottleneck.
4. `crates/boreas-tunnel/src/runtime.rs:252-257` — `configure` sets only
   `TCP_NODELAY`; it sets no `TCP_NOTSENT_LOWAT`, `SO_SNDBUF`, or `SO_RCVBUF`.
   Add those here only if H2/`ss` shows sender bufferbloat or a notsent backlog.
   `crates/boreas-tunnel/src/tcp_opts.rs` is descriptive policy, not a live
   socket option; changing it alone changes nothing.
5. Handshake reduction (session resumption, 0-RTT, or pipelining stages) belongs
   at `runtime.rs:117-139` and the OpenSSL session configuration, only if
   Experiment A shows the stage cost is the problem. That is security-sensitive
   and is not the first optimization.

Do not lower the 3 Mbps bound, enlarge the acceptance wait, alter netem
delay/loss, or treat one 8 MiB pass as stable evidence.