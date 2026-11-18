# Netem next experiment: handshake budget vs transport ramp

Status: diagnostic design note for the next run, plus implemented
diagnostic-only helper subcommands. It does not change a threshold, does not
claim a root cause, and does not turn any existing red result green.

## Evidence boundary

Latest downloaded run evidence: performance run
[`44089808664`](https://github.com/Lanlan13-14/Boreas/actions/runs/44089808664),
workflow head `ff076a1`, tested source/binary
`7be5abff064229980c99420b6ccac735de6dcf7e`, backend run `44088534961`. The
downloaded job logs are
[`134061759830`](https://github.com/Lanlan13-14/Boreas/actions/runs/44089808664/job/134061759830)
(1 MiB then 8 MiB) and
[`134061759873`](https://github.com/Lanlan13-14/Boreas/actions/runs/44089808664/job/134061759873)
(strict 200 ms / 0.1% / 100 Mbps). The run completed failure: the 1 MiB sample
measured **2.439 / 2.305 Mbps** and the 8 MiB sample **2.879 / 2.556 Mbps**
(Edge -> Core / Core -> Edge), both below the unchanged 3 Mbps bound. The sender
phase fields (`connect_seconds`, `send_seconds`, `digest_seconds`) are in the
artifact and job logs; the table below uses those fields directly, not a model.

The historical table and numbers below come from run `43901434822` (tested
source `4ef5e37fd7b7d06712eb7ab4799019375bfa1b37`, backend `43899414586`); its
workflow head `02c958a` is not the tested source.

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

Latest paired diagnostic (run `44089808664`, same 200 ms / 0.1% / 100 Mbps
profile, unchanged gates and byte counts):

| Sample | Bytes | Edge -> Core | Core -> Edge | Bound | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| 1 MiB | 1048576 | 2.439 Mbps | 2.305 Mbps | 3 Mbps | fail |
| 8 MiB | 8388608 | 2.879 Mbps | 2.556 Mbps | 3 Mbps | fail |

Both samples are single short windows; they are not steady state, not an SLA and
not a root cause.

### The actual denominator, from the phase fields

The gate value is `throughput_mbps = bytes * 8 / (connect + send + digest)`.
`payload_send_mbps` is the separate send-only value
`bytes * 8 / send_seconds`. `digest_seconds` starts after
`shutdown(SHUT_WR)` and ends when the receiver's 64-byte digest returns, so it
includes the sender's tail drain and the receiver's EOF/hash interval, not just
a 64-byte RTT. The downloaded diagnostic job gives:

| Sample | Direction | connect s | send s | digest s | elapsed s | gate Mbps | send-only Mbps |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 MiB | Edge -> Core | 0.401473 | 2.205152 | 0.832798 | 3.439423 | 2.439 | 3.804 |
| 1 MiB | Core -> Edge | 0.401387 | 2.207256 | 1.029927 | 3.638569 | 2.305 | 3.800 |
| 8 MiB | Edge -> Core | 0.401401 | 17.656077 | 5.255351 | 23.312829 | 2.879 | 3.801 |
| 8 MiB | Core -> Edge | 0.401335 | 23.514992 | 2.334668 | 26.250995 | 2.556 | 2.854 |

The gate denominator contains 1.23–5.66 s of connect/tail-drain that the
send-only denominator excludes. For 1 MiB, send-only is 3.80 Mbps in both
directions while the gate reports 2.439 / 2.305. This is a denominator
sensitivity, **not** a throughput root cause: in the same run the 8 MiB
Core -> Edge send-only value is 2.854 Mbps, and the strict 1 MiB Edge -> Core
send-only value is 2.189 Mbps, both below 3. The 3 Mbps bound remains unchanged;
no field here replaces it.

Short-window results are also unstable across runs. The strict
200 ms / 0.1% / 100 Mbps job (`134061759873`) measured 1.545 / 2.199 Mbps gate
and 2.189 / 3.805 send-only; the 50 ms / 0% / 10 Mbps control
(`134061759963`) measured 4.646 / 4.622 gate and 6.836 / 6.882 send-only. At
200 ms, the 1 MiB Edge -> Core `send_seconds` was
2.205 s in the diagnostic sample and 3.832 s in the strict sample. Short-window
variance is therefore large; one pair cannot distinguish a fixed denominator
effect from transport or scheduling variance.

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
- Run `43901434822` failed 1 MiB but its same-source 8 MiB diagnostic passed one
  trial at 3.989 / 6.075 Mbps, so that single pair was not a fixed 3 Mbps
  ceiling. Run `44089808664` did not reproduce the 8 MiB pass: both samples
  stayed below 3 Mbps (1 MiB 2.439 / 2.305, 8 MiB 2.879 / 2.556). Across two
  runs the 8 MiB outcome is unstable; neither pass nor fail is steady state or
  acceptance, and this note attributes no cause.

## What the `stat` evidence can and cannot say

The only CPU evidence in the downloaded logs is the smoke's
`resource_evidence_source=linux-proc-stat-read-only` sampler. It reads
`/proc/<pid>/stat` and `/proc/<pid>/exe` every 100 ms for the daemon thread
group, so it excludes kernel softirq, veth/netem, TUN and probe-process CPU. It
reported 1.25–3.00% of one CPU: for the diagnostic 1 MiB window, 0.070 s core
and 0.050 s edge over 3.810 s; for the 8 MiB window, 0.350 s core and 0.390 s
edge over 26.480 s. Those low process percentages do not support a CPU
saturation explanation, but the sampler is coarse, narrow in scope and not a
per-packet measurement. A CPU-per-packet cost remains unproven. This note
records no root cause.

The sampler runs inside the probe window. Its 100 ms cadence is bounded but not
zero, and the later periodic `ss`/`tc`/`ip` telemetry in the current tree also
sits inside the same window. Their throughput cost was not separately measured.
They are neither a proven cause nor proven harmless; do not use their presence
to explain the red gate or to dismiss it. The `ss` before/after snapshots
bracket the probe workers and are captured outside the transfer window; the
in-window observer is the resource sampler (and, later, the periodic telemetry).

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

The 440898 8 MiB job also captured end snapshots (not periodic samples):
Core socket `cwnd:126 ssthresh:252`, `retrans:0/15`,
`bytes_retrans:10732`, `delivery_rate 4657976 bps`; Edge socket
`cwnd:130 ssthresh:93`, `retrans:0/11`, `bytes_retrans:13034`,
`delivery_rate 3655352 bps`. Both snapshot delivery rates are above 3 Mbps
while the gate averages are 2.879 / 2.556 Mbps, and both cwnd/ssthresh values
are low. That is consistent with loss/cwnd effects during the window, but two
snapshots cannot separate loss recovery, short-window slow start, or
per-packet serialization. No cause is assigned.

The 400 ms job has **no `ss` evidence**: `ss_before/after_*_status=
unmeasured:no-snapshot`, because the transfer never ran. Do not infer cwnd,
retransmits, or a transport cause for that case from this run.

These are only two snapshots bracketing the transfer. They cannot show whether
the 1 MiB average is slow start, an application-limited burst, or loss recovery.
The 8 MiB end state suggests loss-driven cwnd reduction in at least one
direction, but one trial cannot separate that from the short window.

## Periodic trajectory telemetry (implemented, diagnostic only)

The smoke starts two bounded samplers inside the disposable namespaces before
the daemons launch and stops them when the probe window closes. Every 250 ms
each records `ss -tin` for the fixed underlay pair (`bytes_acked`,
`bytes_received`, `cwnd`, `ssthresh`, `rto`, `retrans`, `unacked`, `rtt`,
`delivery_rate`); every fourth tick it also records `tc -s qdisc` drops,
overlimits, requeues and backlog plus `ip -s link` TUN RX/TX bytes and drops. A
non-connected run therefore still records what the kernel saw (for example
`SYN-SENT`), and the qdisc/TUN counters show whether the underlay itself dropped
or queued packets.

Bounds: at most 240 samples and 32 socket records per sample per namespace
(expected about 0.4 MiB, under 8 MiB worst-case NDJSON in the disposable work
directory), 360 `timeout`-capped commands per namespace (240 `ss` + 60 `tc` + 60
`ip`), and the process cannot outlive its 60 s deadline by more than one short
tick. Only about 30 summary lines per namespace reach the uploaded log. The
sampler overhead sits inside the measured probe window because sampling starts
before the daemons, so it perturbs the same run it observes; it changes no
threshold, wait, netem profile, byte count or gate and is never acceptance.

The summary compares per-namespace `bytes_acked` deltas and implied TCP rates
with the overlay `throughput_mbps`. That comparison is diagnostic only: TCP
payload carries TLS/WSS/relay framing, the windows are short, and a rate
difference is not by itself an attribution.

Still missing for H2/H3/H4: the N >= 3 matrix, the 32 MiB sample, phase
alignment between sampler ticks and the sender's `send_seconds`, and the
direct-TCP baseline runs described below. One diagnostic run cannot select a
hypothesis, and none of this note claims a root cause.

## Direct-TCP baseline subcommands (implemented, diagnostic only)

`tools/release/netns_overlay_perf.py` now exposes caller-invoked diagnostics.
No baseline run has been executed yet; this section describes the implemented
tool only. The modes are not wired into the smoke or workflow, they change no
threshold, byte count, wait or netem profile, and they never read
`BOREAS_MIN_THROUGHPUT_MBPS`.

- `baseline-receive LOCAL_IP` listens on that underlay address at port `18081`.
- `baseline-send LOCAL_IP PEER_IP` connects from `LOCAL_IP` to
  `PEER_IP:18081` and verifies the same SHA-256 digest.
- `compare LABEL OVERLAY_JSON BASELINE_JSON` prints both denominators and their
  ratios as key=value lines.

Both baseline roles use the same `CHUNK`, `BOREAS_PERF_BYTES` bound (1..64 MiB),
payload and SHA-256 check as the overlay probe, one connection and one attempt.
`BASELINE_TIMEOUT_SECONDS` is 30 s, the same as the overlay socket timeout, and
the port is distinct from the overlay's `18080`. The sender emits
`throughput_mbps` (connect-through-digest), `payload_send_mbps` (send-only),
`scope=underlay-direct-tcp-baseline`, `gate=not-applicable` and
`acceptance=never`. The sender writes one JSON object to stdout; the receiver
writes its JSON (including the digest) to stderr, so redirect both when saving
its output. Set the same `BOREAS_PERF_BYTES` for both roles.

Two arrangements are available:

1. **Same-namespace control.** Run both roles inside one namespace with the
   namespace's own underlay address:
   `baseline-receive 192.0.2.1` and `baseline-send 192.0.2.1 192.0.2.1`.
   The kernel routes this locally, so it bypasses the veth/netem path and the
   overlay; it tests the probe process, local TCP stack and hashing path.
2. **Cross-namespace underlay control.** Run `baseline-receive 192.0.2.1` in
   Core and `baseline-send 192.0.2.2 192.0.2.1` in Edge. This crosses the same
   veth pair and netem profile but bypasses the Boreas daemon, TUN and TLS.

Swap the roles for the Core -> Edge direction; one sender result covers only
one direction.

`compare` never applies a threshold and returns zero even when the overlay or
baseline value is missing or below 3. It prints `overlay_gate=unchanged` and
`baseline_compare_acceptance=never`, so a high baseline cannot turn a red
overlay result green. Ratios are `baseline / overlay` for both denominators; a
ratio above 1 means the baseline was faster than the overlay. `compare` also
prints the overlay `connect_seconds`, `send_seconds`, `digest_seconds` and the
connect-plus-digest share of `elapsed_seconds`, so the denominator effect is
visible from any saved sender JSON without re-deriving it. Pass `-` as
`BASELINE_JSON` to inspect an existing overlay result before a baseline run;
the baseline fields report `unmeasured` while the overlay phase fields remain
visible.

Interpretation is deliberately limited:

- same-namespace baseline near the overlay rate: the probe/host path is a
  candidate; do not blame the overlay before testing it;
- same-namespace baseline far above 3 Mbps but cross-namespace underlay near
  2.5 Mbps: the impaired TCP path and short window are sufficient to produce
  the red gate without overlay-specific overhead;
- cross-namespace underlay far above 3 Mbps: the overlay path is the
  differentiator and deserves the layer-by-layer work in Experiment B;
- a single baseline run cannot select a cause; use N >= 3 and the same byte
  count as the overlay sample being compared.

Example, after the namespaces exist (replace `$CORE_NS`/`$EDGE_NS` with the
live names; the smoke appends its PID and removes them at exit):

```bash
ip netns exec "$CORE_NS" python3 tools/release/netns_overlay_perf.py \
  baseline-receive 192.0.2.1 > baseline-core-rx.log 2>&1 &
ip netns exec "$EDGE_NS" python3 tools/release/netns_overlay_perf.py \
  baseline-send 192.0.2.2 192.0.2.1 > baseline-edge-to-core.json
python3 tools/release/netns_overlay_perf.py compare \
  edge_to_core perf-sender-edge.log baseline-edge-to-core.json
```

The smoke removes its namespaces at exit and does not call these modes, so a
future CI step needs a dedicated harness or must invoke the baseline before
cleanup. That invocation point is the remaining integration gap; this slice
does not edit the smoke or the workflow.

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
4. Early `ss -tin` sampling from Edge launch to connected, retaining
   `SYN-SENT`/`ESTABLISHED` and `rtt/rto/retrans/cwnd`. This is now implemented
   by the periodic trajectory telemetry above (250 ms cadence, started before
   the daemons); the remaining gap is aligning those ticks with the binary's
   stage trace.

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
floor. The periodic sampling above is now implemented for every smoke run:
`ss -tin` every 250 ms and `tc -s qdisc` / `ip -s link` every fourth tick on both
namespaces, summarized as per-namespace `bytes_acked`/`bytes_received` deltas
with cwnd, ssthresh, retransmits, rto and delivery rate. The N >= 3 matrix and
the 32 MiB sample remain future work; one diagnostic run cannot select H2, H3 or
H4.

Pair each overlay sample with the direct-TCP baseline controls above: a
same-namespace run isolates the probe/host path, and a cross-namespace underlay
run keeps the veth/netem path but removes the Boreas daemon/TUN/TLS. Compare
both denominators with `compare`; the 3 Mbps gate still applies only to the
overlay result. A baseline above 3 Mbps does not make the overlay pass, and a
baseline below 3 Mbps does not by itself identify the overlay as the cause.

The latest pair weakens H4 as a complete explanation: the 8 MiB sample rose
relative to 1 MiB (2.879 / 2.556 vs 2.439 / 2.305 Mbps) but still stayed below
the 3 Mbps bound, so it did not converge above the gate. That is still two short
windows, not a conclusion.

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

No root cause is established here. The connect/tail-drain denominator effect is
measured, but it does not explain the below-3 send-only directions; CPU per
packet, per-packet flush/serialization, loss/cwnd collapse and short-window bias
all remain unproven. Do not present any of them as the cause without the N >= 3
controls above.

Do not lower the 3 Mbps bound, enlarge the acceptance wait, alter netem
delay/loss, or treat one 8 MiB pass as stable evidence.
