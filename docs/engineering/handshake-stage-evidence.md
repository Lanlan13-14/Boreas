# Handshake stage evidence (2026-11-17)

Observed timer evidence only. This note changes no gate, threshold, retry or
wait, and makes no CPU, crypto, transport or throughput model.

## Provenance

| Item | Evidence |
| --- | --- |
| Performance run | [44085204578](https://github.com/Lanlan13-14/Boreas/actions/runs/44085204578), `workflow_dispatch`, workflow head `fcc179ab00d8e4b866c8acc8a30f7d87d2d41389`, conclusion **failure** |
| Diagnostic job | [134045796278](https://github.com/Lanlan13-14/Boreas/actions/runs/44085204578/job/134045796278), conclusion **failure**; step `Measure 1 MiB then 8 MiB without masking either result` failed, while `Report raw evidence and failure reasons` and `Upload diagnostic logs and raw evidence` succeeded |
| Source run | [43972354900](https://github.com/Lanlan13-14/Boreas/actions/runs/43972354900), conclusion **success**, head `0295cf86b08261aa57a8fecd3c21fb17be618692` |
| Checkout actually used by the diagnostic job | `0295cf86b08261aa57a8fecd3c21fb17be618692` (log: `diagnostic_source_sha=0295cf86...`, `diagnostic_source_run=43972354900`) |
| Binary artifact | `boreas-hop-node-linux-x86_64-43972354900`, artifact ID `14278689010`, archive digest `sha256:91f6a4e82c9d4f79b8ffcc28ed328cbc990cefce08729f0423da0516a849939d`; `sha256sum --check --strict SHA256SUMS` passed in the job |
| Raw diagnostic logs | [artifact 14329306431](https://github.com/Lanlan13-14/Boreas/actions/runs/44085204578/artifacts/14329306431) (`window-diagnostic-43972354900.zip`) |
| Timer opt-in | `BOREAS_DIAGNOSTIC_TIMING=1` on the diagnostic job only. `.github/workflows/rust-tls.yml` at `0295cf8` does **not** set it, so the source TLS run is provenance for the binary, not phase-timer evidence |

The same artifact was run twice, sequentially, under the same
`200 ms / 0.1% loss / 100 Mbps` profile: first 1 MiB, then 8 MiB.

## Emitted phase labels

`DiagnosticTimer` (`crates/boreas-tunnel/src/runtime.rs:57-85` at `0295cf8`)
reads `Instant::now()` at timer creation and writes
`boreas-diagnostic-timing phase=<static-label> elapsed_us=<integer>` when the
timer drops, only when the environment value is exactly `1`. The value is
truncated integer microseconds around the named function scope, so it includes
network waits under the netem profile; it is not CPU time or crypto service
time. The timers do not gate, retry or rewrite the handshake.

The checked-out smoke at `0295cf8` adds `report_diagnostic_timing()`
(`tools/release/netns_daemon_smoke.sh:113-133`), which copies only lines
matching these nine static labels to stdout, prefixed by `core` or `edge`:
`outer_tls`, `ws_handshake`, `inner_tls`, `session_handshake`,
`confirmation`, `circuit_open`, `e2e_tls`, `circuit_accept`,
`e2e_tls_accept`. Each sample emits ten lines because `confirmation` is
reported by both nodes.

Label scopes at `0295cf8`: edge `outer_tls` → `LinkClient::connect_preconnected`
around `outer.connect`; `ws_handshake` → `ws::client_handshake`; `inner_tls` →
`inner.connect`; `session_handshake` → `session::client_handshake`;
`circuit_open` → `open_circuit`; `e2e_tls` → `run_e2e`; `confirmation` →
`finish_e2e`/`confirm_e2e_application`. Core `circuit_accept` →
`accept_circuit`; `e2e_tls_accept` → `run_e2e`; `confirmation` →
`finish_e2e`/`confirm_e2e_application`.

## Measured values

Filtered `elapsed_us` from job `134045796278`; both samples:

| Phase (node) | 1 MiB sample | 8 MiB sample |
| --- | ---: | ---: |
| `circuit_accept` (core) | 400346 | 400370 |
| `e2e_tls_accept` (core) | 403512 | 403585 |
| `confirmation` (core) | 401436 | 401358 |
| `outer_tls` (edge) | 423259 | 424511 |
| `ws_handshake` (edge) | 400524 | 400519 |
| `inner_tls` (edge) | 802980 | 802865 |
| `session_handshake` (edge) | 800427 | 800534 |
| `circuit_open` (edge) | 400318 | 400338 |
| `e2e_tls` (edge) | 404706 | 404696 |
| `confirmation` (edge) | 65 | 63 |

The largest same-label change between the two samples is `1252 µs`
(`edge outer_tls`); every other label changes by at most `115 µs`. These are
per-node scopes with the same wire exchange observed from both ends; do not add
or compare core and edge values as one duration.

The harness startup block (`startup_timing_stage_lines=16`) was identical in
both samples: Core launch → first `btun0` `60 ms`; Edge launch → first `btun0`
`60 ms`; Edge launch → connected-result `4110 ms`; Edge TUN → connected-result
`4050 ms`; connected wait `4010 ms`. At the connected-result boundary the
classification was `available-not-connected` for Core and `available-connected`
for Edge. These are harness-observed boundaries under the netem profile, not
crypto or CPU time.

## Sample outcomes

The diagnostic job failure is the existing `BOREAS_MIN_THROUGHPUT_MBPS=3.000`
assertion on the 1 MiB sample, not a timer-collection failure.

| Sample | Bytes | edge → core | core → edge | Smoke result |
| --- | ---: | ---: | ---: | --- |
| `original_1mib` | 1048576 | 1.737 Mbps | 1.437 Mbps | failed (`smoke_exit=1`) |
| `longer_8mib` | 8388608 | 6.015 Mbps | 6.010 Mbps | passed (`smoke_exit=0`) |

The 1 MiB sender JSON reports `elapsed_seconds` `4.829673` (edge → core) and
`5.836159` (core → edge). Both samples report `0.000%` ICMP loss; average/max
were `400.302/400.343 ms` and `400.292/400.347 ms` respectively. No causal
claim is made from these two samples. The job records
`diagnostic_caveat=single short window, not steady state and not an SLA`.

## Old run: missing-filter note only

Run [43971162046](https://github.com/Lanlan13-14/Boreas/actions/runs/43971162046)
job [133663463009](https://github.com/Lanlan13-14/Boreas/actions/runs/43971162046/job/133663463009)
(conclusion **failure**) used source run
[43969887087](https://github.com/Lanlan13-14/Boreas/actions/runs/43969887087)
at `d6ddb19`. Its 1 MiB sample failed and its
8 MiB sample passed. Its checked-out smoke has `report_startup_timings()` and
no `report_diagnostic_timing()`; phase lines appeared only in the 1 MiB failure
path because the failure trap prints raw `core.err`/`edge.err`. Its successful
8 MiB log contains no `boreas-diagnostic-timing` line. That job is therefore not
complete filtered timer evidence; the new job above is.

## Next experiment (function level)

The current probe's denominator includes pre-data work:
`tools/release/netns_overlay_perf.py:sender()` sets `started = time.monotonic()`
before `socket.create_connection()` and computes `elapsed_seconds` /
`throughput_mbps` after the receiver's digest reply (`0295cf8` lines 47-75).
The reported number is therefore sender wall time for connect + handshake +
payload + digest reply, not payload-only time.

Next experiment, changing only the diagnostic probe:

1. In `sender()`, record `t_connect` immediately after
   `socket.create_connection()` returns, `t_sent` after the send loop and
   `shutdown(SHUT_WR)`, and `t_done` after the digest reply. Emit
   `connect_seconds`, `send_seconds`, `digest_seconds`,
   `payload_mbps = sent * 8 / send_seconds`, and keep the existing
   `end_to_end_mbps`.
2. In `receiver()`, record `accept_to_first_byte_seconds` and
   `receive_seconds` (accept → EOF) and emit them with the received byte count;
   keep the existing digest check.
3. Run the same `200 ms / 0.1% / 100 Mbps` profile with 1, 2, 4 and 8 MiB and
   at least three repetitions per size, same binary and source. Keep every
   sample, including failures, and change no gate or threshold.

This measures the pre-data and payload intervals separately; it does not assume
which one dominates.
