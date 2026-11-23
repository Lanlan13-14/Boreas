# Single-core diagnostics: implementation status

This branch implements **diagnostics, not a gigabit claim**. Baseline is frozen
at pre.6 `b240461a5ffbd5e54a39dcdd6d5bbed5c969427c`. The original smoke,
performance workflows, TLS policy, TUN defaults and 256 KiB unsent-watermark
are unchanged. No GSO, lanes, offload or helper crypto worker is enabled.

## What runs

- A: real ordinary Linux TUN in private network+mount namespaces; 1360/128-byte
  checksummed TCP/IP packets; both directions, independent generator CPU,
  bounded 32-packet credits, exact ordered byte checks, thread CPU seconds,
  pps and packet API calls. This includes fixture/validation costs and does not
  pretend API calls are measured syscalls. Cycles are explicitly unavailable.
- B: opt-in ignored integration test reusing real policy-pinned signed PKI,
  verified outer TLS, WSS, strict pq768 hop and E2E confirmation, and the
  production `PacketPath`. Client/server on separate allowed logical CPUs,
  batches 1/4/8/11, both directions. Synthetic host source/sink exists only in
  the integration test. Exact bytes, sequence and TCP checksum checked.
- `record-diagnostics` is off in normal/release daemon builds. When enabled,
  scoped thread-local counters collect Circuit/FrameIo/WebSocket writes,
  streaming E2E/hop/outer ciphertext record counts and actual raw socket read/
  write sizes. Flush is never reported as a syscall. Handshake facts printed
  from the actual established TLS adapters; no key/certificate data retained.
- C: exact baseline/candidate built with the same release profile and backend;
  alternating pre6/candidate/candidate/pre6, first low RTT then 68 ms nominal
  RTT (34 ms per endpoint, no loss or rate ceiling). One flow, one direction
  at a time. Both endpoint control/status and forwarding threads bound to the
  endpoint CPU, sampled every 250 ms. Separate-generator mode is explicitly
  unavailable on <3-CPU runners; colocated-generator mode is separate. Raw
  snapshots preserve thread CPU, RSS, system CPU/steal and softirq evidence.
  The existing full-duplex smoke runs afterward with its original thresholds.

## Not yet delivered / not certified

This first screen is intentionally short (2 s warm-up + 5 s observation).
It is **not** the five 15+60-second pairs or final 15-minute thermal test.
No optimization has been attributed, no EPYC/7003 result is inferred from an
Intel runner, and no real-world link capacity is promised. Affinity checks do
not by themselves prove softirq isolation or a complete 1-vCPU machine budget.
Python generators/digest verification and A/B source/sink validation consume
CPU; they must be distinguished from production work when reading costs.

Still needed after the screening fixture is validated: bounded short-I/O
transport fault matrix; per-operation blocking/runtime classification;
intermediate TCP_INFO telemetry and negotiated cipher summaries in C; syscall
and CPU hotspot attribution; fixed-load CPU/RSS/p99 comparisons; long paired
and minute-by-minute tests; and evidence-led fast-path changes with all
required differential security tests. The existing security suite runs, but
that does not imply every new fault case requested by the design is covered.

## Run and evidence

The independent `Single-core capacity diagnostics` workflow runs on this work
branch and supports manual dispatch once discoverable. Its artifact preserves
all logs including failures. Existing acceptance jobs and `gates.json` are not
edited. Build/test are Actions-only; no local cargo/OpenSSL compilation.

Local checks before first push: Python diagnostic unit/socket tests 7 passed,
1 explicitly skipped (`/proc` denied by Android sandbox); legacy overlay probe
40 tests passed. Rust and real TUN results must come from the linked Actions
run before reporting them as validated.
