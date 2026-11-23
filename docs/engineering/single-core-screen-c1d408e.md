# Single-core diagnostic screen — c1d408e

Run: https://github.com/Lanlan13-14/Boreas/actions/runs/45187121489
Frozen baseline: b240461a5ffbd5e54a39dcdd6d5bbed5c969427c
Candidate: c1d408e4dc2709427f8c63a176bc7b5a78b4cb33
Runner: Intel Xeon 6975P-C, four allowed logical CPUs.

**Overall FAILED.** Ordinary-TUN A failed exact-byte comparison. The captured
packet has a kernel-generated nonzero IPv4 ID while the raw socket fixture
expected ID=0; the IP header checksum changed accordingly. Correction 24e7d54
specifies a nonzero fixture ID, retaining the exact-byte assertion. That
correction needs its own A run before marking the fixture validated.

OpenSSL capability verifier, Clippy, release diagnostic build and 319 Rust
unit/integration tests passed. B and C passed their own diagnostic correctness
checks. This is NOT completion of the supplied single-core gigabit design.

## B: real authenticated record chain

Outer: TLS 1.3 TLS_AES_256_GCM_SHA384. Hop/E2E: TLS 1.3,
X25519MLKEM768, ML-DSA-65, AES-256-GCM, no resumption/0-RTT (reported by the
actual established adapters). Both production peer binding and `PacketPath`
are used, replacing only test host I/O.

Each direction transported 16,384 MTU=1360 packets with exact ordered content
and checksum validation. Counter results for BOTH client/server sender roles:

| Batch requested | E2E records | Hop records | Outer records | Raw socket successful writes |
|---:|---:|---:|---:|---:|
| 1 | 16,384 | 16,384 | 16,384 | 16,384 |
| 4 | 4,096 | 4,096 | 4,096 | 4,096 |
| 8 | 2,048 | 2,048 | 2,048 | 2,048 |
| 11 | 1,490 | 1,490 | 1,490 | 1,490 |

This establishes the fixture can distinguish actual record/write amortization
from a flush count. It does NOT establish that the real TUN daemon sustains
11-packet batches, or that any production optimization has been implemented.
B runs are sub-second, include synthetic source/sink validation CPU and are
not steady-state thermal numbers; raw costs are retained in `tier-b.log`.

## C: two short observations per version/profile/mode

Each endpoint's entire observed thread set pinned to one logical CPU.
Separate mode uses a third CPU shared by the two Python generators (its direct
baseline is ~6 Gbps and differs from colocated mode ~11.3 Gbps at low RTT).
Colocated mode pins each generator to its local endpoint CPU. Softirq/steal
snapshots are retained, but complete machine/IRQ 1-vCPU isolation is unproven.

Values below are application receiver Mbps (decimal), minimum–maximum of the
TWO **5-second** observations after **2-second** warm-up; directions run
separately. Neither interval meets the required 15+60-second protocol.

| Profile | Version | Generator placement | Edge→Core | Core→Edge |
|---|---|---|---:|---:|
| low RTT | pre6 | separate | 3584.675–3607.010 | 3340.420–3402.882 |
| low RTT | candidate | separate | 3526.020–3547.108 | 3359.370–3388.113 |
| low RTT | pre6 | colocated | 2709.325–2732.862 | 2741.940–2786.136 |
| low RTT | candidate | colocated | 2689.724–2720.287 | 2709.081–2750.002 |
| nominal 68ms RTT | pre6 | separate | 2200.192–2202.465 | 932.177–967.587 |
| nominal 68ms RTT | candidate | separate | 2113.352–2199.275 | 1064.312–1314.563 |
| nominal 68ms RTT | pre6 | colocated | 871.295–1004.180 | 509.820–1323.829 |
| nominal 68ms RTT | candidate | colocated | 929.260–1032.349 | 581.402–732.019 |

All 64 single-direction application transfers (direct and overlay) completed
and matched exact byte count + streamed SHA-256. The old post-hook smoke also
ran in each fixture with its original criteria. Full-diagnostic C passing
means transfers and measurement completed, **not** that every result exceeded
1000 Mbps.

There is **no performance optimization in this candidate**; do not attribute
noisy differences to the diagnostic code. The 68ms colocated results fail to
establish stable bidirectional gigabit even on this Intel runner. They provide
no EPYC/7003 evidence. Final 15-minute per-minute gigabit, small-packet/p99,
fixed-load CPU/RSS improvements and short-I/O fault matrix are still absent.

Raw evidence: `/var/minis/workspace/evidence-45187121489` and the run artifact.
The original production daemon, original netns smoke, original performance
workflow and gates are unchanged. main/release are not modified or deployed.
