# Boreas (Βορέας)

<p align="center">
  <strong>Ultra-High-Performance Post-Quantum L3 Overlay Network</strong><br>
  <strong>超高性能抗量子三层虚拟互联网络</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Coming%20Soon-orange?style=flat-square" alt="Status: Coming Soon">
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square" alt="License: GPL-3.0">
  <img src="https://img.shields.io/badge/Language-Rust-dea584?style=flat-square" alt="Language: Rust">
  <img src="https://img.shields.io/badge/Security-ML--KEM--768%20%2B%20X25519-blue?style=flat-square" alt="Post-Quantum Security">
  <img src="https://img.shields.io/badge/Transport-Multi--Stream%20WSS-green?style=flat-square" alt="Transport">
</p>

---

## Status / 当前状态

> **English**: **`Coming Soon`** — *Boreas* is currently under active architecture validation and core engine development. Source code, static artifacts, and deployment guides will be made available upon initial milestone completion.
>
> **中文**：**`即将推出 (Coming Soon)`** —— *Boreas* 目前处于架构验证与核心引擎研发阶段。完整源码、静态发行产物及部署指引将在首个工程里程碑就绪后发布。

---

## Overview / 项目概述

### English
**Boreas** (named after the Ancient Greek god of the north wind, in family alignment with *Zephyr*) is an ultra-high-performance Layer 3 Overlay VPN engine engineered specifically for traversing CDN edge networks (AWS CloudFront, Cloudflare) and cross-continental high-latency links. 

Unlike generic full-mesh P2P systems burdened by excessive state-machine layers, background DHTs, and nested loopback context switches that saturate 1-vCPU VPS instances, Boreas is forged from the ground up in **Rust** with a single mandate: **achieving line-rate throughput and instantaneous speed-up under high latency with minimal CPU footprint**.

### 中文
**Boreas**（源自古希腊北风之神，与 *Zephyr* 西风呼应）是专为穿透 CDN 边缘网络（AWS CloudFront、Cloudflare）及跨洋跨洲高延迟链路打造的**底层极速三层 Overlay VPN 引擎**。

针对通用 P2P 组网在单核机器上层叠反代、系统调用风暴与上下文切换过载（在 1 vCPU 规格下吞吐卡死）的物理痛点，Boreas 采用纯 **Rust** 从零设计，专注于纯粹的底层网络互联：**以极低 CPU 消耗攻克跨洋高延时带宽时延积（BDP）瓶颈，实现毫秒级顶格起速与线速吞吐**。

---

## Key Architectural Highlights / 核心架构亮点

### 1. Dual-Layer Transport Engine / 双层极速传输架构
- **Parallel Tunnel Concurrency (多流并发条带化)**:
  - Dynamically establishes parallel WSS physical streams (default 4–8) to shatter the Bandwidth-Delay Product (BDP) bottleneck and bypass strict single-connection TCP window caps imposed by CDN edge servers.
  - **5-Tuple Flow Affinity (五元组流亲和调度)**: Packet striping based on `(SrcIP, DstIP, Proto, SrcPort, DstPort)` hashes ensures that packets belonging to the same internal flow stay strictly ordered, preventing TCP retransmissions while multi-stream aggregation saturates physical bandwidth within 0.5s.
- **In-Stream Micro-Framing Multiplexing (流内微帧多路复用)**:
  - Carries ultra-compact 4-byte frame headers (`StreamID: 2B + Length: 2B`) within each physical WSS tunnel, multiplexing L3 packets without the overhead of repetitive TCP handshakes.

### 2. Zero-Copy Kernel & Packet Batching / 零拷贝内核与批处理优化
- **Linux TUN Batching with GSO/GRO (`IFF_VNET_HDR`)**:
  - Leverages Linux Generic Segmentation/Receive Offload (`IFF_VNET_HDR`), allowing the kernel to aggregate packets into super-packets (up to 64KB) per I/O event.
  - Drops syscall frequencies by over 80% (from ~23,000 syscalls/sec down to <1,500/sec at peak load), eliminating the `sy + si` CPU bottleneck on 1-vCPU nodes.
- **Slab RingBuffer Zero-Allocation Pipeline**:
  - Employs pre-allocated ring buffers and unshared buffer pools (`bytes::BytesMut`), executing in-place cryptographic operations and direct Tokio async socket writes without per-packet heap allocation.

### 3. Native CDN-Ready TLS Termination / 内置原生 CDN TLS 终结
- **Direct Edge Ingress (彻底拔除 Nginx/Caddy 反代)**:
  - Native pure-Rust TLS termination (`rustls`) listening directly on public ports (`0.0.0.0:443` or custom origin ports).
  - Eliminates intermediate reverse proxies (Nginx / Caddy / cloudflared) and localhost socket loops, cutting intra-host context switches to absolute zero.
- **User-Supplied Certificate Mode (自备证书，保持内核轻量)**:
  - Users provide their own standard PEM certificates and keys (e.g., Cloudflare 15-year Origin CA certificate, self-signed certificates, or custom domain certs) without bloating the network binary with complex ACME / Let's Encrypt automation logic.

### 4. ZSL/2 Post-Quantum Hybrid Security / ZSL/2 混合后量子安全体系
- **Hybrid PQXDH Key Encapsulation**:
  - Combines classical **X25519** with **ML-KEM-768** (NIST FIPS 203 standard, Kyber768) via `HKDF-SHA256` key derivation, providing verifiable post-quantum forward secrecy against future harvest-now-decrypt-later adversaries.
- **Hardware-Accelerated Encryption & 0ms Silent Rekeying**:
  - Auto-selects **ChaCha20-Poly1305** or hardware-accelerated **AES-256-GCM** (AES-NI).
  - Automatically executes in-band silent key rotation (Rekey) every 1 GB of data or every 1 hour with zero disconnection and 0ms downtime.
- **RFC-005 Zero-Residency Ephemeral Join Tickets (一次性内存票据)**:
  - Hub exposes an ephemeral `/join/<token>` endpoint (256-bit token with a 15-minute TTL).
  - Single-use consumption burns the token immediately in memory, returning the node's assigned Virtual IP (VIP), subnet, and Hub public key, before atomically upgrading the connection into a multi-stream WSS data tunnel.

### 5. Symmetrical Node Topology / 对称节点架构
- **Single Unified Binary (单一二进制)**:
  - Does not enforce a rigid client-versus-server dichotomy. All nodes execute the exact same statically compiled binary.
  - Node roles are fluidly determined by configuration: listening on WSS (`listeners`), dialing outbound peers (`peers`), or concurrently doing both.
- **Seamless Lifecycle (一键入网与干净解绑)**:
  - Nodes join via an instant one-line command (`boreas join <url>`) and can cleanly detach (`boreas leave`), triggering active `NodeLeave` control frames that instantly purge routing tables and DNS entries across peers without orphaned routes.

### 6. Embedded Virtual Mesh DNS / 内置轻量虚拟内网 DNS
- Embedded asynchronous UDP/TCP DNS service bound solely to the internal gateway VIP (e.g. `10.20.0.1:53`).
- Dynamically resolves mesh node hostnames (e.g., `hk-halo.boreas` → `10.20.0.2`), transparently recursing external domains to the host's upstream DNS.
- *Strictly decoupled from any public media unlock or geo-routing DNS systems.*

---

## Topology Alignment / 拓扑定位

Boreas serves as the neutral, ultra-high-speed foundational L3 substrate. Users can seamlessly construct:
- **Radial Hub-and-Spoke Backbones**: Interconnecting cloud nodes across AWS, CloudFront, Aliyun, and regional data centers (HK, SG, JP, US, TW, AU).
- **Direct Multi-Point Interconnects**: Future-proof architecture supporting direct point-to-point mesh overlays without changing the underlying protocol primitives.

---

## License / 开源许可证

Licensed under the [GNU General Public License v3.0](LICENSE) (GPL-3.0). See `LICENSE` for details.
