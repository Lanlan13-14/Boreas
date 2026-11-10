# Boreas

Boreas is a lightweight Layer 3 VPN over WebSocket with post-quantum encryption, designed for CDN traversal and high-latency links.

Boreas 是一个基于 WebSocket 传输并支持后量子加密的轻量级三层 VPN，专为穿透 CDN 边缘与高延迟长链路设计。

---

## Status / 项目状态

Coming Soon (Under development) / 开发中（即将推出）

Architecture design and protocol specifications are finalized. The core engine and test suites are currently being built.

架构设计与协议规范已完成，核心引擎与测试套件正在开发中。

---

## Motivation / 背景

Running traditional full-mesh P2P VPNs over TCP or WebSocket on low-resource instances (such as 1 vCPU VPS) often incurs high CPU overhead. The combination of multi-layer encapsulation, user/kernel context switches, and nested reverse proxies (e.g. Nginx, Caddy, or cloudflared) can significantly limit throughput. Furthermore, single TCP streams over cross-continental links often suffer from Bandwidth-Delay Product (BDP) constraints and small buffer windows.

Boreas is designed to solve these specific constraints with a single, standalone binary written in Rust.

在低配实例（如 1 vCPU VPS）上通过 TCP 或 WebSocket 运行传统全网格 P2P 组网时，常因多层封装、频繁的上下文切换以及叠加外部反代（如 Nginx、Caddy 或 cloudflared）而产生高 CPU 占用，导致吞吐受限。此外，跨洋高延迟链路下的单条 TCP 连接也容易受带宽时延积（BDP）和较小窗口限制而无法有效利用带宽。

Boreas 采用纯 Rust 编写为单独立二进制，旨在针对这些特定约束提供轻量、高效的解决方案。

---

## Key Features / 主要特性

### 1. Transport / 传输设计
- **Multi-Stream Pooling (多流并发)**: Establishes parallel WSS connections to improve throughput on high-latency links, using 5-tuple hashing to keep packets of the same flow in order.
  通过并行建立多条 WSS 连接改善高延迟链路吞吐，利用五元组哈希确保同一数据流的包序一致。
- **In-Stream Multiplexing (流内复用)**: Multiplexes packets within connections using a minimal 4-byte header (`StreamID` and `Length`), avoiding repetitive handshakes.
  在单连接内部通过 4 字节紧凑帧头（`StreamID` 与 `Length`）复用虚拟流，减少握手损耗。

### 2. Performance / 性能优化
- **Single Binary with Native TLS (单二进制与内置 TLS)**: Native TLS termination (`rustls`) listening directly on public ports with user-provided certificates. No external reverse proxy required.
  基于 `rustls` 原生终结 TLS，直接监听公网端口（用户提供证书），无需额外前置 Nginx 或 Caddy。
- **Packet Batching (数据包批处理)**: Supports Linux TUN `IFF_VNET_HDR` and GSO/GRO to process aggregated packets, reducing syscall frequency under high throughput.
  支持 Linux TUN `IFF_VNET_HDR` 与 GSO/GRO 大包批处理，降低高吞吐场景下的系统调用频率。
- **Buffer Reuse (内存重用)**: Uses pre-allocated memory buffers (`bytes::BytesMut`) to minimize per-packet heap allocations.
  基于预分配缓冲池减少每个数据包的内存分配开销。

### 3. Security / 安全与认证
- **Hybrid Post-Quantum Key Exchange (混合后量子密钥协商)**: Combines X25519 and ML-KEM-768 (FIPS 203) for post-quantum forward secrecy, derived via HKDF-SHA256.
  结合 X25519 与 ML-KEM-768（FIPS 203），通过 HKDF-SHA256 派生会话密钥，具备抗量子前向安全。
- **Authenticated Encryption (对称加密与轮换)**: Supports ChaCha20-Poly1305 and AES-256-GCM, with periodic in-band key rotation (rekeying).
  支持 ChaCha20-Poly1305 与 AES-256-GCM，支持传输过程中定时进行带内密钥轮换。
- **Ephemeral Join Links (一次性入网链接)**: Supports one-time invite tokens with a short TTL, consumed directly in memory without saving plaintext credentials to disk.
  支持短有效期的一次性入网 Token，内存验证即焚，避免明文静态凭据长期落盘。

### 4. Topology & Management / 拓扑与管理
- **Symmetrical Nodes (对称节点)**: A single binary handles both listening (`listeners`) and dialing (`peers`). Nodes can act as hubs, spokes, or both.
  全网统一二进制，通过配置监听（`listeners`）或主动连接（`peers`）决定运行行为，既可作汇聚点也可作边缘节点。
- **Internal DNS (内置内网 DNS)**: Embedded DNS resolver listening on the private gateway IP to resolve node hostnames to virtual IPs (`*.boreas`). Fully isolated from public DNS or media unblock services.
  仅监听内网虚拟网关 IP，用于将节点主机名解析为虚拟 IP（`*.boreas`），与任何外部公共 DNS 或媒体解锁项目完全隔离。
- **Clean Lifecycle (便捷生命周期)**: One-command join and clean exit (`leave`), immediately notifying connected peers to clear routes and internal DNS mappings.
  支持一键加入与主动解绑退出（`leave`），退出时通知对端即时清空路由表与内网 DNS 映射。

---

## License / 开源许可证

Licensed under the [GNU General Public License v3.0](LICENSE) (GPL-3.0). See `LICENSE` for details.
