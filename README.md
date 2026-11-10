# Boreas

[English](#english) | [简体中文](#简体中文)

---

## English

Boreas is a lightweight Layer 3 VPN over WebSocket with post-quantum encryption, designed for CDN traversal and high-latency links.

### Status

**Coming Soon (Under active development)**

Architecture design and protocol specifications are finalized. The core engine and test suites are currently being built.

### Motivation

Running traditional full-mesh P2P VPNs over TCP or WebSocket on low-resource instances (such as 1 vCPU VPS) often incurs high CPU overhead. The combination of multi-layer encapsulation, user/kernel context switches, and nested reverse proxies (e.g., Nginx, Caddy, or cloudflared) can significantly limit throughput. Furthermore, single TCP streams over cross-continental links often suffer from Bandwidth-Delay Product (BDP) constraints and small buffer windows.

Boreas is designed to address these constraints with a standalone binary written in Rust.

### Key Features

#### 1. Transport
- **Multi-Stream Pooling**: Establishes parallel WSS connections to improve throughput on high-latency links, using 5-tuple hashing to keep packets of the same flow in order.
- **In-Stream Multiplexing**: Multiplexes packets within connections using a minimal 4-byte header (`StreamID` and `Length`), avoiding repetitive handshakes.

#### 2. Performance
- **Single Binary with Native TLS**: Native TLS termination (`rustls`) listening directly on public ports with user-provided certificates. No external reverse proxy required.
- **Packet Batching**: Supports Linux TUN `IFF_VNET_HDR` and GSO/GRO to process aggregated packets, reducing syscall frequency under high throughput.
- **Buffer Reuse**: Uses pre-allocated memory buffers (`bytes::BytesMut`) to minimize per-packet heap allocations.

#### 3. Security
- **Hybrid Post-Quantum Key Exchange**: Combines X25519 and ML-KEM-768 (FIPS 203) for post-quantum forward secrecy, derived via HKDF-SHA256.
- **Authenticated Encryption**: Supports ChaCha20-Poly1305 and AES-256-GCM, with periodic in-band key rotation (rekeying).
- **Ephemeral Join Links**: Supports one-time invite tokens with a short TTL, consumed directly in memory without saving plaintext credentials to disk.

#### 4. Topology & Management
- **Symmetrical Nodes**: A single binary handles both listening (`listeners`) and dialing (`peers`). Nodes can act as hubs, spokes, or both.
- **Internal DNS**: Embedded DNS resolver listening on the private gateway IP to resolve node hostnames to virtual IPs (`*.boreas`). Fully isolated from public DNS or media unblock services.
- **Clean Lifecycle**: One-command join and clean exit (`leave`), immediately notifying connected peers to clear routes and internal DNS mappings.

### License

Licensed under the [GNU General Public License v3.0](LICENSE) (GPL-3.0). See `LICENSE` for details.

---

## 简体中文

Boreas 是一个基于 WebSocket 传输并支持后量子加密的轻量级三层 VPN，专为穿透 CDN 边缘与高延迟长链路设计。

### 项目状态

**开发中（即将推出 / Coming Soon）**

架构设计与协议规范已完成，核心引擎与测试套件正在本地开发与验证中。

### 背景与初衷

在低配实例（如 1 vCPU VPS）上通过 TCP 或 WebSocket 运行传统全网格 P2P 组网时，常因多层封装、频繁的系统调用与上下文切换、以及叠加外部反代（如 Nginx、Caddy 或 cloudflared）而产生高 CPU 占用，导致吞吐受限。此外，跨洋高延迟链路下的单条 TCP 连接也容易受带宽时延积（BDP）和较小窗口限制而无法有效利用带宽。

Boreas 采用纯 Rust 编写为单独立二进制，旨在针对这些特定约束提供轻量、高效的解决方案。

### 主要特性

#### 1. 传输机制
- **多流并发条带化**：通过并行建立多条 WSS 连接改善高延迟链路吞吐，利用五元组哈希确保同一数据流的包序一致，避免 TCP 重传。
- **流内微帧复用**：在单连接内部通过 4 字节紧凑帧头（`StreamID` 与 `Length`）复用虚拟流，减少重复握手损耗。

#### 2. 性能优化
- **单独立二进制与原生 TLS**：基于 `rustls` 原生终结 TLS，直接监听公网端口（用户提供证书），无需额外前置 Nginx 或 Caddy。
- **数据包批处理**：支持 Linux TUN `IFF_VNET_HDR` 与 GSO/GRO 大包批处理，降低高吞吐场景下的系统调用频率。
- **缓冲池复用**：基于预分配缓冲池减少每个数据包的内存分配开销。

#### 3. 安全体系
- **抗量子混合密钥协商**：结合 X25519 与 ML-KEM-768（FIPS 203），通过 HKDF-SHA256 派生会话密钥，具备抗量子前向安全。
- **认证加密与带内轮换**：支持 ChaCha20-Poly1305 与 AES-256-GCM，支持传输过程中定时进行带内密钥轮换（Rekey）。
- **一次性入网凭据**：支持短有效期的一次性入网 Token，内存验证即焚，避免明文静态凭据长期落盘。

#### 4. 拓扑与运维
- **对称节点模型**：全网统一二进制，通过配置监听（`listeners`）或主动连接（`peers`）决定运行行为，既可作汇聚点也可作边缘节点。
- **内置私有 DNS**：仅监听内网虚拟网关 IP，用于将节点主机名解析为虚拟 IP（`*.boreas`），与任何外部公共 DNS 或媒体解锁项目完全隔离。
- **便捷生命周期**：支持一键加入与主动解绑退出（`leave`），退出时通知对端即时清空路由表与内网 DNS 映射。

### 开源许可证

本项目采用 [GNU General Public License v3.0](LICENSE) (GPL-3.0) 许可证。详情请参阅 `LICENSE` 文件。
