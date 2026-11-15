# Boreas

Boreas 是一个用 Rust 编写的**零 UDP 三层（L3 TUN）加密互联隧道**，核心架构采用**标准外层 TLS 1.3 + RFC 6455 WebSocket（WSS）承载 + 双层内层 TLS 1.3（`X25519MLKEM768` 后量子混合密钥交换 + `ML-DSA-65` 身份证书）**。

业务 IP 报文在进入公网前依次经过三层封装与认证：
1. **外层承载（Outer TLS 1.3 + Binary WSS）**：纯 TCP/HTTPS WebSocket 二进制流，零 UDP 端口依赖，可直连公网源站或穿越反向代理与标准 WebSocket 链路。
2. **逐跳会话层（Hop Inner TLS 1.3，`pq768`）**：在 WebSocket 字节流之上建立基于 OpenSSL 3.6+ 的 `X25519MLKEM768` + `ML-DSA-65` 双向认证（mTLS），强制校验证书公钥与离线双签（`Ed25519 + ML-DSA-65`）`NodeIdentity` 的绑定关系。
3. **端到端加密层（E2E TLS 1.3，`e2e-required`）**：在逐跳会话的 `RelayCircuit` 内再建立一层端点间 `X25519MLKEM768` + `ML-DSA-65` mTLS 电路并绑定 Linux `/dev/net/tun`；即使未来经过不可信中继节点，中继也无法解密业务载荷。

---

## 当前能做什么 / 还不能做什么（`v0.1.0-pre.3`）

Boreas 当前处于**开发预发布阶段**（最新可用预发布版为 `v0.1.0-pre.3`），尚未通过正式生产发布审批（[`docs/engineering/gates.json`](docs/engineering/gates.json) 中 `production_approved: false`）。请按以下真实边界评估使用：

### 已可真机运行的能力
- **离线四权分离 PKI 签发与验签**：支持在离线管理端通过 `boreas pki` 初始化根信任锚（`roots.cbor`），分离签发节点 `ML-DSA-65` 证书、双签 `NodeIdentity`（`local.signed`）与有界有效期状态快照（`status.signed`），零在线 CA 依赖、禁止 TOFU（首次连接盲信）。
- **跨公网双机点对点 L3 隧道（Linux）**：预编译静态二进制 `boreas-linux-x86_64-musl-pq768` 支持在两台公网 Linux 主机之间建立 `Core <-> Edge`（`suite = "pq768"` + `security_mode = "e2e-required"`）真实 `/dev/net/tun` 隧道，按永久槽位 VIP（如 `10.20.1.1 <-> 10.20.1.2`）双向转发 IPv4 流量，并自动静默丢弃宿主机发往 TUN 口的非对端本地杂包。
- **状态新鲜度保护与实时观测**：守护进程运行期持续核验 `status.signed` 时效（过期自动阻断业务转发 fail-closed），并提供基于 `SO_PEERCRED` 同 UID 校验的 `control.sock` 供 `boreas ctl status` / `boreas status` 查询实时连接与收发包计数。

### 尚未完成 / 已知限制
- **单线程轮询数据面性能限制**：`v0.1.0-pre.3` 守护进程数据面仍为单线程串行轮询，跨公网实测吞吐约 **0.7–1.2 Mbps**、附加约 **+27 ms** 延迟，多线程异步/双工优化正在推进中。
- **拓扑与控制面演进中**：当前仅支持 `1 Core <-> 1 Edge` 点对点转发；跨多 Core 多跳网格路由收敛、自动故障切换（Failover）、Edge 直连（DIR）及内建权威 DNS 运行时（`[dns].tcp`）尚未打通。
- **运维自动化与跨平台范围**：生产级自动化证书/状态快照轮换与完整 `boreas-supervisor` 在线热升级闭环尚未就绪；守护进程（`boreas daemon`）目前仅支持 Linux（Windows Wintun 与 macOS `utun` 仅完成底层设备库切片，Release 中的五平台 `.tar.gz`/`.zip` 基础归档不含 OpenSSL 3.6+ 后端）。
- **24 项正式版门禁推进中**：包括独立密码学审计（`G-EXTERNAL-REVIEW`）、双 TLS 栈互操作（`G-CRYPTO`）、长稳资源预算（`G-RESOURCE`）在内的 [24 项生产门禁](docs/engineering/gates.json) 仍为 `open`，请勿用于承载高敏生产业务。

---

## 5 分钟快速开始（Linux x86_64）

从 [GitHub Releases (`v0.1.0-pre.3`)](https://github.com/Lanlan13-14/Boreas/releases/tag/v0.1.0-pre.3) 下载预编译的全静态后量子守护进程二进制 `boreas-linux-x86_64-musl-pq768`（内嵌静态链接的 OpenSSL 3.6.5，不依赖宿主机 `glibc` 或系统 `libssl`）并校验 SHA-256：

```bash
VERSION="v0.1.0-pre.3"
BASE_URL="https://github.com/Lanlan13-14/Boreas/releases/download/${VERSION}"

# 1. 下载 Linux x86_64 静态 pq768 二进制与校验和清单
curl -fLO "${BASE_URL}/boreas-linux-x86_64-musl-pq768"
curl -fLO "${BASE_URL}/SHA256SUMS-PRE3"

# 2. 校验 SHA-256 完整性（预期输出：boreas-linux-x86_64-musl-pq768: OK）
grep '  boreas-linux-x86_64-musl-pq768$' SHA256SUMS-PRE3 | sha256sum -c -

# 3. 安装到系统路径并检查 pq768 后端能力
sudo install -m 0755 boreas-linux-x86_64-musl-pq768 /usr/local/bin/boreas
boreas doctor
```

`boreas doctor` 输出包含 `"status":"pre_release_pq768_e2e"` 与 `"daemon":true,"tls_backend":true` 即表示二进制就绪。

> **下一步直达**：请打开 **[双机公网实战部署教程（`docs/deployment/README.md`）](docs/deployment/README.md)**，按步骤完成离线 PKI 签发、`config.toml` 配置、Core/Edge 隧道拉起与单机 `netns` 本地演练。

---

## 常用 CLI 命令速查表

> 注：表中标记 **`[pq768]`** 的子命令需要启用了 `--features openssl-inner-tls` 的二进制（如 `boreas-linux-x86_64-musl-pq768`）；无 TLS 后端的基础 CLI 构建调用它们会以退出码 `2` 拒绝执行。

| 命令 | 用途说明 |
|---|---|
| `boreas doctor` / `boreas self-check` | 输出当前二进制编译集成能力 JSON（是否包含 `daemon`、`tls_backend`、`control_socket`） |
| `boreas config-check <config.toml>` | 校验 `0600` 权限与 `version = 1\|2` 静态配置策略，输出脱敏 JSON |
| `boreas config-migrate <legacy.toml>` | 将旧版 `version = 1` 配置转换为规范 `version = 2` TOML 输出至 stdout（不改写原文件） |
| `boreas pki init-ca --ca-dir <DIR> [--net-id <32HEX>] [--generation <N>] [--validity-days <1..3650>]` | **`[pq768]`** 初始化离线 `NetworkRoot`、`IdentityAuthority`、`StatusSigner`、外层 TLS CA 与 `roots.cbor` |
| `boreas pki issue-node --ca-dir <DIR> --out-dir <DIR> --role <core\|edge> --home-core <1..16> --vip-octet <1..251> [--generation <N>] [--validity-hours <N>] [--outer-san <DNS>]` | **`[pq768]`** 签发单节点密钥、ML-DSA-65 身份证书、`local.signed` 与初始 `status.signed` |
| `boreas pki sign-status --ca-dir <DIR> --out <FILE> --sequence <N> [--ttl-seconds <1..86400>]` | **`[pq768]`** 使用离线 `StatusSigner` 签发/续期网络状态快照（TTL 最长 24 小时） |
| `boreas pki verify-bundle --material-dir <DIR> [--roots <FILE>] [--require-peer]` | **`[pq768]`** 离线全链路校验节点材料包（根信任锚、证书公钥绑定、`peer.signed` 与状态时效） |
| `boreas daemon serve --config <FILE> --material-dir <DIR> --listen <IP:PORT> [--ws-path </tunnel>] [--tun-name <NAME>] [--mtu <1280..1400>]` | **`[pq768, Linux]`** 启动 Core 服务端守护进程，监听 WSS 入站并绑定真实 TUN 网卡 |
| `boreas daemon connect --config <FILE> --material-dir <DIR> [--connect <IP:PORT>] [--tls-name <DNS>] [--ws-host <HOST:PORT>] [--ws-path </tunnel>] [--tun-name <NAME>] [--mtu <1280..1400>]` | **`[pq768, Linux]`** 启动 Edge 客户端守护进程，拨号连接 Core 并建立端到端 `pq768` TUN 隧道 |
| `boreas ctl status [--socket <PATH>] [--config <FILE>]` | 查询运行中守护进程的 Unix 控制套接字，输出实时连接状态与 `tx`/`rx` 字节/包统计 JSON |
| `boreas [--lang zh-CN\|zh-TW\|en] status [--json] [--socket <PATH>]` | 渲染终端状态视图（传 `--socket` 时读取实时守护进程状态，否则显示离线快照） |

---

## 仓库结构速览

| 路径 | 职责说明 |
|---|---|
| [`crates/boreas-cli`](crates/boreas-cli) | 单二进制命令行入口（`boreas` / `boreas-easy`），含配置校验、离线 `pki`、Linux `daemon` 与 `ctl` 控制查询 |
| [`crates/boreas-proto`](crates/boreas-proto) | 有界应用层二进制帧格式、控制面握手消息与确定性 CBOR 管理对象编解码 |
| [`crates/boreas-pki`](crates/boreas-pki) | 离线根授权（`roots.cbor`）、`Ed25519 + ML-DSA-65` 双签管理对象验签、节点证书签发与状态新鲜度策略 |
| [`crates/boreas-crypto`](crates/boreas-crypto) | TLS 密码套件策略模型及基于 OpenSSL 3.6+ 的 `X25519MLKEM768` + `ML-DSA-65` mTLS 后端适配 |
| [`crates/boreas-tunnel`](crates/boreas-tunnel) | 外层 TLS + RFC 6455 WSS 传输、逐跳内层 TLS、会话授权、`RelayCircuit` 与端到端 `PacketPath` |
| [`crates/boreas-tun`](crates/boreas-tun) | 有界 L3 数据包 I/O 抽象及 Linux `/dev/net/tun`、Windows Wintun、macOS `utun`、`VirtualTun` 适配 |
| [`crates/boreas-dns`](crates/boreas-dns) | 有界权威 `.boreas` DNS 报文解析与基于 `smoltcp` 的响应构造原语 |
| [`crates/boreas-supervisor`](crates/boreas-supervisor) | 崩溃可恢复的升级事务日志（Journal）、活动版本指针与发布清单双签校验原语 |
| [`docs/`](docs) | [实战部署教程](docs/deployment/README.md)、[配置参考](docs/config/README.md)、[v1.11.0 架构主计划](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md)、[门禁账本](docs/engineering/gates.json) |
| [`tools/`](tools) | [Linux 双 netns 端到端冒烟脚本](tools/release/netns_daemon_smoke.sh)、发布打包校验与协议测试向量工具 |

---

## 开发者验证命令

1. **无外部 C 依赖的基础工作区检查与单元测试**：
   ```bash
   cargo check --locked --workspace --all-targets
   cargo test --locked --workspace
   ```

2. **启用 OpenSSL 3.6+（`openssl-inner-tls`）编译与全链路测试**：
   需准备包含 `ML-KEM` 与 `ML-DSA` provider 的静态 OpenSSL 3.6.5（完整构建参数可参考 [`.github/workflows/rust-tls.yml`](.github/workflows/rust-tls.yml)）：
   ```bash
   export OPENSSL_DIR="/path/to/static-openssl-3.6.5"
   export OPENSSL_STATIC=1

   cargo test --locked -p boreas-crypto -p boreas-pki --features openssl-backend
   cargo test --locked -p boreas-tunnel -p boreas-cli --features boreas-cli/openssl-inner-tls
   cargo build --locked --release -p boreas-cli --features openssl-inner-tls
   ```

3. **Linux 双 `netns` + 真实 `/dev/net/tun` 端到端冒烟验证**：
   在支持 `/dev/net/tun` 的 Linux 主机上，使用单条脚本自动完成离线 PKI 签发、双网络命名空间隔离、`daemon serve/connect` 握手、真实内核 `ping` 0% 丢包校验与 `ctl status` 包计数核对：
   ```bash
   sudo bash tools/release/netns_daemon_smoke.sh ./target/release/boreas
   ```

4. **CI 工作流说明**：
   - [`.github/workflows/ci.yml`](.github/workflows/ci.yml)：锁定依赖预检、Rust workspace Clippy/单测与协议向量校验。
   - [`.github/workflows/rust-tls.yml`](.github/workflows/rust-tls.yml)：源码构建固定版本静态 OpenSSL 3.6.5、运行 `pq768` mTLS 测试、编译 `boreas-linux-x86_64-musl-pq768` 并执行真实 `netns` TUN 转发测试。
   - [`.github/workflows/platforms.yml`](.github/workflows/platforms.yml) / [`linux-system.yml`](.github/workflows/linux-system.yml) / [`native-device.yml`](.github/workflows/native-device.yml)：五目标基础构建与各平台原生网卡驱动测试。

---

## 更多文档与许可证

- **部署与配置**：[双机公网实战部署教程](docs/deployment/README.md) | [TOML 配置字段参考](docs/config/README.md) | [`version = 2` 配置示例](docs/config/config.example.toml)
- **架构与工程**：[v1.11.0 安全与工程主计划](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md) | [实现状态记录](docs/engineering/implementation-status.md) | [发版规范](docs/releases/README.md)
- **许可证**：本项目基于 [GPL-3.0-only](LICENSE) 许可证开源。
