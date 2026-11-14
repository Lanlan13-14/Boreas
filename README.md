# Boreas

[English](#english) | [简体中文](#简体中文)

> **Status / 状态:** design baseline plus a small Phase 0 policy/parser foundation only. No daemon, TLS backend, network engine, or frozen wire protocol is implemented. See the [v1.11.0 master plan](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md) and the [implementation status and gate ledger](docs/engineering/implementation-status.md).

---

## English

Boreas is a design for a Rust Layer 3 overlay engine using WebSocket transport. The current repository is **not a usable VPN**: it now contains pure policy/parser foundations for application framing, identity/authorization and TLS policy, prefix/routing decisions, L3 packet validation/PMTU, authoritative DNS wire messages, and an upgrade transaction journal, plus a minimal CLI status command. These do not implement a TLS backend, authenticated network path, real TUN device or socket service. All roadmap phases and acceptance gates remain unverified; Phase 0 is not complete.

The v1.11.0 plan is the authoritative architecture baseline, not a frozen production protocol or security certification. Its security design calls for standard TLS 1.3 hybrid key exchange and ML-DSA authentication, and explicitly retires the historical custom handshake designs. Application framing and deterministic object encoding remain candidates until Phase 0 review and independent test vectors are complete. There is no legacy 4-byte `StreamID`/`Length` framing in the current implementation.

### Current CLI

`boreas`, `boreas doctor`, and `boreas self-check` emit a small JSON status report. The report states that daemon, TLS and networking are unavailable and Phase 0 is incomplete. Unknown commands exit unsuccessfully; they do not simulate a successful daemon start.

### Verification boundary

CI runs formatting, check, Clippy, and tests on Windows and Ubuntu. This is not evidence of Linux `x86_64` and `aarch64` static TLS builds, real Linux operation, CDN compatibility, cryptographic interoperability, or security acceptance. See the [gate ledger](docs/engineering/implementation-status.md) for every open gate and required follow-up.

## 简体中文

Boreas 是一个基于 Rust 的三层 Overlay 引擎设计，计划使用 WebSocket 承载。**当前仓库不是可用的 VPN**：目前只有最小 CLI 状态基础，没有 TLS 后端，也没有网络引擎。所有路线阶段和验收门禁仍未验证，Phase 0 尚未完成。

[v1.11.0 主计划](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md)是架构设计基线，并非已冻结的生产协议或安全认证。仓库已有应用帧解析、身份/授权及TLS策略、前缀/路由裁决、L3报文校验与PMTU、权威DNS报文、升级事务日志等纯策略/解析基础，但没有TLS后端、认证网络路径、真实TUN设备或socket服务。其安全设计要求采用标准 TLS 1.3 混合密钥交换及 ML-DSA 身份认证，并明确废弃历史自研握手。应用帧和确定性管理对象编码仍是候选规范，须待 Phase 0 评审及独立测试向量验证后再冻结。当前实现没有旧式 4 字节 `StreamID`/`Length` 帧。

### 当前 CLI

`boreas`、`boreas doctor` 和 `boreas self-check` 输出简短 JSON 状态，明确标示 daemon、TLS 和网络功能不可用、Phase 0 未完成。未知命令以失败状态退出，不会假装 daemon 已成功启动。

### 验证范围

CI 在 Windows 与 Ubuntu 上运行格式检查、check、Clippy 和测试。这不代表已验证 Linux `x86_64` 与 `aarch64` 静态 TLS 构建、真实 Linux 运行、CDN 兼容、密码互操作或安全验收。请查看[实现状态与门禁表](docs/engineering/implementation-status.md)，其中逐项记录所有未通过门禁及后续任务。

---

## License

GPL-3.0-only; see [LICENSE](LICENSE).
