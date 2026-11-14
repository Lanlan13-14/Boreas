# Boreas

[English](#english) | [简体中文](#简体中文)

> **Status / 状态:** v1.11.0 design baseline with several pure policy and packet-processing primitives; this is not a production VPN or frozen wire protocol. VirtualTun, ICMP/PTB construction and IPv4 fragmentation, and UDP/IP DNS packet handling exist, but end-to-end data-plane and release gates remain unaccepted. See the [master plan](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md), [implementation status and gate ledger](docs/engineering/implementation-status.md), and [recent GitHub Actions run](https://github.com/Lanlan13-14/Boreas/actions/runs/43604239086).

---

## English

Boreas is a design for a Rust Layer 3 overlay engine using WebSocket transport. The current repository is **not a production-ready VPN**. Main-branch code includes a VirtualTun, ICMP/PTB construction, IPv4 fragmentation and UDP/IP DNS packet handling, alongside policy and parser foundations. These primitives are not a validated full data plane. An OpenSSL source download/hash/build and an AES client-side HTTP path have succeeded, but the mTLS server assertion is still pending: `G-CRYPTO` has not passed, and this does not establish Boreas end-to-end TLS acceptance. All roadmap phases and acceptance gates remain unverified; Phase 0 is not complete.

The v1.11.0 plan is the authoritative architecture baseline, not a frozen production protocol or security certification. Its security design calls for standard TLS 1.3 hybrid key exchange and ML-DSA authentication, and explicitly retires the historical custom handshake designs. Application framing and deterministic object encoding remain candidates until Phase 0 review and independent test vectors are complete. There is no legacy 4-byte `StreamID`/`Length` framing in the current implementation.

### Current CLI

`boreas`, `boreas doctor`, and `boreas self-check` emit a small JSON status report. The report states that daemon, TLS and networking are unavailable and Phase 0 is incomplete. Unknown commands exit unsuccessfully; they do not simulate a successful daemon start.

### Verification boundary

GitHub Actions has successfully allocated five native runner targets. In the latest reported run, Clippy passed, and 17 DNS wire/packet tests passed; the workspace test run then failed one TUN test, so later tunnel tests did not run. The matrix is not green and complete artifacts are not yet available. This is not evidence of Linux `x86_64` and `aarch64` static TLS builds, production operation, CDN compatibility, cryptographic interoperability, or security acceptance. See the [gate ledger](docs/engineering/implementation-status.md) and [Actions run history](https://github.com/Lanlan13-14/Boreas/actions/runs/43604239086) for current evidence and open gates.

## 简体中文

Boreas 是一个基于 Rust 的三层 Overlay 引擎设计，计划使用 WebSocket 承载。**当前仓库尚非生产可用的 VPN**：主分支已有 VirtualTun、ICMP/PTB构造、IPv4分片及UDP/IP DNS报文处理，也有若干纯策略与解析模块，但这不等于已验收的完整数据面。OpenSSL源码下载/hash/build及AES客户端HTTP路径已成功；mTLS服务端断言仍待验证，因此 `G-CRYPTO` 未通过，也不能据此宣称 Boreas 端到端 TLS 已验收。所有路线阶段和验收门禁仍未完成，Phase 0 尚未完成。

[v1.11.0 主计划](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md)是架构设计基线，并非已冻结的生产协议或安全认证。仓库已有应用帧解析、身份/授权及TLS策略、前缀/路由裁决、L3报文校验与PMTU、权威DNS报文、升级事务日志等纯策略/解析基础，但没有TLS后端、认证网络路径、真实TUN设备或socket服务。其安全设计要求采用标准 TLS 1.3 混合密钥交换及 ML-DSA 身份认证，并明确废弃历史自研握手。应用帧和确定性管理对象编码仍是候选规范，须待 Phase 0 评审及独立测试向量验证后再冻结。当前实现没有旧式 4 字节 `StreamID`/`Length` 帧。

### 当前 CLI

`boreas`、`boreas doctor` 和 `boreas self-check` 输出简短 JSON 状态，明确标示 daemon、TLS 和网络功能不可用、Phase 0 未完成。未知命令以失败状态退出，不会假装 daemon 已成功启动。

### 验证范围

GitHub Actions 已成功分配五种原生 runner 目标。最近一次报告中 Clippy 全部通过，DNS wire/packet 测试 17 项通过；workspace 测试随后有一个 TUN 测试失败，因此后续 tunnel 测试尚未运行。测试矩阵仍未全绿，完整 artifacts 尚未产出。这不代表已验证 Linux `x86_64` 与 `aarch64` 静态 TLS 构建、生产运行、CDN兼容、密码互操作或安全验收。请查看[实现状态与门禁表](docs/engineering/implementation-status.md)及[Actions运行记录](https://github.com/Lanlan13-14/Boreas/actions/runs/43604239086)，了解当前证据和未通过门禁。

---

## License

GPL-3.0-only; see [LICENSE](LICENSE).
