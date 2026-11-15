# Boreas

[English](#english) | [简体中文](#简体中文)

> **Status / 状态:** v1.11.0 design baseline and development foundation only—not a production VPN or frozen wire protocol. Linux/Windows CI and five native platform builds plus four Linux distro-container checks have passed as foundation/development evidence; the latest reported unit tests passed, but Clippy warnings failed the overall workflow. A separate AES/ChaCha hybrid-ML-DSA mTLS PoC is not Boreas Rust/WSS, static backend, or independent interoperability evidence, and does not pass G-CRYPTO. See the [master plan](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md), [implementation status and gate ledger](docs/engineering/implementation-status.md), and linked CI records there.

---

## English

Boreas is a design for a Rust Layer 3 overlay engine using WebSocket transport. The current repository is **not a production-ready VPN**. Main-branch code includes VirtualTun, ICMP/PTB and IPv4-fragmentation primitives, UDP/IP DNS packet handling, a real smoltcp-based DNS packet path, and policy/parser foundations; none constitutes a validated production data plane. Linux/Windows foundation CI passed (run [43606273297](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273297)); the platform workflow passed five native build/test jobs and four Linux distro-container `doctor` checks (run [43606273363](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273363)). Unit tests passed in run [43651142110](https://github.com/Lanlan13-14/Boreas/actions/runs/43651142110), including PKI 13, proto 8, tunnel 21, DNS wire 12, DNS packet 6, and smoltcp 4 tests, but nine DNS test Clippy warnings made that overall workflow fail. A standalone AES/ChaCha hybrid-ML-DSA mTLS positive/negative PoC passed in [run 43649750521](https://github.com/Lanlan13-14/Boreas/actions/runs/43649750521) at `1fc4a34`; it is not Boreas Rust/WSS, independent interoperability, or static production backend evidence, so `G-CRYPTO` remains open. All roadmap phases and acceptance gates remain unaccepted; Phase 0 is not complete.

The v1.11.0 plan is the authoritative architecture baseline, not a frozen production protocol or security certification. Its security design calls for standard TLS 1.3 hybrid key exchange and ML-DSA authentication, and explicitly retires the historical custom handshake designs. Application framing and deterministic object encoding remain candidates until Phase 0 review and independent test vectors are complete. There is no legacy 4-byte `StreamID`/`Length` framing in the current implementation.

### Current CLI

`boreas`, `boreas doctor`, and `boreas self-check` emit a small JSON status report. The report states that daemon, TLS and networking are unavailable and Phase 0 is incomplete. Unknown commands exit unsuccessfully; they do not simulate a successful daemon start.

### Verification boundary

Recorded evidence: [run 43606273297](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273297) passed Linux/Windows foundation checks; [run 43606273363](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273363) passed five native platform build/test jobs plus four Linux distro-container doctor checks. [Run 43650844858](https://github.com/Lanlan13-14/Boreas/actions/runs/43650844858) verified 16 management, 8 AppHeader and 15 CBOR vectors plus 14 Python tests. In [run 43651142110](https://github.com/Lanlan13-14/Boreas/actions/runs/43651142110), all reported unit tests passed (PKI 13, proto 8, tunnel 21, DNS wire 12, DNS packet 6, smoltcp 4), but nine DNS test Clippy warnings caused the overall workflow to fail. A separate [AES/ChaCha hybrid-ML-DSA mTLS PoC](https://github.com/Lanlan13-14/Boreas/actions/runs/43649750521) passed positive/negative harness checks but is not Boreas Rust/WSS or independent interoperability evidence and does not pass `G-CRYPTO`. These are development/foundation results only, not production VPN, static TLS acceptance, cryptographic security, or release approval. See the [gate ledger](docs/engineering/implementation-status.md) for evidence boundaries.

## 简体中文

Boreas 是一个基于 Rust 的三层 Overlay 引擎设计，计划使用 WebSocket 承载。**当前仓库是开发基础，不是生产可用 VPN**：主分支包含 VirtualTun、ICMP/PTB与IPv4分片基础、UDP/IP DNS处理、真实smoltcp DNS packet路径及纯策略/解析模块，但尚非生产数据面。Linux/Windows基础CI run [43606273297](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273297)通过；平台run [43606273363](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273363)通过五种原生平台构建/测试和四种Linux发行版容器doctor检查。run [43651142110](https://github.com/Lanlan13-14/Boreas/actions/runs/43651142110)中单测通过（PKI 13、proto 8、tunnel 21、DNS wire 12、DNS packet 6、smoltcp 4），但9条DNS测试Clippy警告令整个workflow失败。独立AES/ChaCha混合ML-DSA mTLS正负测试PoC run [43649750521](https://github.com/Lanlan13-14/Boreas/actions/runs/43649750521)通过；但它不是Boreas Rust/WSS路径、独立互操作或静态生产后端证据，故`G-CRYPTO`仍未通过。所有路线阶段与验收门禁均未接受完成，Phase 0尚未完成。

[v1.11.0 主计划](docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md)是架构设计基线，并非已冻结的生产协议或安全认证。仓库已有应用帧解析、身份/授权及TLS策略、前缀/路由裁决、L3报文校验与PMTU、权威DNS报文、升级事务日志等纯策略/解析基础，但没有TLS后端、认证网络路径、真实TUN设备或socket服务。其安全设计要求采用标准 TLS 1.3 混合密钥交换及 ML-DSA 身份认证，并明确废弃历史自研握手。应用帧和确定性管理对象编码仍是候选规范，须待 Phase 0 评审及独立测试向量验证后再冻结。当前实现没有旧式 4 字节 `StreamID`/`Length` 帧。

### 当前 CLI

`boreas`、`boreas doctor` 和 `boreas self-check` 输出简短 JSON 状态，明确标示 daemon、TLS 和网络功能不可用、Phase 0 未完成。未知命令以失败状态退出，不会假装 daemon 已成功启动。

### 验证范围

记录的证据：Linux/Windows基础CI [43606273297](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273297)通过；平台CI [43606273363](https://github.com/Lanlan13-14/Boreas/actions/runs/43606273363)通过五种原生平台构建/测试及四种Linux发行版容器doctor检查；向量workflow [43650844858](https://github.com/Lanlan13-14/Boreas/actions/runs/43650844858)通过16个管理对象、8个AppHeader、15个CBOR向量和14项Python测试。run [43651142110](https://github.com/Lanlan13-14/Boreas/actions/runs/43651142110)中的单元测试全部通过（PKI 13、proto 8、tunnel 21、DNS wire 12、DNS packet 6、smoltcp 4），但9条DNS测试Clippy警告导致workflow失败。独立AES/ChaCha混合ML-DSA mTLS PoC [43649750521](https://github.com/Lanlan13-14/Boreas/actions/runs/43649750521)通过正负测试，但不是Boreas Rust/WSS路径或独立互操作证据，也不通过`G-CRYPTO`。以上均为开发基础证据，不代表生产VPN、静态TLS验收、密码安全或发行批准。当前门禁见[实现状态与门禁表](docs/engineering/implementation-status.md)。

---

## License

GPL-3.0-only; see [LICENSE](LICENSE).
