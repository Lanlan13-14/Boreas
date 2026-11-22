# GitHub Actions 怎么看

| 标签 | 看什么 | 何时看 |
|---|---|---|
| Quick checks | Rust 单测和 Clippy、协议向量、发布脚本逻辑 | 常规代码 PR；只改普通文档不触发 |
| Integration / Encrypted tunnel | 真实 Linux 隧道和加密认证；验收分支还检查私有 DNS、主备切换、双向吞吐及可选 GSO | 改隧道、加密或部署相关代码；查看运行摘要中的实际覆盖 |
| Integration / Network delay | 延迟、丢包、带宽限制和路由矩阵 | 成功的 `main` 隧道运行后，或输入受信的运行 ID 后手动触发 |
| Security | Rust 依赖和原生 OpenSSL 安全通告、构建固定项 | 依赖与安全验收；保留每日检查 |
| Linux TUN / Native packet devices | 真设备包收发与清理；分别验证 Linux、Windows、macOS 驱动 | 改数据设备时；不是普通单测的重复 |
| OpenWrt / Package | 路由器用户空间兼容、五平台开发包可执行及两种静态 Linux 包 | 主线、交接验收分支或手动；不会发版 |
| On demand / OpenSSL CLI experiment | 独立 OpenSSL 命令行正反例，不是 Boreas 隧道 | 仅手动，需要检查后端实验时运行 |

性能门槛未降低：正常链路与高延迟链路的三轮双向达标及完整性检查仍自动跑；单电路的首秒观测与短长传输对比改为手动诊断，不替代正式门槛。要确认具体用例是否验过，请点开对应步骤，`skipped` 不能算通过。

集成运行只构建并验证一次候选制品。适用的功能验收分配到独立的 `Functional netns` runner；性能采样、可选诊断和 GSO 在另一个 runner 上顺序执行。`main` 和 `work/v111-handoff` 的强制验收汇总同时检查两侧结果。开发二进位制归档名称不变；构建证据仍在 `rust-tls-<run_id>`，功能及性能日志分别在 `rust-tls-functional-<case>-<run_id>-<attempt>` 和 `rust-tls-performance-<run_id>-<attempt>`。

## OpenSSL 版本为什么有两个

上游正式标签 `openssl-4.1.0` 不等于当前构建所用源码。受审固定提交 `941390af2ac35f41d2f95bb0bac823dbf0700845` 是带公告修复的开发快照，自报 `4.1.1-dev`；既不是原样 `4.1.0`，也不是正式的 `4.1.1`。集成运行的摘要记录确切版本和提交；构建仍验证源码摘要、编译选项和链接。不要因为标题变化换用无补丁的版本。
