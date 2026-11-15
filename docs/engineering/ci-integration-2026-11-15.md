# Actions CI 集成诊断记录（2026-11-15）

## 范围与证据口径

本记录只引用 GitHub Actions 对应的 exact head SHA、run/job ID 和 URL。2026-11-15 12:50+08 dispatch 的锁刷新 run 实际运行于 `8090fd6bd0ce5f9d1ba1eef9cc33cbac000cc138`；远端 main 后续推进，当前整合工作树在本轮审阅时为 `7a8be2d38c383f4f398045a6148345e4ae251491`。以下旧 SHA 的失败记录不代表后续 SHA 状态。未在本机执行 cargo、Python 或测试；以下仅为远端 API/Actions 日志诊断和静态源码修复。

## Refresh Cargo.lock

- Run [43678497934](https://github.com/Lanlan13-14/Boreas/actions/runs/43678497934)，`workflow_dispatch`，branch `main`，head SHA `8090fd6bd0ce5f9d1ba1eef9cc33cbac000cc138`，2026-11-15 04:50:31Z 创建，结束 `failure`。
- Generate job [132703791745](https://github.com/Lanlan13-14/Boreas/actions/runs/43678497934/job/132703791745)：`success`。Validate job [132703853859](https://github.com/Lanlan13-14/Boreas/actions/runs/43678497934/job/132703853859)：`failure`；metadata check 成功，`cargo check --workspace --all-targets --locked` 失败，提交步骤跳过。
- 生成锁 artifact：ID `14147481274`，名称 `generated-cargo-lock-43678497934`，API archive `https://api.github.com/repos/Lanlan13-14/Boreas/actions/artifacts/14147481274/zip`。已由本地忽略目录 `.local/ci-review/refresh-lock-43678497934/` 下载并核验，不提交。
- artifact 中 `source-revision.txt` 为上述 SHA；`metadata-result.txt` 为 `metadata_exit_code=0`；`Cargo.lock.sha256` 为 `626c7f75a0993566c0ea1524d6b80406b87d8d2cd9382205b592b5f73a056b9c`。锁变更含 `boreas-proto` 的 `serde_json` dev-dependency、`boreas-tunnel` 的 `boreas-pki`/`boreas-proto`/`openssl` 依赖和 `serde_json 1.0.154` 依赖闭包（`itoa`、`memchr`、`zmij`）。此 artifact 的 compile validation 失败，不能称为已验证锁；应用到后续 main 前仍需确认 manifests 一致，并用后续 exact SHA 重跑 CI。
- Validate 日志观察到 `boreas-supervisor` 编译问题：`main.rs:1402` 调用不存在的 `readiness::probe_once` (E0425)；`readiness.rs:617` 嵌套 loop `break report` 试图从外层 `let report = loop` 返回 `ReadyReport`，而实际期望 `()` (E0308)，后续 join unreachable；`main.rs:1105` 的 `SupervisePlan` 缺 `ready_expected_schema`；`main.rs:1243` 的 `ReadinessPolicy` 缺 `expected_schema` (E0063)。日志来源：上述 Validate job URL，报错约 2026-11-15 04:51:30Z。

## exact 3d5665b integration push 状态（失败，仅历史证据）

以下 run 均由 push 触发，head SHA 均为 `3d5665bf359b65746cbb2f683a2bec9beb33675a`，状态均 `failure`。不能以 upstream `8457d06` 旧 green 代替。

| Workflow / run | 结果 | 失败 job / 观察 |
|---|---|---|
| [Rust CI 43678457694](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457694) | failure | Ubuntu 与 Windows Rust checks 均失败；format、locked dependency preflight 均成功。Ubuntu 日志在 `tools/tests/test_control_vectors.py` 的 `OtherBodyTests.test_probe_ping_and_pong` 失败：`control.parse_control(ping)` 到 `parse_probe` 抛 `Reject("invalid_field")`（job [132703671801](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457694/job/132703671801)，约 04:50:24Z）。Windows check 失败需结合日志进一步定位（job [132703671567](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457694/job/132703671567)）。 |
| [OpenSSL TLS 43678457779](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457779) | failure | workflow job [132703672054](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457779/job/132703672054)；步骤显示 policy-only tests、backend compile/all-targets、real mTLS tests、PKI/transport/supervisor tests 均失败；格式步骤生成了需审阅的 rustfmt patch。该 job 日志尚未完成根因分类。 |
| [Linux system TUN 43678457749](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457749) | failure | job [132703671773](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457749/job/132703671773)：cargo 因 `--locked` 无法更新 Cargo.lock；因此实际设备测试未运行，后续设备证据检查报告缺测试数/结果。 |
| [Platforms 43678457712](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457712) | failure | preflight 成功，五个 target build jobs 失败，后续 runtime/bundle jobs skipped。job IDs：`132703759399` Linux aarch64 musl、`132703759405` Windows x86_64、`132703759406` macOS arm64、`132703759412` Linux x86_64 musl、`132703759429` macOS x86_64；各 job URL 可由 run URL 后附 `/job/<id>`。需结合完整日志进一步确认是否均由缺失新锁所致。 |
| [Native device 43678457711](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457711) | failure | macOS x86_64 [132703671655](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457711/job/132703671655)、macOS arm64 [132703671854](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457711/job/132703671854)、Windows [132703671898](https://github.com/Lanlan13-14/Boreas/actions/runs/43678457711/job/132703671898)；Windows 日志明确 cargo 因 `--locked` 不得更新 Cargo.lock。其他平台详细日志未在此轮定因。 |

## 当前授权源码修复（尚待 Actions）

lead 授权范围为 `crates/boreas-supervisor/src/main.rs`、`crates/boreas-supervisor/src/readiness.rs`、`crates/boreas-supervisor/tests/readiness.rs`。静态修复：将解析得到的必需 `ready_expected_schema` 传入 `SupervisePlan`，再设置 `ReadinessPolicy.expected_schema`；实现 `readiness::probe_once`，将授权连接/部分握手状态保存在 supervisor 的 pending slot 跨轮轮询，沿用单一绝对 deadline，不阻塞并保留外层 child-exit/信号轮询与失败 rollback；修复 readiness 单测跨嵌套 loop 的 break 目标；集成 fixture 显式提供 schema，并新增错误 schema 必须拒绝、回滚且消耗一次持久 trial attempt 的 E2E 用例。

这三文件尚未运行 formatter、编译或测试，均待 GitHub Actions。当前 main 是 `7a8be2d38c383f4f398045a6148345e4ae251491`；本轮源码改动尚未提交/推送，不能声称 CI 通过。锁由主代理在后续 main 上核对并应用。
