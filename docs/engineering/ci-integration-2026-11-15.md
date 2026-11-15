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

## 后续推送 db9df5c 的 Actions 结果（精确 SHA）

- exact push SHA `db9df5c35e5871fc58022f319b7d5c5019e70a45`；当前 API 查询 main 已推进到 `a54def8107888a9a4553f15f534055c79a05c51f`，旧 run 不代表后续提交。
- Rust CI [43679392648](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392648) failure；Ubuntu job [132706494822](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392648/job/132706494822) 与 Windows job [132706494846](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392648/job/132706494846) failure。Ubuntu/Windows 编译及 platforms 五个 target 首要阻塞均为 `crates/boreas-tunnel/src/ws.rs:583` 的 E0774：`#[derive(Clone, Copy, Debug, Eq, PartialEq)]` 挂在 `valid_close_code` 函数上。Ubuntu unit compile 另见 `e2e.rs:1048` 局部 `admission` 遮蔽 helper (E0618) 和 `ws.rs:973` 调用 `read_frame` 缺第四个 `Instant` 参数 (E0061)；主代理后续告知 admission 已在其他工作中修复，ws 由独立任务修复。
- Rust CI Ubuntu 的 Clippy `-D warnings` 诊断：`boreas-pki/src/enrollment.rs` 的 `csr_policy`、`ED25519_POP_DOMAIN`、`ED25519_POP_PAYLOAD_LEN`、`setup_with_policy` 未使用；`from_verified_csr`/`test_request` 参数数目 8/7。均不应通过 suppress lint 处理；PKI 已由独立任务接手。
- Windows Clippy 同一 job 在 `crates/boreas-supervisor/src/main.rs` 报 `execute_supervise` 的 `store` 未使用、Unix-only `POLL_INTERVAL` 与 readiness policy 字段死代码，以及 `open_store` 返回的 `CliOutcome` 为过大 Err variant (`result_large_err`)。本轮获准仅改 `main.rs`：Unix-only 的 poll 常量与 readiness 配置字段加 `cfg(unix)`；在非 Unix 保留运行路径/失败关闭与 store 重开检查，并显式消费仅在 Unix 有效的 readiness 参数；将 `CliOutcome::RunChild` 的计划对象装入 `Box<SupervisePlan>`，缩小错误枚举大小，调用处解箱。没有 allow lint 或删安全逻辑。此修复尚未 Actions 验证。
- Linux TUN run [43679392570](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392570) success；job [132706494410](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392570/job/132706494410) 报真实设备测试证据通过：60 passed、0 failed。
- Platforms run [43679392618](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392618) failure：五个目标 job 均在同一 `ws.rs:583` E0774 编译失败，runtime/bundle job skipped。jobs：Linux aarch64 [132706564087](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392618/job/132706564087)、macOS x86_64 [132706564093](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392618/job/132706564093)、Linux x86_64 [132706564105](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392618/job/132706564105)、Windows [132706564113](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392618/job/132706564113)、macOS arm64 [132706564142](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392618/job/132706564142)。
- OpenSSL/TLS run [43679392679](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392679) 已完成 failure，job [132706494976](https://github.com/Lanlan13-14/Boreas/actions/runs/43679392679/job/132706494976)。首先 `boreas-pki/src/enrollment.rs:1434` 报 E0599：`Asn1Object` 没有 `to_der` 方法；PKI 由独立 Luna 任务修复。之后 supervisor 单测 39 个中 4 个失败：`dangling_pointer_with_placeholder_fails_closed_before_launch`、`missing_store_fails_closed_for_every_subcommand`、`placeholder_in_child_argument_is_rejected_not_substituted`、`placeholder_without_any_active_version_fails_closed`；原因均为既有 unit helper 构造 `supervise` 参数未加入必需 `--ready-expected-schema <ID>`。另一个编译/测试根因已在上段注明。日志于 2026-11-15 05:05:41Z 显示缺参错误并于 05:05:42Z 汇总 `35 passed; 4 failed`。
- Ubuntu Rust CI 的 `tools/tests/test_control_vectors.py::OtherBodyTests::test_probe_ping_and_pong` 仍失败于 `tools/control_vectors.py:606` 的 `Reject("invalid_field")`；独立 Luna-probe-vectors 已负责，不在本任务范围内。

## 当前授权源码变更（待 Actions）

此前 readiness/schema 修复已由主代理提交推送为 db9df5c；该 exact SHA 的 TLS 实测指出 `main.rs` 单元 helper 遗漏必需 schema 参数，主代理已在后续提交中合并相应工作。当前这轮新增修改仅限 `crates/boreas-supervisor/src/main.rs`：cfg-gate Unix-only poll 常量和 readiness plan 字段，保留 Windows 上 readiness 不可用时的 fail-closed/store-open 路径；将 `RunChild` 内的 `SupervisePlan` 装箱，以消除大错误类型 Clippy 诊断。该 diff 尚待 CI；本机未运行编译、Clippy、格式化或测试。

日志快照保存在忽略路径 `.local/ci-review/db9df5c/`。