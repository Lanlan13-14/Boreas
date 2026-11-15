# Actions 回归结果（2026-11-15）

仅记录 GitHub Actions 精确 SHA/run/job 结果；没有在本机执行编译、测试、格式化或 Python。Actions API 通过 `.local/github-api.ps1` 认证调用，token 未输出。当前工作树中新写但未推送的改动不作为 CI 证据。

## 最新已推送 SHA 97d5530

Exact SHA `97d5530d79808054e5fb3026bdbece9ab72a1a61`（不包括随后未确认进入 CI 的本地改动）。

| workflow | run | conclusion / jobs |
|---|---:|---|
| Rust CI | [43680303358](https://github.com/Lanlan13-14/Boreas/actions/runs/43680303358) | failure；Ubuntu job [132709260681](https://github.com/Lanlan13-14/Boreas/actions/runs/43680303358/job/132709260681) 与 Windows job [132709260849](https://github.com/Lanlan13-14/Boreas/actions/runs/43680303358/job/132709260849) Clippy、Test 失败；锁依赖 preflight 与 rustfmt 成功。Windows `boreas-tunnel --lib` 为 145 passed / 10 failed。下列具体失败清单来自 Windows job 日志。 |
| Platform functional verification / development packaging | [43680303294](https://github.com/Lanlan13-14/Boreas/actions/runs/43680303294) | failure；5 个 target jobs workspace tests 均失败：Linux x86_64 musl [132709323729]、Linux aarch64 musl [132709323731]、macOS arm64 [132709323733]、macOS x86_64 [132709323740]、Windows [132709323868]；静态 CLI runtime 与五目标 development bundle 均 skipped。 |
| Linux system TUN | [43680303326](https://github.com/Lanlan13-14/Boreas/actions/runs/43680303326) | success。 |
| OpenSSL hybrid TLS | [43680303355](https://github.com/Lanlan13-14/Boreas/actions/runs/43680303355) | cancelled；job [132709281534](https://github.com/Lanlan13-14/Boreas/actions/runs/43680303355/job/132709281534)。Compile/backend 与其后测试步骤被取消/失败标记，不能当作独立 TLS 根因。 |

### Windows `boreas-tunnel` 的十项失败

job `132709260849`，日志在 2026-11-15 05:16:41Z 给出 `145 passed; 10 failed`：

- `e2e::tests::circuit_stream_carries_bytes_between_two_nodes`：`client session: Message(SessionMismatch)`；peer侧 circuit 为 `Io(InvalidData)`。
- `e2e::tests::duplicate_offset_resets_the_circuit`：`client session: Message(SessionMismatch)`；circuit 为 `Io(InvalidData)`。
- `e2e::tests::e2e_confirmation_gates_business_stream_when_higher_node_opens`：`authorized hop: Message(SessionMismatch)`，confirmed E2E 为 `Io(InvalidData)`。
- `e2e::tests::relay_forwards_across_three_nodes`：`client session: Message(SessionMismatch)`。
- `runtime::tests::admission_charges_only_authenticated_peers`：`Session(PeerRoleNotAllowed)`，客户端继而 `Io(InvalidData)`。
- `runtime::tests::loopback_session_roundtrip`：`Session(PeerRoleNotAllowed)`，客户端继而 `Io(InvalidData)`。
- `ws::tests::base64_roundtrip`：断言不等，left `None`，right `Some([])`。
- `ws::tests::control_frames_do_not_enter_the_byte_stream`：读取 pong 失败 `InvalidData: Closed`。
- `ws::tests::fragmented_message_is_reassembled_and_bounded`：断言 `stream.read(&mut out).is_err()` 失败（读取未按预期报错）。
- `ws::tests::oversized_frame_and_head_are_rejected`：错误分类 left `MaskedServerFrame`，预期 right `MessageTooLarge`。

## 前序 run 状态及同源失败归类

### SHA 0afc452

Exact SHA `0afc4526162f07f92346a41c104319159173d444`：Rust CI [43680115164](https://github.com/Lanlan13-14/Boreas/actions/runs/43680115164) failure（jobs Ubuntu [132708696538]、Windows [132708696494]）；Platforms [43680115227](https://github.com/Lanlan13-14/Boreas/actions/runs/43680115227) failure（5 target jobs `132708855752`、`132708855768`、`132708855826`、`132708855864`、`132708855878`；CLI/bundle skipped）；Linux TUN [43680115210](https://github.com/Lanlan13-14/Boreas/actions/runs/43680115210) success；TLS [43680115138](https://github.com/Lanlan13-14/Boreas/actions/runs/43680115138) cancelled（job `132708763904`）。未重复拉取这些 run 的完整日志；TLS/supervisor 的必需 `--ready-expected-schema` helper 参数缺失与此前 `db9df5c` TLS 日志揭示的同根因，不在此重复下载日志。

在 0afc452 Platforms macOS Intel job `132708855752` 日志中，`boreas-supervisor` 的 release-manifest validator 测试实际成功（如 `manifest::tests::release_policy_enforces_freshness_lifetime_and_sequence`、`sequence_ledger_accepts_only_verified_manifests`、`verify_release_rejects_untrusted_and_oversized_inputs_before_crypto`、`verify_release_without_a_crypto_backend_fails_closed`）。但该 workflow 整体不是绿色：相同 job 有 supervisor CLI 单测失败，主要因测试 helper 未传 `--ready-expected-schema <ID>`；另有 macOS 临时路径太长导致 readiness socket bind 报 `path must be shorter than SUN_LEN`，并使 `failed_trial_is_bounded_by_the_durable_budget` 失败。故 validator tests 单项 pass 不代表 target tests / workflow pass，也不代表 release 可用。

### 8934d31、7bddbf8

| SHA | run IDs / 结论 |
|---|---|
| `8934d3141b3c8b9f64d56da3aa6fb0cd19c48435` | TUN [43680052454](https://github.com/Lanlan13-14/Boreas/actions/runs/43680052454) success；Rust CI [43680052467](https://github.com/Lanlan13-14/Boreas/actions/runs/43680052467) failure；Platforms [43680052555](https://github.com/Lanlan13-14/Boreas/actions/runs/43680052555) cancelled；TLS [43680052524](https://github.com/Lanlan13-14/Boreas/actions/runs/43680052524) cancelled。 |
| `7bddbf82b5d273c2d007487b3b48da37160b47d0` | TUN [43679914709](https://github.com/Lanlan13-14/Boreas/actions/runs/43679914709) success；Platforms [43679914660](https://github.com/Lanlan13-14/Boreas/actions/runs/43679914660) failure；Rust CI [43679914742](https://github.com/Lanlan13-14/Boreas/actions/runs/43679914742) failure；TLS [43679914764](https://github.com/Lanlan13-14/Boreas/actions/runs/43679914764) cancelled。 |

`7bddbf8` 的平台/Rust 失败也包含 supervisor `--ready-expected-schema` 新参数未同步测试调用者的既有问题，随后 0afc452 同源，不重复展开旧日志。

## 当前不可推断事项

CI 报告只对应上述 Actions `head_sha`。当前尚未推送的 `runtime.rs` 和 `tests/wss_e2e_openssl.rs` 变更不在这些 SHA 中，因此本报告中的运行时/WSS failures 不能作为其已测试或修复的证据。CLI smoke 不是 production 验证；development packaging 明确 unsigned / production blocked。`root_authorization` 和之后的提交也未以本报告的 97d5530 run 代替验证。


## Later completed SHA: Clippy diagnostic supplement (2026-11-15)

Read only completed runs newer than 97d5530. Latest completed non-green/green full Rust CI found was exact SHA `757227d781bb2d4c46cd0853feb5a9da712173ef`, Rust CI run [43681050699](https://github.com/Lanlan13-14/Boreas/actions/runs/43681050699), conclusion failure. (Later SHA `712a94f` Rust CI/TLS/platform runs were still in progress at query time; no waits/polling. Its TUN run was completed, but that says nothing about Clippy.) Rust jobs: Ubuntu [132711538868](https://github.com/Lanlan13-14/Boreas/actions/runs/43681050699/job/132711538868), Windows [132711538931](https://github.com/Lanlan13-14/Boreas/actions/runs/43681050699/job/132711538931); each reported Clippy and Test failed. The following error diagnostics appeared in both Clippy logs under `cargo clippy --workspace --all-targets --locked -- -D warnings` (Clippy 1.100.0); they are not claims about later `712a94f` or unpushed bool/root-auth/runtime/WSS/fixture changes.

- Rust lint `function-casts-as-integer`: `crates/boreas-supervisor/src/signals.rs:28:62`, “direct cast of function item into an integer”.
- dead code: `crates/boreas-tunnel/src/e2e.rs:487:19`, associated function `new` never used; `crates/boreas-tunnel/src/tls.rs:77:19`, `from_verified_certificate` never used; and `crates/boreas-tunnel/src/tls.rs:110:19`, associated function `new` never used.
- Clippy `never_loop`: `crates/boreas-tunnel/src/e2e.rs:286:9`, “this loop never actually loops”.
- Clippy `chunks_exact_to_as_chunks`: `crates/boreas-tunnel/src/sha1.rs:20:27`, “using `chunks_exact` with a constant chunk size”.
- Clippy `manual_is_multiple_of`: `crates/boreas-tunnel/src/ws.rs:778:27`, “manual implementation of `.is_multiple_of()`”.
- Clippy `unused_mut`: `crates/boreas-tunnel/src/ws.rs:1042:13`, variable does not need to be mutable (test target).
- Clippy `same_item_push`: `crates/boreas-tunnel/src/ws.rs:1240:13`, “it looks like the same item is being pushed into this `Vec`” (test target).

Compiler summary for tunnel library: six previous errors; tunnel lib-test: seven previous errors. These findings reflect precisely 757227d, not the later WSS fix in 712a94f. The job log also had `warning: unused dependency boreas-proto` from `crates/boreas-pki/Cargo.toml:21:1`; this was a warning, not one of the `-D warnings` compiler errors reported in the captured excerpt.

Evidence handling: `.local/ci-clippy-132711538868.json` and `.local/ci-clippy-132711538931.json` are ignored local diagnostic captures. The helper emitted a JSON-escaped log string, which was decoded with PowerShell `ConvertFrom-Json`; grep-like extraction was run over the decoded log, not the serialized one-line JSON. No source/ledger changed, and no local compilation, test, Python, or formatting command was run.
