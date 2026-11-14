# Phase 0 密码/TLS 后端能力核查（观察快照）

**观察时间：2026-11-14（本任务提供的时钟快照；网络响应可能改变）**
**范围：BOREAS Master Plan v1.11.0 §4、Phase 0 / G-CRYPTO。本文只记录标准/源代码可核实信息与待验证项；不是实现验收或密码审计。**

## 结论摘要

- `[事实]` 本次一手 RFC 查询确认：RFC 9846 已于 2026-07 发布并取代 RFC 8446；RFC 10024 已于 2026-08 发布并标准化 `X25519MLKEM768`（group `0x11EC`）、`SecP256r1MLKEM768`、`SecP384r1MLKEM1024`；RFC 9881 已于 2025-10 发布 ML-DSA 的 X.509/CRL 编码。
- `[事实]` IETF Datatracker 当前显示 `draft-ietf-tls-mldsa-06` 是 active Internet-Draft，状态 **RFC Ed Queue / Awaiting First editor**，不是 RFC。其草案列出 `mldsa44=0x0904`、`mldsa65=0x0905`、`mldsa87=0x0906`。G-CRYPTO ADR 必须将这仍在队列中的版本、代码点和未来 RFC 变更风险标明；不能把代码点当成已发布标准。
- `[事实]` 固定 tag `openssl-3.6.1` 的 [`ssl/t1_lib.c`](https://github.com/openssl/openssl/blob/openssl-3.6.1/ssl/t1_lib.c) 默认 TLS group list 含 `X25519MLKEM768`，并有 provider 提供 TLS-GROUP / TLS-SIGALG 的发现机制；同 tag [`ssl_local.h`](https://github.com/openssl/openssl/blob/openssl-3.6.1/ssl/ssl_local.h) 定义 `mldsa44/65/87` 名称与草案代码点常量。固定 release tarball SHA-256 为 `b1bfedcd5b289ff22aee87c9d600f515767ebf45f77168cb6d64f231f518a82e`，tag 的 [`VERSION.dat`](https://github.com/openssl/openssl/blob/openssl-3.6.1/VERSION.dat) 字段为 `MAJOR=3, MINOR=6, PATCH=1`。OpenSSL 官方 [3.6 EVP ML-DSA 文档](https://docs.openssl.org/3.6/man7/EVP_SIGNATURE-ML-DSA/)说明有 ML-DSA primitive；这些源码/文档仍**不证明默认构建的 TLS 全链 CertificateVerify + RFC 9881 X.509 + 双向认证**。目前脚本将该项交给 s_server/s_client CI 实际验证；CI 尚未运行，不能称通过。
- `[事实·协作取证，更正]` lead 后续说明：本地 `.local/rust-stable-manifest.toml` 是不提交的 stable manifest 取证文件，字段 `date=2026-11-12`、`cargo=1.100.0`；此前给出的 `23969614DD3F027EF8828B831F170BBBCAA3C29C99E93BEC20F5983F685086AA` **不是该 manifest 的 SHA-256，而是主计划文件 SHA-256**，故不可引用为 manifest 哈希。lead 表示正在 rustup update stable；本文作者未直接读取 manifest，manifest 的真实 hash 尚待 lead 计算/复核。
- `[待证]` 本次没有在 Linux x86_64 或 aarch64 编译、运行、互操作任何 TLS PoC。因此不得写“G-CRYPTO 通过/后端完整支持/静态发行可行”。
- `[设计]` 不接受静默经典 KEX 回落，不造 TLS 扩展、不恢复 PQ-IK。Cipher suite 目标必须逐项检查 AES-256-GCM 和 ChaCha20-Poly1305，并且在外层 WSS 与逐跳内层会话中分别报告协商结果。

## 标准与状态证据

| 项目 | 本次观察 | 工程含义 | 一手来源 |
|---|---|---|---|
| TLS 1.3 | RFC 9846，Standards Track，2026-07；取代 RFC 8446。更新包含 key_share 禁止跨连接复用和按 AEAD 使用限额及时 KeyUpdate 等要求。 | TLS 版本/记录策略基线采用 RFC 9846；完整握手必须生成新临时 key_share。 | [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html) |
| Hybrid KEX | RFC 10024，Standards Track，2026-08。`X25519MLKEM768` 是推荐组，值 4588 / `0x11EC`；定义另外两组。 | 必须验证实际协商 group，不以存在 ML-KEM API 或配置名作证。 | [RFC 10024 §2, §7](https://www.rfc-editor.org/rfc/rfc10024.html) |
| X.509 ML-DSA | RFC 9881，Standards Track，2025-10；定义 ML-DSA-44/65/87 的 X.509/CRL AlgorithmIdentifier / OID。ML-DSA keyUsage 不可用于 keyAgreement。 | 证书生成、DER 解析、链签名验证、用途限制要单独验证；证书签名算法支持不自动代表 TLS `CertificateVerify` 支持。 | [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) |
| TLS ML-DSA | Datatracker 当前页面显示 `draft-ietf-tls-mldsa-06` active draft，提交 IESG publication，IESG state `RFC Ed Queue`，RFC Editor state `Awaiting First editor`；更新时间 2026-10-12，最新版修订 2026-09-11。 | 仅能标为 draft。草案拟定的 0x0904/05/06 需版本钉定，并监视后续 RFC/registry 改变。 | [IETF Datatracker: draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)；[draft -06 原文](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-06.txt) |
| Rust stable | 当前尝试访问 `https://static.rust-lang.org/dist/channel-rust-stable.toml` 返回工具层 `application/octet-stream` 不支持；未拿到可读清单，未运行 rustup。 | 不确认也不否认计划文档所述 1.100.0；Phase 开始当天须从清单校验版本、日期、manifest hash，并在 ADR 记录抓取时间/哈希。 | [Stable manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml) |

### TLS ML-DSA 草案的精确含义

草案 -06 把签名方案值映射至 RFC 9881 OID，并要求 `CertificateVerify` 按 RFC 9846 的上下文规则调用 FIPS 204 `ML-DSA.Sign/Verify`（ctx 为空）。因此合格能力不是“能生成 ML-DSA 密钥/证书”：TLS 实现须在 `signature_algorithms` / `signature_algorithms_cert`、证书解析/链验证、服务器端 CertificateVerify 和客户端证书验证路径都接通同一规则。草案建议的值在其 IANA 表中 `Recommended=N`，且文件明确标为 Internet-Draft。

## 后端选型矩阵（源码审查后的候选，不代表实测）

| 候选 | Hybrid KEX / ML-KEM | ML-DSA TLS认证 / X.509 | Rust 整合与静态 Linux | 当前建议 |
|---|---|---|---|---|
| OpenSSL 3.6.1 `openssl-3.6.1` tag + CLI | 3.6.1 为固定维护 patch release（2026-01-27；OpenSSL政策称非 LTS release至少受支持13个月）。2026-11-14 检索时上游最新版本已是 4.1.0；本轮选用 3.6.1 是计划规定的 3.6+ 目标稳定分支，避免在 smoke test 内引入 OpenSSL 4.x major API/ABI变化，非声称其比4.1更新。tag源码默认 group list 含 `X25519MLKEM768`。 | 同一 tag 有 TLS-SIGALG provider discovery，官方 3.6 EVP docs 有 ML-DSA 原语；但未证明 stock default provider 确实注册 TLS `mldsa65`、CertificateVerify 与 RFC 9881 X.509 全链。提供的 CI PoC 对双方用同一个 OpenSSL CLI，只能验证同实现互通。 | `no-shared` 构建 libcrypto/libssl 静态链接 CLI；本 workflow 用 `readelf -d` 拒绝这两个 OpenSSL shared deps，明确不是 fully-static libc 程序。 | **第一 PoC 候选，GitHub Actions backend smoke PoC 已落文件，未执行。** 等 lead 推送后查看 Actions logs/artifact；不代表完整 G-CRYPTO。 |
| rustls 0.23 + aws-lc-rs / aws-lc-sys | rustls 最新 GitHub release 本次观察为 0.23.46（2026-10-14）；需核查该 tag 对 hybrid KEX 和 key share 的具体实现/feature gating。计划书既有的 0.23.35 AWS-LC 默认 provider 源码清单缺 ML-DSA sig mapping，只能说明旧版本当时不满足；不能外推最新版本。 | 要核验最新版本是否支持 ML-DSA 签名方案、RFC 9881 X.509 解析，以及客户端证书双向认证；不能以 AWS-LC 有 primitive 代替 TLS 接线。 | Rust 原生 API 和可静态链接潜力有吸引力；仍须在两目标架构构建验证，AWS-LC 本身含原生构建/目标限制。 | **第二候选/关键反证对象**：先做 tag/source 级能力查证；若任一缺项则停止，不 fork 自造扩展。 |
| OpenSSL-compatible provider (如 oqs-provider) + OpenSSL | 可借 OpenSSL provider 机制扩展 KEM/groups；必须针对稳定版本、算法名和标准组分别确认。不可将实验 provider 或旧草案组当 RFC 10024。 | Provider 可动态暴露 TLS-SIGALG；要核实 provider 声明草案代码点与证书 OID/CertificateVerify 完整一致且有维护承诺。 | provider 动态模块会与静态单二进制目标冲突；须验证静态链接或将模块打包且可重现。 | **探索性候选**：只有维护状态、精确 draft 版本、双架构静态路径同时过审才入围。 |
| 纯 Rust 组合（其他 TLS crate + PQ 原语 crate） | 若 TLS 实现仅支持经典组或需要外部拼接 hybrid，共享秘密拼接/自建扩展不合格。 | 原语 crate 不等于 TLS CertificateVerify 或 X.509 PKIX。 | 编译容易不等于协议实现满足；维护性与完整度待查。 | 不作为默认候选；除非维护者已实现标准规范全层且有跨实现互操作证据。 |

**原则**：现在没有通过“完整支持”一列的已证实候选。OpenSSL 排在首位是 PoC 优先级，不是选型结论。rustls 0.23.46 的 release 页面本次还显示与 classical X25519 key-share hint 有关的安全修复，说明不应把旧版本结果沿用；按实际 release 管理/安全通告更新依赖。

## 可执行 PoC 计划与门禁

### 0. 固定输入、留证

1. 从 Rust stable channel manifest 读取 stable release、date、commit/hash；写入 `rust-toolchain.toml`（release 可复现 pin）与 CI artifact 元信息。每个 Phase 开工重新抓取 manifest，差异记 ADR。
2. 锁定 OpenSSL tag/commit、provider tag/commit、rustls tag/commit、AWS-LC tag/commit、构建镜像 digest、Cargo.lock、target triple；保存源码审查链接和 SHA-256。禁止浮动 `main/master` 的构建作为验收证据。
3. 固定最低策略：TLS 1.3 only；只启用 `X25519MLKEM768` (`0x11EC`)；只允许 `TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`；ML-DSA-65（ML-DSA-87可另记扩展）。TLS ML-DSA 暂依草案 -06 的 `mldsa65 (0x0905)`，若 RFC 发布或草案变动先 ADR 更新。

### 1. 单一进程、双向认证握手（G-CRYPTO 核心）

- 在同一 PoC 进程内运行本地 HTTPS/WSS 外层与 WebSocket binary stream 中的独立内层 TLS；WS frame 任意分割/合并，TLS byte-stream framing 不依赖 WebSocket message boundaries。
- 创建测试 CA/双方 ML-DSA-65 身份证书（按 RFC 9881 DER），并创建客户端/服务器端互信链。验证两端均提交证书及 CertificateVerify；应用层验证 net_id / role / node identity 另做断言，不能只靠 TLS handshake 成功。
- 记录 ClientHello/ServerHello 结构化遥测：TLS 版本、group ID、signature scheme、cipher suite、双方证书 SPKI OID及链验证结果。应实际记录 group `0x11EC`、scheme `0x0905`，不允许从 config 假设推导。
- 负测试：服务端只接受 classical group、移除 ML-DSA 能力、错用证书 OID、坏链、服务端证书代客户端、客户端证书缺失、wrong role/network、签名失败、指定 AEAD 不重叠、尝试 TLS 1.2/0-RTT/PSK-only。全部必须失败关闭，不得静默降级。
- 用第二个独立维护的 TLS 实现对同一配置/证书做 client-server 互操作；记录版本与 pcap/日志。仅同实现自测不算互操作。

### 2. 外层与内层分开判定

外层 HTTPS/WSS 可以由 CDN 或公开 TLS 栈终结，不将外层 classical KEX 误报为内层失败；外层测试只验证 HTTPS策略和记录实际协商组。G-CRYPTO 核心必须证明 WS payload 内层独立协商 hybrid + ML-DSA 双向认证，不能拿外层协商结果替代。

### 3. 双架构静态门禁

在 Linux x86_64 和 aarch64（真实目标机或可验证的本机 runner）分别从干净锁定环境构建静态 musl 产物；运行 `file/readelf`、`ldd`/loader检查、依赖闭包审计及启动/密钥读取/握手测试。产物无意外动态依赖；记录 provider/modules 实际装载路径。交叉编译成功不代替 aarch64 上实际执行握手。必要时使用原生 aarch64 runner，不能用 QEMU 的单次成功代替性能/内存实机验收。

### 4. AEAD 和鲁棒性矩阵

- 每个候选 AEAD 单独启动握手、传输多 record payload、检查协商值与双端解密一致；若平台/后端不支持其中之一，不能宣称该后端完整满足计划要求。
- 各架构记录 key share 大小、ML-DSA证书/签名尺寸、握手 CPU/墙钟、最大握手内存、峰值 RSS；不填虚构性能指标。
- 连续连接验证 key_share 每连接新鲜；重连完整握手。验证证书大尺寸下的资源上限、畸形握手拒绝、KeyUpdate/AEAD 限额行为。
- `pq1024` 另立测试 profile：RFC 10024 `SecP384r1MLKEM1024` + ML-DSA-87，做独立端到端双实现 PoC；不作为 `pq768` 通过的推论。

### 5. 当前仓库 PoC 实现边界与 GitHub Actions 运行方法

- `tools/crypto-poc/run-openssl-mtls.sh` 与 `.github/workflows/crypto-poc.yml` 是**后端冒烟测试**，基于固定 OpenSSL `3.6.1` tag 和 release tarball SHA-256 `b1bfedcd5b289ff22aee87c9d600f515767ebf45f77168cb6d64f231f518a82e`，仅应在 GitHub Actions 中构建/运行。workflow 对 `openssl` CLI 做 OpenSSL shared lib 依赖检查；**不声称完全静态 libc**。PoC 仅 Linux x86_64 runner，不等同 Linux aarch64。
- 脚本生成 ML-DSA-65 root/server/client 证书，在仅 `X25519MLKEM768`、`mldsa65`、指定 TLS 1.3 AEAD 条件下，用相同 OpenSSL `s_server`/`s_client` 测试两套 AEAD 正向 mTLS，并用 `-WWW` 请求临时工作目录中的固定静态 HTTP 响应；临时响应只有非秘密成功标记。负测要求 classical-only group、无 client cert、AEAD 不交叠、未来时间下短期 client cert 过期均出现明确拒绝。负测非零 exit 本身不算通过：要求日志包含预期 TLS/证书拒绝原因，排除 timeout 和明显 CLI/文件设置错误。首轮真实日志暴露 server verbose certificate verify evidence不完整，当前改用 `-verify_verbose` 并要求 issuer depth、leaf depth 与 `verify return:1`；该断言未在最新 Actions验证，可能需基于新原始日志调准，不可降低验证实质。
- FIFO 保持 server stdin 不发生 EOF；`ss` readiness 不建立 probe 连接；客户端 `-ign_eof` 保持接收 server 的响应，server 有 `naccept=1`、40 秒 timeout。server/client 均配置 `-no_ticket`，server `-num_tickets 0`。OpenSSL原始 TLS命令输出（可能含 TLS session PSK）只在脚本私有临时目录；EXIT trap抽取严格 allowlist诊断/协商行、敏感标记扫描，随后清除原始日志和私钥。artifact 只含证书公有信息文本、已过滤协议/错误日志、版本/依赖信息、无私钥上游源码压缩包，**不得上传任何测试私钥/私密 CSR/包含私钥的工作目录或 session secret**。已上传的先前实验artifact包含 TLS Resumption PSK，lead确认artifact ID `14117716318`已删除；不要再引用该旧artifact作为可留存证据。
- 该 smoke test 是同一 OpenSSL 实现的 `s_server` 与 `s_client` 互通，**不是第二个独立 TLS 实现互操作，更没有 WebSocket、Rust FFI 或 Boreas 内层 transport**。首次 GitHub Actions（lead提供的日志 `.local/crypto1.log`，run 2249）已成功完成下载 hash 校验及 OpenSSL 静态库/CLI构建，但脚本因 `install_sw` 没安装 `${OPENSSL_PREFIX}/ssl/openssl.cnf`，在生成证书阶段失败。当前脚本已在私有临时目录显式生成最小 OpenSSL 配置（仅激活内建 default provider），设置 `OPENSSL_CONF`，并复制不含密钥的该配置到证据目录。该修正尚未由下一次 Actions 验证；状态为“待重跑 CI”，不是 PoC 通过。

### 6. 证据包与判定

交付最少包含：ADR（规范/draft 版本、代码点和升级路径）、提交哈希与构建日志、每架构二进制/依赖闭包、证书样例及其 RFC 9881 OID 检查、双向握手日志、协商参数抓取、互操作记录、正负测试结果、失败场景和限制。G-CRYPTO 仅在以上真实端到端握手 + 双向认证 + hybrid group + 两种 AEAD + 双实现互操作 + x86_64/aarch64 静态构建及运行全部完成后，才由有权限的验收者给出结论。**本文没有执行上述 PoC，当前状态：未验收 / G-CRYPTO 未通过（尚未测）。**

## 原始观察链接

- [RFC 9846 TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846.html)
- [RFC 10024 TLS 1.3 hybrid groups](https://www.rfc-editor.org/rfc/rfc10024.html)
- [RFC 9881 ML-DSA certificates and CRLs](https://www.rfc-editor.org/rfc/rfc9881.html)
- [IETF Datatracker draft status](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)
- [draft-ietf-tls-mldsa-06 source](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-06.txt)
- [Rust stable manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml)
- [OpenSSL 3.6.1 fixed source: ssl/t1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.6.1/ssl/t1_lib.c)
- [OpenSSL 3.6.1 TLS scheme constants: ssl_local.h](https://github.com/openssl/openssl/blob/openssl-3.6.1/ssl/ssl_local.h)
- [OpenSSL 3.6.1 VERSION.dat](https://github.com/openssl/openssl/blob/openssl-3.6.1/VERSION.dat)
- [OpenSSL 3.6.1 release artifact/API SHA-256 metadata](https://api.github.com/repos/openssl/openssl/releases/tags/openssl-3.6.1)
- [OpenSSL 3.6 ML-DSA EVP docs](https://docs.openssl.org/3.6/man7/EVP_SIGNATURE-ML-DSA/)
- [OpenSSL release versioning/support policy](https://openssl-library.org/policies/general/versioning-policy/index.html)
- [OpenSSL 4.1.0 latest release snapshot observed](https://github.com/openssl/openssl/releases/tag/openssl-4.1.0)
- [AWS-LC ML-KEM source: kem.c](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/kem/kem.c)
- [rustls 0.23.46 release snapshot observed](https://github.com/rustls/rustls/releases/tag/v/0.23.46)
- [rustls repository](https://github.com/rustls/rustls)
- [aws-lc-rs repository](https://github.com/aws/aws-lc-rs)
