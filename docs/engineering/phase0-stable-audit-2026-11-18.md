# Phase 0 稳定版本与 §4.2 标准引用审计（2026-11-18）

范围：主计划 BOREAS-MASTER-PLAN-v1.11.0.md §4.2
（第 241–267 行）的标准引用，以及截至 2026-11-18 的 Rust stable、OpenSSL stable/security release、
ML-DSA in TLS 的标准状态。本文只做只读审计，不改 source、CI、workflow 或 gate 策略，不把任何
CVE 标成 waiver，也不声称实现验收或独立审计。

方法与边界：

- 只读官方来源：`static.rust-lang.org`、`openssl-library.org`、`www.rfc-editor.org`、
  `datatracker.ietf.org`、`api.github.com/repos/openssl/openssl`。HTML/文本用 `web_fetch` 读取；
  需要逐字节 SHA-256 与 HTTP 状态时，用 bundled Python 的 `urllib` 只读 GET，**未运行本地构建/测试/格式化**。
- 抓取时间：2026-11-18 06:28–06:40 +08（2026-11-17 22:28–22:40 UTC）。动态页面与 manifest
  会变化，本文 hash 只对应此时间窗。
- `web_fetch` 无法读取 `binary/octet-stream` 的 manifest；其原始字节与 hash 由上述只读 GET 取得，
  HTTP 状态、字节数与 hash 均记录在 §7。

## 1. 结论摘要

| 项目 | 官方当前事实（2026-11-18） | 对本计划的结论 |
|---|---|---|
| Rust stable | `channel-rust-stable.toml` 的 manifest date 为 **2026-11-12**；rustc **1.100.0 (0ef1bc386 2026-11-09)**，git commit `0ef1bc386059596dada8fb65b50425aab2ea637a`；manifest SHA-256 `3051e859570f64a8c5acb9d09e87425db52c7d97287c67e8f6d57d7d34ef9258`，与官方 `.sha256` 一致 | 仓库 `Cargo.toml` MSRV `1.100` 与 `rust-toolchain.toml` 的 `stable` 当前解析一致，**无漂移**；发布前应把 `stable` 固定到 `1.100.0` 并记录 manifest hash，避免 runner 时间差 |
| OpenSSL stable | 支持分支最新版：**4.1.0**（2026-10-23，EOL 2027-11-23）、**4.0.3**（2026-09-29，EOL 2027-05-14）、**3.5.9 LTS**（2026-09-29，EOL 2030-04-08）；4.1.1/4.0.4/3.5.10 **未发布**（tag 均 HTTP 404），官方公告称修复版本计划 **2026-12-01** | 当前后端 pin 的 4.1.0 仍处于 8 个 CVE 的 affected range，**native gate 必须继续 RED**；不得把 4.1.0 的 reduced build 当 CVE waiver |
| OpenSSL security | 20261110 公告 5 个 CVE + 20261117 公告 3 个 CVE，合计 8 个；均影响 4.1/4.0/3.5；修复版本为 4.1.1/4.0.4/3.5.10；全部 Low；两公告均称修复版本 **2026-12-01** 发布 | **当前没有任何已发布的受支持 OpenSSL 版本同时清除这 8 个 CVE**；4.0.3/3.5.9 也受影响，降级不是安全修复 |
| TLS 标准引用 | RFC 9846（TLS 1.3，2026-07，Standards Track，Obsoletes 含 RFC 8446）、RFC 10024（PQ/T hybrid KEX，2026-08，Standards Track）、RFC 9881（ML-DSA X.509/CRL，2025-10，Standards Track）、RFC 5280（X.509 基础 profile，2008-05，Standards Track）均存在且标题/状态相符 | §4.2 的这些引用基本准确；RFC 9846 是 **同版本 TLS 1.3 的 minor update**，不是新版本号；RFC 5280 仍有效但已被多个 RFC 更新 |
| ML-DSA in TLS | **没有 RFC**。`draft-ietf-tls-mldsa-06` 为 Active Internet-Draft（tls WG），Intended status **Informational**，2026-10-12 更新、2026-09-11 最新修订，Expires **2027-03-15**；IESG 状态 **RFC Ed Queue**，RFC Editor 状态 **Awaiting First editor**，IANA review **Version Changed - Review Needed**；`rfc=null` | 不得把 ML-DSA TLS CertificateVerify 写成“RFC 标准”；实现只能显式引用 draft-06 并记录修订与互操作证据。RFC 9881 只覆盖 X.509/CRL 编码，不覆盖 TLS 握手 |
| 最小安全路径 | 没有可立即采用的“安全 OpenSSL 版本” | 保持 production 冻结与 gate RED；优先等 **4.1.1**，其次 **3.5.10 LTS**；不降级、不 waiver、不把本地补丁或 reduced build 当修复 |

## 2. §4.2 逐条核对

| 计划位置与断言 | 官方证据（2026-11-18） | 判定 |
|---|---|---|
| L257：内层 TLS 遵循 **RFC 9846**，取代 RFC 8446 | RFC 9846《The Transport Layer Security (TLS) Protocol Version 1.3》，July 2026，Category: Standards Track；`Obsoletes: 5077, 5246, 6961, 7627, 8422, 8446`；`Updates: 5705, 6066`。摘要说明它是 **same version 1.3 的 minor update**，obsoletes RFC 8446 | **准确，但措辞可更精确**：应写“obsoletes RFC 8446 的同版本 minor update”，而不是暗示新的 TLS 版本；它同时 obsoletes RFC 5246 等，计划只列 8446 是不完整的列举 |
| L257：RFC 9846 含“临时 `key_share` 不得跨连接复用” | RFC 9846 §1.2：`Clients and Servers MUST NOT reuse a key share for multiple connections.` 同段紧接着：`Because [RFC8446] permitted reuse, receiving implementations MUST permit reuse by the peer in order to prevent interoperability issues.` | **发送端准确，接收端需澄清**：实现可以在发送端强制“不复用”，但**不得仅因对端复用 key_share 就拒绝握手**；否则违反 RFC 9846 的互操作要求。§4.2 的“不得跨连接复用”应明确为发送端规则 |
| L257：RFC 9846 含 KeyUpdate 与 AEAD 使用上限要求 | RFC 9846 §1.2 将“在超过 key usage limits 前发起 key update”的要求升级为 MUST，并限制 KeyUpdate 消息数量；§5.5 给出 AES-GCM 约 `2^24.5` full-size records 的界限，并说明接收端 SHOULD NOT 强制这些界限 | **准确**；计划 L275 的 `2^24.5` 记录数限制与 RFC 9846 §5.5 一致 |
| L257：RFC 10024 定义 TLS 1.3 混合密钥交换 | RFC 10024《Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3》，August 2026，Standards Track；摘要定义 **三个**组：`X25519MLKEM768`、`SecP256r1MLKEM768`、`SecP384r1MLKEM1024` | **准确但不完整**：计划只提两个组，RFC 实际定义三个；不影响默认/高敏选择的正确性，但应避免把 RFC 10024 简写成只定义两组 |
| L258：默认仅允许 `X25519MLKEM768` | RFC 10024 §7.1：`Value: 4588 (0x11EC)`，`Recommended: Y`，Reference RFC 10024 | **准确**；IANA Recommended=Y 与“默认”选择一致 |
| L259：高敏套件可选 `SecP384r1MLKEM1024` | RFC 10024 §7.3：`Value: 4589 (0x11ED)`，`Recommended: N`，Reference RFC 10024 | **准确**；但它是 IANA `Recommended: N` 的组，计划应保留“独立实现与互操作证据”的 `[待证]` 限定，不能因为 RFC 定义了就自动可部署 |
| L263：X.509/CRL 编码遵循 RFC 5280 与 RFC 9881 | RFC 5280 May 2008，Standards Track，X.509 Certificate/CRL Profile；RFC 9881 October 2025，Standards Track，定义 ML-DSA-44/65/87 在 X.509/CRL 中的 AlgorithmIdentifier 与公钥/私钥编码，并明确 **禁用 HashML-DSA** | **准确但不完整**：RFC 5280 仍是基础 profile，但 RFC Editor index 显示它已被 RFC 6818、8398、8399、9549、9598、9608、9618、9925、10007 更新；只引 5280 不足以描述当前 profile。实现还必须遵守 RFC 9881 对 pure ML-DSA 的限制，不得使用 HashML-DSA |
| L261–263：节点身份使用 ML-DSA X.509 证书与 TLS `CertificateVerify` | **ML-DSA in TLS 1.3 尚无 RFC**；`draft-ietf-tls-mldsa-06` 是 Active Internet-Draft，Intended Informational，定义 `mldsa44/65/87` 为 `0x0904/0x0905/0x0906`，并引用 RFC 9846 §4.5.2 与 RFC 9881 OID；当前在 RFC Editor 队列（Awaiting First editor） | **设计可保留，但不能称 RFC/标准**：计划应把该认证路径标注为 draft-06 依赖，并固定 draft 修订、代码点与互操作证据；在 RFC 发布前不得写“RFC-compliant ML-DSA TLS” |
| L275：AES-GCM 不得超过 `2^24.5` 条记录 | RFC 9846 §5.5 原文说明 AES-GCM 在单组密钥下最多约 `2^24.5` full-size records，并保留约 `2^-57` AE 安全边际 | **准确** |
| L267：rustls 0.23.35 默认 provider 不满足要求 | 本次审计范围是标准与稳定版本，**未重新逐行核对 rustls 0.23.35 源码**；该断言仍应保留其原始 `[事实]` 来源与复核记录 | **未复核**：不作为本次结论，也不据此改变 rustls 选型 |

### 2.1 需要修订的措辞

1. 把“RFC 9846 取代 RFC 8446”改为“RFC 9846 是 TLS 1.3 同版本 minor update，obsoletes RFC 8446（并 obsoletes RFC 5246/5077/6961/7627/8422，updates RFC 5705/6066）”。
2. 把“临时 key_share 不得跨连接复用”明确为**发送端**要求；接收端必须允许对端复用，避免把 RFC 9846 的互操作条款实现成 fail-closed 拒绝。
3. 把 RFC 10024 写成“定义三个 PQ/T 组”，不要只列两个；`SecP384r1MLKEM1024` 是 IANA `Recommended: N`，其部署仍需独立证据。
4. 把 RFC 5280 写成“基础 profile，另有多个更新 RFC”；密钥/证书扩展的当前语义应以 RFC 5280 + 更新文档 + RFC 9881 一起描述。
5. 任何涉及 ML-DSA TLS CertificateVerify 的文案，改为“draft-ietf-tls-mldsa-06（Informational，RFC Editor 队列）”，不要写 RFC 编号或“已标准化”。

## 3. Rust stable manifest（2026-11-18 抓取）

官方 `channel-rust-stable.toml` 当前内容：

| 字段 | 值 |
|---|---|
| URL | <https://static.rust-lang.org/dist/channel-rust-stable.toml> |
| HTTP | 200，893,976 bytes |
| SHA-256 | `3051e859570f64a8c5acb9d09e87425db52c7d97287c67e8f6d57d7d34ef9258` |
| Last-Modified | Thu, 12 Nov 2026 18:18:49 GMT |
| ETag | `"1d9a13865baced1cef62ffd50a86f6bb"` |
| manifest date | **2026-11-12** |
| `[pkg.rust] version` | **1.100.0 (0ef1bc386 2026-11-09)** |
| `[pkg.rust] git_commit_hash` | `0ef1bc386059596dada8fb65b50425aab2ea637a` |
| `[pkg.cargo] version` | `0.101.0 (3acc79c0c 2026-11-05)` |

官方 `.sha256`（<https://static.rust-lang.org/dist/channel-rust-stable.toml.sha256>，HTTP 200，91 bytes，
SHA-256 `81d394d7eee8d7e3d22efaee66abaaf6dceac125a4ba7369ac8fff5fa73b058e`）内容为：

```text
3051e859570f64a8c5acb9d09e87425db52c7d97287c67e8f6d57d7d34ef9258  channel-rust-stable.toml
```

与上面计算的 manifest SHA-256 完全一致。

仓库现状（只读）：

- `Cargo.toml` 的 `rust-version = "1.100"`。
- `rust-toolchain.toml` 的 `channel = "stable"`，组件为 `rustfmt`/`clippy`。
- 因此当前 CI 的 stable 解析到 1.100.0，**与官方 manifest 无版本漂移**；但 `stable` 是移动目标，
  发布构建应固定 `1.100.0` 并记录 manifest SHA-256，避免 runner 在发布窗口内升级。

## 4. OpenSSL stable 与 security release

### 4.1 官方支持分支（2026-11-18）

来源：<https://openssl-library.org/source/>（HTTP 200，43,229 bytes，SHA-256
`23b2134bfa558c643da77fed5ce8c511986e7492b2fecfbbab5c40908d3a007c`，Last-Modified
Tue, 17 Nov 2026 08:48:23 GMT）。官方表格只列以下三个支持分支：

| 分支 | 最新 release | 发布日期 | EOL | 2026-11 公告影响 | 修复目标 |
|---|---|---|---|---|---|
| 4.1 | **4.1.0** | 2026-10-23 | 2027-11-23 | 8 个 CVE | 4.1.1（未发布） |
| 4.0 | **4.0.3** | 2026-09-29 | 2027-05-14 | 8 个 CVE | 4.0.4（未发布） |
| 3.5 LTS | **3.5.9** | 2026-09-29 | 2030-04-08 | 8 个 CVE | 3.5.10（未发布） |

官方页面明确：“All versions not listed above are out of support and should not be used in production.”
3.6 不在表内，公告也明确 3.6 已 out of support。

### 4.2 两份 2026-11 安全公告

| 公告 | 日期 | 字节/SHA-256 | CVE | 受影响分支 | 修复版本与时间 |
|---|---|---|---|---|---|
| [20261110](https://openssl-library.org/news/secadv/20261110.txt) | 2026-11-10 | 11,780 / `31f4c88950cd9cd310794a218361b787d293a940d2568f9f82334915ac54a402` | CVE-2026-88822、88823、95691、95692、107496 | 5 项均影响 4.1/4.0/3.5；107496 还影响 3.0/1.1.1/1.0.2 | 4.1.1 / 4.0.4 / 3.5.10；计划 2026-12-01 |
| [20261117](https://openssl-library.org/news/secadv/20261117.txt) | 2026-11-17 | 8,844 / `6f4219cd823c3472863cc592182ef571d7485ac2f8735845244dbc13e3e09f27` | CVE-2026-35190、107493、124709 | 35190/124709 影响 4.1/4.0/3.5；107493 影响所有分支（含 3.0/1.1.1/1.0.2） | 4.1.1 / 4.0.4 / 3.5.10；计划 2026-12-01 |

合计 **8 个 CVE，severity 均为 Low**。按公告原文归类：

| CVE | 路径/影响 | 4.1.0 reduced options 是否移除 |
|---|---|---|
| CVE-2026-88822 | QUIC automated peer detection 未初始化栈字节 | `no-quic` 是 build-removal 候选，需要编译/运行时证据 |
| CVE-2026-95691 | QUIC retransmitted CRYPTO 帧 DoS/1-byte disclosure | `no-quic` 候选 |
| CVE-2026-124709 | QUIC server 对 rejected stream 无界保留内存 | `no-quic` 候选 |
| CVE-2026-88823 | AES-GCM-SIV 零长度 incremental AAD 伪造 | `no-siv` 候选；普通 AES-GCM 不受此路径影响 |
| CVE-2026-95692 | AES-GCM-SIV 越界读/IV 长度 | `no-siv` 候选 |
| CVE-2026-107496 | CMS `CMS_encrypt()` EC group order=1 无限循环 | `no-cms` + 未启用 explicit curves 候选 |
| CVE-2026-35190 | TLS 1.3 Suite B 证书标志下的 key-share 越界读 | **不由此三项 options 移除**；只有调用 `SSL_CTX_set_cert_flags(SSL_CERT_FLAG_SUITEB_128_LOS)` 且启用 TLS 1.3 的 server 受影响，但“项目未调用”本身不是 waiver |
| CVE-2026-107493 | `PEM_X509_INFO_read_bio_ex()` 调用方传入非 NULL stack 时的 UAF | **不由此三项 options 移除**；OpenSSL 自身调用传 NULL，但第三方调用路径需独立审查 |

结论：即使采用 `no-quic/no-cms/no-siv` 的 4.1.0 构建，最多只能把 6 个 CVE 作为**build-removal
候选**处理；CVE-2026-35190 与 CVE-2026-107493 仍然存在。且 build-removal 候选需要
`configuration.h`/configdata/静态符号/运行时注册/mTLS 证据，不能只凭“未调用某个 API”放行。

### 4.3 修复版本确实未发布

2026-11-18 复核：

- GitHub release tag `openssl-4.1.1`、`openssl-4.0.4`、`openssl-3.5.10` 均返回 **HTTP 404**
  （响应体 133 bytes，SHA-256 `010563d2cfb8f1e87f700936ce59ee3a33364da46e3db41b0049227918ece74d`）。
- `releases/latest` 返回 **openssl-4.1.0**（published `2026-10-23T12:23:31Z`），asset digest
  `sha256:50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd`。
- 官方 `openssl-4.1.0.tar.gz.sha256`（HTTP 200，87 bytes，SHA-256
  `8305ea87f3cf009165928a27745094d2fbab68ba53e2b2dc00faae541e05fe66`）内容为
  `50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd *openssl-4.1.0.tar.gz`。
- 官方下载表的最新行仍是 4.1.0/4.0.3/3.5.9，没有 4.1.1/4.0.4/3.5.10。

**因此不得**从 tag 名称、计划日期或 advisory 文本推断 4.1.1 的 SHA-256、构建产物或可用性。

### 4.4 当前后端状态

仓库当前 pin（只读核对）：

- `tools/dependencies/openssl-review.json`：`version: 4.1.0`；release SHA-256
  `50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd`；gate `RED`；
  `affected_ranges` 包含上述 8 个 CVE；`fixed_release_availability.available: false`。
- `.github/workflows/crypto-poc.yml:33-34`、`openwrt.yml:60-61`、`rust-tls.yml:53-54` 均 pin
  `OPENSSL_VERSION: 4.1.0` 与同一 SHA-256。
- 该 4.1.0 的 reduced build 仍不是 CVE waiver：8 个 CVE 中 35190/107493 不在
  `no-quic/no-cms/no-siv` 的移除范围，且没有任何已发布 fixed release 可用于替代。

## 5. ML-DSA in TLS 的标准状态

### 5.1 官方状态

`draft-ietf-tls-mldsa-06`（<https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/>，HTTP 200，
60,237 bytes，SHA-256 `6565e0dff8224cec58eccca7d6b6421fe4a07162df4cecf31b366557df47679c`）：

| 字段 | 值 |
|---|---|
| 标题 | Use of ML-DSA in TLS 1.3 |
| 类型 | Active Internet-Draft（tls WG） |
| Intended RFC status | Informational |
| 最新修订 | 06（2026-09-11）；页面 last updated 2026-10-12 |
| Expires | 2027-03-15 |
| WG state | Submitted to IESG for Publication |
| IESG state | RFC Ed Queue |
| RFC Editor status | Awaiting First editor |
| IANA review | Version Changed - Review Needed |
| RFC number | **null（尚无 RFC）** |

Datatracker API（HTTP 200，1,277 bytes，SHA-256
`81050c252629ef6236e40c71f6a92d6109e6ff96a72051f468ca89d60264e9c0`）同时给出
`rev=06`、`rfc=null`、`rfc_number=null`、`intended_std_level=.../inf/`。

draft-06 的关键技术内容（官方 draft 文本）：

- 定义 `mldsa44(0x0904)`、`mldsa65(0x0905)`、`mldsa87(0x0906)` 三个 TLS `SignatureScheme`，
  并分别映射到 RFC 9881 的 `id-ML-DSA-44/65/87` OID（`2.16.840.1.101.3.4.3.17/18/19`）。
- `CertificateVerify` 的签名/验签按 RFC 9846 §4.5.2；ML-DSA 的 `ctx` 参数必须为空字符串。
- IANA 表中三个值均为 `Recommended: N`，并明确“未由 IETF 评估 suitability”。

### 5.2 没有 RFC

RFC Editor 的完整 `rfc-index.xml`（HTTP 200，13,756,401 bytes，SHA-256
`3ed6d6f692806468b8b8bd9501421d03705273ff39961a3673724271eba60eb3`）中，标题含
`ML-DSA`/`Module-Lattice` 的 RFC 只有：

- RFC 9881：ML-DSA in X.509/CRL；
- RFC 9882：ML-DSA in CMS；
- RFC 9935：ML-KEM in X.509；
- RFC 9964：ML-DSA for JOSE/COSE；
- RFC 10042：ML-KEM hybrid for SSH；
- RFC 10073 / 10082：composite ML-DSA for X.509/CMS。

**没有任何“Use of ML-DSA in TLS 1.3”RFC**。因此：

- RFC 9881 只解决证书/CRL 编码，不等于 TLS `CertificateVerify` 的标准；
- `draft-ietf-tls-mldsa-06` 是当前唯一可引用的公开规范文本，且仍是 Internet-Draft；
- 任何实现/文档不得写“RFC 标准 ML-DSA TLS”或暗示已有 RFC 编号。发布前应重新核对 RFC Editor
  队列；若 draft 升为 RFC，再更新引用与 IANA 代码点。

### 5.3 与 OpenSSL 4.1.0 的关系

OpenSSL 4.1.0 的官方 `CHANGES.md`（HTTP 200，928,861 bytes，SHA-256
`bd15a960aed3737d9a76e945089f46869f934c96155f130316773fe4e85462b6`）写明
“The TLS Signature algorithms defaults now include all three ML-DSA variants as first algorithms”，
并列出 `mldsa65:mldsa87:mldsa44:...`。这说明 OpenSSL 4.1.0 已暴露 ML-DSA TLS 签名算法，
但**官方 CHANGES 并未把它宣称为 RFC**；标准状态仍是 draft-06。实现侧应记录：

- 使用的 draft 修订（当前 06）与代码点（0x0904–0x0906）；
- 与另一独立实现的互操作证据；
- 若 OpenSSL 后续按新 draft 修订改变代码点/行为，必须重新做互操作与回归。

## 6. 当前可采取的最小安全版本路径

### 6.1 不接受的路径

| 路径 | 为什么不是安全修复 |
|---|---|
| 继续把 4.1.0（含 reduced options）作为生产后端 | 8 个 CVE 仍 blocking；35190/107493 不在 no-quic/no-cms/no-siv 移除范围；reduced build 没有运行时/符号/配置证据，不能当 waiver |
| 降到 4.0.3 或 3.5.9 | 两者同样受 8 个 CVE 影响，fixed 4.0.4/3.5.10 也未发布；降级不会降低 CVE 暴露 |
| 使用 3.0.24/1.1.1zk/1.0.2zt | 3.0/1.1.1/1.0.2 不在官方支持下载表；3.0.24 为 premium support only；且 3.0 文档没有 ML-DSA（`docs.openssl.org/3.0/.../EVP_SIGNATURE-ML-DSA/` 为 404），不满足 pq768 |
| 使用 3.6.x | 官方公告明确 3.6 已 out of support，未分析 |
| 对 4.1.0 本地打补丁后称为 fixed | 不是官方发布版本；需要独立补丁审查、可复现构建与完整回归；不能作为“最小标准路径”，也不能据此改 gate |

### 6.2 推荐的最小路径（不改变 policy）

1. **现在到 fixed release 发布前：保持 production 冻结。** Native OpenSSL gate 保持 RED；
   `openssl-review.json` 的 `fixed_release_availability.available=false` 与 8 个 CVE 不得删除、
   不得标 waiver；4.1.0 reduced build 仅作为 CI/非生产实验候选。
2. **优先等待 4.1.1（当前 4.1 分支的直接修复版）。** 发布后必须：
   - 用官方 GitHub release + `openssl-4.1.1.tar.gz.sha256` 双重核对 tag/asset digest，不能从 tag 推断；
   - 更新 `openssl-review.json` 的 version、release SHA-256、affected ranges 与 review 日期；
   - 在 x86_64 glibc、x86_64 musl、aarch64 musl、OpenWrt 两架构等既有五个配置上重新构建；
   - 重新跑 `verify-openssl-build.sh`、真实 mTLS、ML-DSA/hybrid capability 与负例；
   - 只有精确 SHA 的 Actions 全部通过后，才能把 native gate 从 RED 改为其他状态。
3. **若 4.1.1 延期：优先评估 3.5.10 LTS。** 3.5 LTS 的 EOL 为 2030-04-08，支持期最长；
   但它是跨分支迁移，必须先证明 ML-DSA-65、X25519MLKEM768、`no-quic/no-cms/no-siv` 等价配置
   和 rust-openssl 0.10.82 的 API/特征兼容，再走与 4.1.1 相同的构建与互操作证据。
   4.0.4 也是 fixed release，但 EOL 仅 2027-05-14，只适合作为更短期的过渡，不作为首选。
4. **若 4.1.1、3.5.10、4.0.4 都未发布：没有可批准的 native OpenSSL 后端。** 此时应保持
   release 冻结；如果产品必须继续，只能另立 ADR 评估替代 TLS 后端/架构，并做独立审查，
   不能把 4.1.0 reduced build 或本地补丁写成“已修复”。
5. **Rust 侧无需安全迁移。** 官方 stable 1.100.0 与仓库 MSRV 1.100 一致；发布构建建议固定
   `1.100.0` + manifest SHA-256，避免 `stable` 在发布窗口移动。若未来 stable 升级，按普通
   toolchain 变更走独立 CI，不把它与 CVE 修复混为一谈。
6. **ML-DSA TLS 侧固定 draft-06 引用。** 在 RFC 发布前，文档与实现只写
   `draft-ietf-tls-mldsa-06`（Informational，RFC Editor 队列），不写 RFC 编号；发布前重新抓取
   RFC Editor/Datatracker 状态。RFC 9881 只作为证书/CRL 编码依据。

## 7. 证据明细（2026-11-18 抓取）

所有 SHA-256 为响应体原始字节的 SHA-256；HTTP 状态与字节数均为同一次只读 GET 的结果。

| 资源 | URL | HTTP | Bytes | SHA-256 | 关键事实/时间 |
|---|---|---|---:|---|---|
| Rust stable manifest | <https://static.rust-lang.org/dist/channel-rust-stable.toml> | 200 | 893,976 | `3051e859570f64a8c5acb9d09e87425db52c7d97287c67e8f6d57d7d34ef9258` | date 2026-11-12；rustc 1.100.0；Last-Modified 2026-11-12 18:18:49 GMT |
| Rust manifest `.sha256` | <https://static.rust-lang.org/dist/channel-rust-stable.toml.sha256> | 200 | 91 | `81d394d7eee8d7e3d22efaee66abaaf6dceac125a4ba7369ac8fff5fa73b058e` | 内容与 manifest hash 一致 |
| OpenSSL downloads | <https://openssl-library.org/source/> | 200 | 43,229 | `23b2134bfa558c643da77fed5ce8c511986e7492b2fecfbbab5c40908d3a007c` | 4.1.0/4.0.3/3.5.9；Last-Modified 2026-11-17 08:48:23 GMT |
| OpenSSL advisory 20261110 | <https://openssl-library.org/news/secadv/20261110.txt> | 200 | 11,780 | `31f4c88950cd9cd310794a218361b787d293a940d2568f9f82334915ac54a402` | 5 CVE；fixed 4.1.1/4.0.4/3.5.10；计划 2026-12-01 |
| OpenSSL advisory 20261117 | <https://openssl-library.org/news/secadv/20261117.txt> | 200 | 8,844 | `6f4219cd823c3472863cc592182ef571d7485ac2f8735845244dbc13e3e09f27` | 3 CVE；fixed 同上；计划 2026-12-01 |
| OpenSSL latest release | <https://api.github.com/repos/openssl/openssl/releases/latest> | 200 | 11,618 | `4694503c52b88c4e93c7eb2064e7e5718bf213005e345e8fb1aac54cc84e04c0` | tag openssl-4.1.0；published 2026-10-23 |
| OpenSSL fixed tags | `.../releases/tags/openssl-4.1.1`、`.../openssl-4.0.4`、`.../openssl-3.5.10` | 404 | 133 | `010563d2cfb8f1e87f700936ce59ee3a33364da46e3db41b0049227918ece74d` | 三个 fixed tag 都不存在 |
| OpenSSL 4.1.0 tarball `.sha256` | <https://github.com/openssl/openssl/releases/download/openssl-4.1.0/openssl-4.1.0.tar.gz.sha256> | 200 | 87 | `8305ea87f3cf009165928a27745094d2fbab68ba53e2b2dc00faae541e05fe66` | `50c17b… *openssl-4.1.0.tar.gz` |
| OpenSSL 4.1.0 CHANGES | <https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/CHANGES.md> | 200 | 928,861 | `bd15a960aed3737d9a76e945089f46869f934c96155f130316773fe4e85462b6` | TLS signature defaults 包含三种 ML-DSA |
| RFC 9846 | <https://www.rfc-editor.org/rfc/rfc9846.txt> | 200 | 339,413 | `b1bee06a814f92ca4677c85b97519be53869b2bf8edc79ade955fb51c0402b17` | July 2026；Standards Track；Obsoletes 含 RFC 8446 |
| RFC 10024 | <https://www.rfc-editor.org/rfc/rfc10024.txt> | 200 | 21,016 | `5efcfacef53549ec4ff57450dfec28085b34cf3f34d829c541c0ddbe19230dfe` | August 2026；三个 hybrid 组 |
| RFC 9881 | <https://www.rfc-editor.org/rfc/rfc9881.txt> | 200 | 229,857 | `20ae3b519bc69e32989fa6e625ab8746453eddf457e20ddbfd79d841a44237a2` | October 2025；ML-DSA X.509/CRL |
| RFC 5280 | <https://www.rfc-editor.org/rfc/rfc5280.txt> | 200 | 352,580 | `a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d` | May 2008；Standards Track；updated-by 9 个 RFC |
| RFC index | <https://www.rfc-editor.org/rfc-index.xml> | 200 | 13,756,401 | `3ed6d6f692806468b8b8bd9501421d03705273ff39961a3673724271eba60eb3` | 无 ML-DSA TLS RFC |
| ML-DSA draft page | <https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/> | 200 | 60,237 | `6565e0dff8224cec58eccca7d6b6421fe4a07162df4cecf31b366557df47679c` | draft-06；RFC Ed Queue；Awaiting First editor |
| ML-DSA draft API | <https://datatracker.ietf.org/api/v1/doc/document/draft-ietf-tls-mldsa/> | 200 | 1,277 | `81050c252629ef6236e40c71f6a92d6109e6ff96a72051f468ca89d60264e9c0` | `rfc=null`；rev 06；expires 2027-03-15 |

原始 manifest/RFC/HTTP 响应由 bundled Python `urllib` GET 取得；HTML/文本另用 `web_fetch` 交叉读取。
未使用 token，未打印任何凭据。

## 8. 明确不声称的事项

- 本文没有修改 `Cargo.toml`、`Cargo.lock`、workflow、`openssl-review.json` 或任何 source；
  也没有把 native gate 从 RED 改绿。
- 本文没有运行本地 build/test/format；所有版本/状态结论仅来自上述官方只读获取。
- 本文没有把 4.1.0 reduced build、本地补丁、tag 名称或“未调用某 API”当作 CVE waiver。
- 本文没有声称 fixed release 已存在；4.1.1/4.0.4/3.5.10 在 2026-11-18 抓取时均未发布。
- 本文没有声称 ML-DSA TLS 已标准化；当前只有 draft-ietf-tls-mldsa-06（Informational，RFC Editor 队列）。
- 本文没有重新审计 §4.2 的全部实现细节（如 rustls 0.23.35 源码、具体 TLS 代码路径）；这些仍需
  独立 review 与精确 SHA 的 Actions 证据。
- 动态页面、manifest 与 RFC Editor 队列会变化；发布/合并前应重新抓取并记录新的 hash 与时间。
