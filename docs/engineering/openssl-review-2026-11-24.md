# OpenSSL 新安全公告审查（2026-11-24，pre7 发布阻塞修复）

## 实际失败与边界

主线 `3e352ac` 的依赖作业 `45394899880` 检出此前尚未审查的
`20261124` 公告而失败。RustSec 作业通过不覆盖 native OpenSSL。
保留失败记录；不能仅把审查日期前移，也不能依赖 no-quic/no-cms
为四项新问题整体豁免。性能数据仍取原始诊断，不因安全快照更新
宣称性能获益或稳定千兆。

官方公告：<https://openssl-library.org/news/secadv/20261124.txt>

实查时正文 9,067 字节，SHA-256：
`370945815429db4a94eae07603cbef690b4b1d2de0312060f35be7d6bd7a32e3`。
公告列出四项 Low 问题，修复发布计划为 2026-12-01。实查官方
`openssl-4.1.1` release API 仍返回 404。本文不把 dev 快照写成正式版。

## 逐项修复与上游回归

以下修复提交均来自官方漏洞页面相应分支的链接，而非猜测补丁。

| 编号 | 触发边界 | 4.1 分支修复 | 回归与核验 |
|---|---|---|---|
| CVE-2026-84786 | 非 SMTP DANE 客户端混用 PKIX 0/1 与 DANE-TA 2 的 TLSA 记录，特殊信任锚叶证书触发 NULL 解引用 | `a7e57082ccb27330a42f5f116a4e125b13bdcfef` | 修正 num_untrusted=0 的索引，选中证书判空；同提交新增 `test/danetest.c::run_trusted_ee_test` |
| CVE-2026-107494 | QUIC 重传 NEW_CONNECTION_ID 可不断排入 RETIRE_CONNECTION_ID | `dec00b87a89e8f81cef0e50cbbecdfad4d377849` | 忽略已处理的重复序号；回归 `55286691decd4e8db6fcc218e1f6e43da4d37a2b` |
| CVE-2026-121482 | 启用 CRL 检查时，CMS/PKCS7 消息可让相对 CRLDP 名称反复重建，CPU 消耗过大 | `14a9f9ad6e8a17437fb75545f33e4fc56e9d41f6` | 预先缓存完整名称并限制相对名称数量，原失败校验不变；回归 `c35fc554d4a38c72b9b1a09325d42e81967fa0fc` |
| CVE-2026-84785 | 非默认接收 QUIC stream 模式可被小片段乱序间隙占用大量重组节点 | `fead004f52d6e5efffa62019ea451218c0aa79e9` | 限制 1024 个区间；同提交新增 `test_rstream_range_limit` |

生产继续禁用 QUIC/CMS/SIV；但是 DANE、PKCS7/X509 不能据此当作
已删除的路径。选取真实上游修复，不以源码未调用某 API 代替修复。

官方漏洞页（含上述修复提交链接）：
<https://openssl-library.org/news/vulnerabilities/>

## 不可变来源与完整祖先证明

- 新快照：`a7e57082ccb27330a42f5f116a4e125b13bdcfef`。
- 官方 codeload tar.gz：56,030,769 字节。
- 实测归档 SHA-256：`21a34f1e90d7accefefb9ad23b0e15a83a7d5504ffb53142f9193ecb44364340`。
- `VERSION.dat`：4.1.1-dev；不是正式 4.1.1。
- 旧 pin `941390af2ac35f41d2f95bb0bac823dbf0700845` 到新 pin 的
  官方 compare 返回 ahead / 55 commits，包含上述四修复与两个独立回归。
  基线 4.1.0 到新 pin 共 199 commits，未超过单页 compare 提交上限。
- 原八项修复仍保留在 `fixed_commit.fixes`，新增四项和相关回归；
  原 affected_ranges 继续阻塞未修复发布版，并追加四项新范围。
  新公告仍然触发独立人工审查，门禁代码不变。

## 必须实际完成的 Actions 证据

本提交只记录上游审查和配置，不冒称新快照已通过运行时测试。
发布前需观察以下真实结果，缺失或失败则暂不发 pre7：

1. 官方数据依赖审查、RustSec、锁定版本、固定 Action 审计。
2. 精确 reduced-build 验证：生成及安装头、configdata、disabled
   列表、算法正反例、静态链接与真实 pq768 mTLS。
3. 主线真实 WSS/hop/E2E、故障关闭、功能 netns 与原性能门禁。
4. 原生 x86_64/aarch64 OpenWrt 静态构建和 rootfs 冒烟。
5. 单独 full-feature 的上游 TEST 构建，运行 DANE、X509/CRL、QUIC
   stream/radix、PEM/CMS 配方；日志显式保留 skip，不能算作已执行。
   该测试构建不用于发布，不改变生产 no-tests/no-quic 选项。
6. 审查工具正反例：旧 pin 拒绝、错误摘要拒绝、漏补丁拒绝、未来公告拒绝。

不更新 Cargo.lock，不增数据线程，不削安全层，不移动已发布 tag。
