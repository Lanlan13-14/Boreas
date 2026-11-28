# Boreas

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

## Boreas 是什么？

Boreas 把分散在不同网络里的主机连成一个私有 IP 网络。最简单的用法是让一台 Linux 主机做 Core，另一台做 Edge：Edge 主动连上 Core，之后两端都可用隧道 IP 访问对方。比如，你可以从家里通过隧道访问服务器上的 SSH 或管理页面，不必把这些业务端口直接暴露在公网。Core 的隧道接入端口仍需让 Edge 能连到。

## 能做什么？

| 用途 | 怎么用 |
| --- | --- |
| 双机互通 | 一台 Core、一台 Edge。先用双向 `ping` 确认隧道通了，再用隧道 IP 访问 SSH 或私有服务。 |
| 并行传输 | Linux 开发构建支持显式启用 2–4 条独立加密电路。不同连接分到不同电路；不是把一条 TCP 流拆成几份并发发送。 |
| 多 Core 互联 | 可用独立的 `boreas node mesh-run` 按签名拓扑选路和验证备用路径。它不是普通双机模式里勾一个开关。 |
| 私有域名 | 可为组网内的服务配置私有 DNS。只想按 IP 访问时可以完全不用它。 |

## TCP 直连和 WebSocket 是什么关系？

**实验分支的直连设计**：TCP 直接承载自定义、无 TLS 的加密通道，握手使用 X25519 + ML-KEM-768 和 ML-DSA-65，数据使用 AES-256-GCM。该协议借鉴 WireGuard 的设计思路，但不是 WireGuard 协议，也不与其兼容；实现和安全性尚待完整测试及独立审计。身份认证依赖预先验证的签名身份中的 ML-DSA 公钥。

**WSS 外层证书的已知限制：** 当前双机客户端通过 `outer-ca.pem` 是否存在来选择 WSS；没有这个文件时会选择直连，即使服务器使用公共 CA 证书也是如此。因此当前实现尚未满足“使用公共 CA 时客户端无需 CA 文件”的目标。服务端 WSS 使用 `outer.pem`/`outer.key`；证书验证与公开 CA 信任路径需要后续修复和测试。

- `--connect` 填 Core 可达的底层 `IP:端口`，不是隧道 IP。
- WSS 模式下 `--tls-name` 填证书上的名称；`--ws-host` 和 `--ws-path` 分别设定 WebSocket 请求的 Host 和路径。直连模式忽略这三项。
- 用 Rust 实现，Linux TUN 接收和送回 IP 包；在 `pq768` / `e2e-required` 路径上由业务两端另建端到端加密电路，使用同一套无 TLS 后量子握手。

## 从这里开始

- **第一次部署：** [双机教程](docs/deployment/README.md)从签发和配置开始。已有材料和二进制的话，直接看[一键安装](docs/deployment/ONE_CLICK.md)。
- **手上是公开预览版：** 用 [`v0.1.0-pre.3` 双机演练](docs/deployment/README.md#public-pre3)里的命令；不要与开发构建的安装步骤混用。
- **想连接多台 Core：** [四 Core 互联](docs/deployment/linux-core-mesh-topology.md)有拓扑、启动顺序和排错方法。

## 默认哪些流量走隧道？

双机部署只添加指向对端隧道 IP 的 `/32` 路由。普通上网、默认路由和 Core、Edge 的系统 DNS 不变。私有 DNS 需要另行启用。当前组网范围为 `10.20.0.0/16`，节点地址须与签发的身份一致。

连不上时，先区分 Core 的底层连接地址、证书上的 TLS 名称和隧道 IP，再按[排错指南](docs/deployment/README.md#troubleshooting)检查。部署后可用 `boreas ctl status --socket <PATH>` 看实际连接和收发计数。

## 常用操作

| 命令 | 用途 |
| --- | --- |
| `boreas doctor` | 查看当前构建包含哪些功能 |
| `boreas config-check <FILE>` | 检查配置文件 |
| `boreas ctl status --socket <PATH>` | 读取实时状态与流量计数 |
| `boreas console` | 打开交互控制台 |

[配置参考](docs/config/README.md) · [离线签名部署](docs/deployment/VERIFIED-SERVICE.md) · [CI 与测试说明](docs/engineering/ci-workflows.md)

Boreas 目前是开发预览，以上教程以 Linux 为主。许可证：[GPL-3.0-only](LICENSE)。
