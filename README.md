# Boreas

**先让两台 Linux 主机通过加密隧道互相访问。** Boreas 是用 Rust 编写的实验性三层隧道。它通过 TUN 接收 IP 包，用 TLS 1.3 和 WebSocket 在 TCP 上承载流量；在本文所用的 `pq768` / `e2e-required` 路径中，节点用预配的签名身份相互认证，业务端点再建立端到端加密电路。

如果你第一次上手，不妨从 `Core ↔ Edge` 开始：不接管默认路由，只让两个隧道地址互通。等两端的 `ping` 和收发计数都符合预期，再考虑服务托管或多 Core 实验。

[部署教程](docs/deployment/README.md) · [一键安装](docs/deployment/ONE_CLICK.md) · [配置参考](docs/config/README.md) · [多 Core 拓扑](docs/deployment/linux-core-mesh-topology.md)

## 选择一条路线

| 你想做什么 | 从哪里开始 |
| --- | --- |
| 手上没有开发构建，想用公开包试通两台 x86-64 Linux 主机 | [公开预发布 `v0.1.0-pre.3` 双机演练](docs/deployment/README.md#public-pre3)；使用实际发布的 Linux pq768 二进制。 |
| 已有可信的当前开发制品，想从安装走到互通 | [两节点完整流程](docs/deployment/README.md#workflow)，再按[一键安装](docs/deployment/ONE_CLICK.md)先预演、后安装。脚本不编译、不签发节点、不自动组网。 |
| 目标是 Linux/systemd 下的离线双签部署及受控回退 | [离线签名服务](docs/deployment/VERIFIED-SERVICE.md)。需要独立预配的发布根、管理工具和双签候选；不能拿公开预发布资产直接套用。 |
| 想验证多 Core 路径或目录同步 | [四 Core 拓扑教程](docs/deployment/linux-core-mesh-topology.md)。`node mesh-run` 是独立入口，目录协调器模式需要包含 `4363e0e` 的发现实现；它不是普通 Core/Edge daemon 的配置开关。 |

公开预发布包与仓库开发构建有不同的命令和运行状态要求。先记下二进制的版本或源码提交、架构和来源；同源 SHA-256 可以检查文件完整性，不能代替独立认证。

## 先分清三个地址

- **底层地址**：如 `203.0.113.10:8443`，Edge 通过它连接 Core 的 TCP 端口；该连接走原有网络，不走 TUN。
- **TLS 名称**：如 `wss.example.net`，需与 Core 外层证书的 DNS SAN 一致；即使用 IP 连接，也不能跳过名称校验。节点内部身份则由预配的签名对象和证书公钥确定，不由域名或 IP 决定。
- **隧道地址（VIP）**：如 `10.20.1.1` 和 `10.20.1.2`，签发时绑定节点槽位。验证时 `ping` 对端 VIP，而不是公网地址。

## 日常操作

| 命令 | 用途 |
| --- | --- |
| `boreas doctor` | 查看当前二进制的编译能力；不会建立隧道或验证生产就绪。 |
| `boreas config-check <FILE>` | 检查配置语法、字段和文件权限；不会验证对端在线。 |
| `boreas config-migrate <FILE>` | 将支持的旧版配置规范化到 stdout，不覆盖源文件。 |
| `boreas ctl status --socket <PATH>` | 使用与 daemon 相同的 UID 查询实际控制 socket。 |
| `boreas console` / `boreas-easy` | 行式控制台；`--json` 获取一次状态，`--lang zh-CN` 切换简体中文。`boreas-easy` 由安装器提供，也可直接用 `boreas console`。 |

控制台默认查找 `/run/boreas/control.sock`，而 daemon 会把 socket 放在配置的 `state_dir` 下；路径不同时请显式传入 `--socket`。在 Linux 开发构建中，`config-save-candidate` 需精确传入 `--confirm SAVE`。它只保存端点候选片段并返回 `applied:false`，不会应用或建立连接；控制台只能预览，不能保存。详见[配置参考](docs/config/README.md)。

## 项目状态

Boreas 仍处于开发预发布阶段，未获生产批准。Linux 隧道、目录或服务的某个场景通过验证，不等于已覆盖真实设备、开放网络、所有拓扑或其他系统。Windows/macOS 基础归档及 OpenWrt 模板也不是 daemon 产品支持声明。请在可回收的测试环境中使用，不承载关键或敏感业务。

- 查实现和精确提交的证据：[实现状态](docs/engineering/implementation-status.md) · [CI 导航](docs/engineering/ci-workflows.md) · [生产门禁](docs/engineering/gates.json)
- 维护网络信任：[策略与状态目录](docs/deployment/POLICY-STATE.md) · [升级信任边界](docs/upgrade/README.md)
- 遇到错误：[按层排查](docs/deployment/README.md#troubleshooting)

许可证：[GPL-3.0-only](LICENSE)。
