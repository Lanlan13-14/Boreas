# Boreas

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

## Boreas 是什麼？

Boreas 可以把分散在不同網路的主機連成私人 IP 網路。最簡單的用法是讓一台 Linux 主機當 Core、另一台當 Edge：由 Edge 主動連上 Core，之後兩端都可以用隧道 IP 存取對方。例如，你可以從家中透過隧道連線到伺服器上的 SSH 或管理頁面，不必把這些服務的連接埠直接開放到網際網路。Edge 仍需能連上 Core 的隧道連接埠。

## 可以做什麼？

| 用途 | 怎麼用 |
| --- | --- |
| 雙機互通 | 一台 Core、一台 Edge。先用雙向 `ping` 確認隧道，再用隧道 IP 存取 SSH 或私人服務。 |
| 並行傳輸 | Linux 開發版可明確啟用 2–4 條獨立加密電路。不同連線分配到不同電路，不會把同一條 TCP 串流拆開傳送。 |
| 多 Core 互連 | 用獨立的 `boreas node mesh-run` 根據簽章拓撲選路並驗證備援路徑，不是一般雙機模式的設定開關。 |
| 私有網域名稱 | 可為組網內部服務另外設定私有 DNS。只用 IP 存取時，不必啟用。 |

## TCP 直連和 WebSocket 有什麼關係？

**目前雙機隧道使用 WSS，也就是 TLS 上的 WebSocket，底層是 TCP。** Edge 可以直接撥到 Core 的 `IP:連接埠`，不經反向代理；這仍會進行 TLS 握手及 WebSocket 升級，並不是略過 WebSocket 的裸 TCP 模式。現行教學沒有獨立的裸 TCP 或明文 `ws://` 入口。

- `--connect` 指定 Edge 能連上的 Core `IP:連接埠`，不是隧道 IP。
- `--tls-name` 填寫憑證上的名稱；`--ws-host` 和 `--ws-path` 分別指定 WebSocket 請求的 Host 與路徑。
- Boreas 以 Rust 實作，透過 Linux TUN 收送 IP 封包，以 TLS 1.3、WebSocket 和預先配置的簽章身分建立隧道；`pq768` / `e2e-required` 模式另由流量兩端建立端對端加密電路。

## 從這裡開始

- **第一次部署：** [雙機教學](docs/deployment/README.zh-TW.md)從簽發與設定開始。已有節點材料和執行檔，可直接看[一鍵安裝](docs/deployment/ONE_CLICK.zh-TW.md)。
- **手上是公開預覽版：** 請依照 [`v0.1.0-pre.3` 雙機實作](docs/deployment/README.zh-TW.md#public-pre3)的指令，不要與開發版的安裝步驟混用。
- **想連通多台 Core：** [四 Core 互連](docs/deployment/linux-core-mesh-topology.zh-TW.md)有拓撲、啟動順序和疑難排解。

## 哪些流量預設會走隧道？

雙機部署只新增前往對端隧道 IP 的 `/32` 路由。一般上網、預設路由，以及 Core 和 Edge 原本的系統 DNS 都不變。私有 DNS 要另外啟用。目前組網範圍是 `10.20.0.0/16`，節點位址須與簽發的身分一致。

連不上時，先分清 Core 的底層連線位址、憑證上的 TLS 名稱，以及隧道 IP，再依照[疑難排解](docs/deployment/README.zh-TW.md#troubleshooting)檢查。部署後可用 `boreas ctl status --socket <PATH>` 查看連線與收發計數。

## 常用操作

| 指令 | 用途 |
| --- | --- |
| `boreas doctor` | 查看目前版本編入哪些功能 |
| `boreas config-check <FILE>` | 檢查設定檔 |
| `boreas ctl status --socket <PATH>` | 讀取即時狀態和流量計數 |
| `boreas console` | 開啟互動式控制台 |

[設定參考](docs/config/README.md) · [離線簽章部署](docs/deployment/VERIFIED-SERVICE.md) · [CI 與測試說明](docs/engineering/ci-workflows.md)

Boreas 目前是開發預覽，以上教學以 Linux 為主。授權條款：[GPL-3.0-only](LICENSE)。
