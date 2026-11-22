# Boreas

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

## What is Boreas?

Boreas connects hosts on different networks into a private IP network. Start with two Linux hosts: run a Core on one, let an Edge dial it from the other, then use their tunnel IPs to reach either host. For example, you can reach SSH or a private dashboard on your server without opening those application ports to the internet. The Core's tunnel port still needs to be reachable from the Edge.

## What can I use it for?

| Use case | How to get started |
| --- | --- |
| Connect two hosts | Set up one Core and one Edge. Check `ping` in both directions, then use the tunnel IP for SSH or your own services. |
| Run independent connections in parallel | Linux development builds can opt into 2–4 encrypted circuits. Separate flows can use different circuits; a single TCP stream is not striped across them. |
| Connect several Cores | The separate `boreas node mesh-run` command supports signed-topology routing and alternate-path testing. It is not a toggle in the two-host daemon setup. |
| Resolve private names | Configure private DNS for services on the overlay, or skip DNS entirely if tunnel IPs are enough. |

## How do direct TCP and WebSocket fit together?

**The current two-host tunnel uses WSS: WebSocket over TLS, carried by TCP.** The Edge can dial the Core's `IP:port` directly, without a reverse proxy. It still performs a TLS handshake and WebSocket upgrade. Direct dialing is not a separate raw TCP mode, and the current guide does not offer a plaintext `ws://` listener.

- `--connect` takes the Core's reachable `IP:port`, not its tunnel IP.
- `--tls-name` is the certificate name. Use `--ws-host` and `--ws-path` for the WebSocket request's Host and path.
- Boreas is written in Rust. Linux TUN is the IP packet interface; TLS 1.3, WebSocket, and provisioned signed identities provide the tunnel transport and authentication. With `pq768` / `e2e-required`, the traffic endpoints also establish a separate end-to-end encrypted circuit.

## Get started

- **Setting up Boreas for the first time?** Follow the [two-host guide](docs/deployment/README.en.md) to issue identities and configure both nodes. If you already have the node files and binary, start with [one-click installation](docs/deployment/ONE_CLICK.en.md).
- **Using the public preview?** Follow the [`v0.1.0-pre.3` walkthrough](docs/deployment/README.en.md#public-pre3), not the installation steps for development builds.
- **Connecting several Cores?** The [four-Core guide](docs/deployment/linux-core-mesh-topology.en.md) covers topology, startup order, and troubleshooting.

## What traffic goes through the tunnel?

The two-host setup adds only a `/32` route to the peer's tunnel IP. It leaves regular internet traffic, the default route, and system DNS on both hosts alone. Private DNS is opt-in. The current overlay uses `10.20.0.0/16`, and each node's IP must match its issued identity.

If the tunnel doesn't connect, check the Core's network address, certificate name, and tunnel IP separately. See [troubleshooting](docs/deployment/README.en.md#troubleshooting). Run `boreas ctl status --socket <PATH>` after setup to check the connection and packet counters.

## Common commands

| Command | Purpose |
| --- | --- |
| `boreas doctor` | Check the features compiled into your build |
| `boreas config-check <FILE>` | Check a configuration file |
| `boreas ctl status --socket <PATH>` | Read live status and packet counters |
| `boreas console` | Open the interactive console |

[Configuration reference](docs/config/README.md) · [Offline signed deployment](docs/deployment/VERIFIED-SERVICE.md) · [CI and testing](docs/engineering/ci-workflows.md)

Boreas is a development preview. These guides focus on Linux. License: [GPL-3.0-only](LICENSE).
