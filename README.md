# Goloom

[Русская версия](README.ru.md)

Goloom is a VPN that hides WireGuard packets inside a video-conferencing media stream. To a network observer the device looks like it is in a video call with a public service (Yandex Telemost, Wildberries Stream, or VK Calls); in reality it is exchanging WireGuard datagrams with a Goloom server.

This repository contains:

| Component | Path | What it is |
|---|---|---|
| **Server** | [`cmd/goloom-wg-server`](cmd/goloom-wg-server) | Long-running daemon for a Linux VPS. Joins a video call, terminates Goloom-tunneled WireGuard packets, hands them to the kernel WG stack, NATs to the internet. |
| **Windows GUI client** | [`cmd/goloom-wg-gui`](cmd/goloom-wg-gui) | Wails-based desktop app with profile management, embedded WireGuard userspace, and one-click connect. |
| **Windows CLI client** | [`cmd/goloom-wg-client`](cmd/goloom-wg-client) | Headless reference client for Linux/Windows/macOS. Uses kernel/userspace WireGuard. |
| **Mobile SDK** | [`mobile`](mobile) | Gomobile bridge — produces `goloom.aar` (Android) and `Goloom.xcframework` (iOS). Embeds a userspace WireGuard so apps don't need `wireguard-android` / `WireGuardKit`. |
| **Reference Android app** | [Pinnss/goloom-android](https://github.com/Pinnss/goloom-android) | Full Compose UI — profile import/export, per-app split tunnel, logs, auto-reconnect. |

## Supported transports

| Transport | Status | Notes |
|---|---|---|
| **Yandex Telemost** | Stable | VP8 video frames carry WireGuard. |
| **Wildberries Stream** (LiveKit) | Stable | DataChannel-native; needs operator-captured cookies (see [USAGE.md](docs/USAGE.md#wb-stream-auth)). |
| **VK Calls** | Stable | VP8 video over anonymous-peer join; client solves captcha once via WebView and replays the session profile thereafter. |
| **VK TURN SRTP** | Stable — **recommended** | Wraps WireGuard as WebRTC media (RTP/SRTP) and relays it through VK's *own* TURN servers. The Goloom server is just the call's "other peer" — it never runs a TURN server itself. Bypasses VK's media-shape policy: ~30–40 Mbps vs ~2 Mbps on the legacy path. |
| **VK TURN (legacy DTLS)** | Deprecated | DTLS + WireGuard over VK TURN. VK shape-throttles this to ~7–9 KB/s since 2026-05; kept only for older clients. |

> The first three transports join a conference as a hidden participant. The two **VK TURN** transports instead relay WireGuard through VK's own TURN infrastructure — you do **not** run your own TURN server; VK's is the relay, and that is exactly what makes the traffic hard to block. See [USAGE.md → VK TURN SRTP](docs/USAGE.md#vk-turn-srtp).

## Quick start

### Run a server

See [`docs/INSTALL.md`](docs/INSTALL.md) ([RU](docs/INSTALL.ru.md)) for the full step-by-step. Short version on a Debian/Ubuntu VPS:

```bash
# Download the latest server binary from Releases:
wget -O goloom-wg-server https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-amd64
chmod +x goloom-wg-server

# Place the example config + install script:
wget https://github.com/Pinnss/goloom-server/raw/main/goloom-wg-server.yaml.example -O goloom-wg-server.yaml
mkdir deploy && cd deploy
wget https://github.com/Pinnss/goloom-server/raw/main/deploy/install.sh
wget https://github.com/Pinnss/goloom-server/raw/main/deploy/goloom-wg-server.service
cd ..

# Run the installer (requires root + WireGuard + iptables already installed):
sudo bash deploy/install.sh
sudo systemctl start goloom-wg-server
```

The first start prints a one-time admin password — capture it from `journalctl -u goloom-wg-server`. Then open `https://<vps-ip>:9443`, log in, change the password, and create your first inbound. The panel returns a `goloom://...` connection string (and a QR code) you give to your client.

### Connect a client

- **Windows GUI**: download `goloom-wg-gui-windows-amd64.zip` from [Releases](https://github.com/Pinnss/goloom-server/releases), unzip, run `goloom-wg-gui.exe` as Administrator, paste the connstr, click Connect.
- **Android**: download the latest APK from [goloom-android Releases](https://github.com/Pinnss/goloom-android/releases), install, scan the QR or paste the connstr.

For details on creating inbounds, capturing WB Stream cookies, and connecting different clients, see [`docs/USAGE.md`](docs/USAGE.md) ([RU](docs/USAGE.ru.md)).

## Build from source

```bash
git clone https://github.com/Pinnss/goloom-server.git
cd goloom-server
go build ./cmd/goloom-wg-server     # Linux server
go build ./cmd/goloom-wg-client     # CLI client
```

For the Wails GUI, see [`cmd/goloom-wg-gui/README.md`](cmd/goloom-wg-gui/README.md). For the mobile SDK, see [`mobile/README.md`](mobile/README.md).

## License

Apache-2.0.
