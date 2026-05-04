# Goloom

Goloom is a VPN tunneling protocol that hides traffic inside a Telemost (Yandex's WebRTC video calling) media stream. To a network observer the device looks like it's in a video call with `telemost.yandex.ru`; in fact it is exchanging WireGuard packets.

This repository hosts the **server** (the relay running on a VPS) and the **mobile SDK** that client applications embed via `gomobile`.

| Component | Path | What it is |
|---|---|---|
| Server | [`cmd/goloom-wg-server`](cmd/goloom-wg-server) | Long-running daemon on a VPS. Joins Telemost meetings, terminates Goloom-tunneled WireGuard packets, hands them to the kernel WG stack, NATs to the internet. |
| Desktop client | [`cmd/goloom-wg-client`](cmd/goloom-wg-client) | Reference CLI client for Linux/Windows/macOS. Uses kernel/userspace WireGuard. |
| Mobile SDK | [`mobile`](mobile) | Gomobile bridge — produces `goloom.aar` (Android) and `Goloom.xcframework` (iOS). Embeds a pure-Go userspace WireGuard so the mobile app does not need `wireguard-android` / `WireGuardKit`. |
| Reference Android app | [Pinnss/goloom-android](https://github.com/Pinnss/goloom-android) | Full Compose UI — profile import/export, per-app split tunnel, logs, auto-reconnect on network change. |

## Quick start

### Running a server (VPS)

See [`docs/INSTALL.md`](docs/INSTALL.md) for the full step-by-step. Short version:

```bash
git clone https://github.com/Pinnss/goloom-server.git
cd goloom-server
sudo bash deploy/install.sh
```

Then open `https://<vps-ip>:9443` to provision an inbound — the panel returns a `goloom://…` connection string (and a QR code) that you give to your client.

### Building the mobile SDK

```bash
cd mobile
./scripts/build-android.sh
# → ../build/android/goloom.aar
```

See [`mobile/README.md`](mobile/README.md) for iOS and integration details.

## Documentation

- [`docs/INSTALL.md`](docs/INSTALL.md) — Server installation guide
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — How the protocol works end-to-end
- [`mobile/README.md`](mobile/README.md) — Mobile SDK API and build instructions

## License

Apache-2.0.
