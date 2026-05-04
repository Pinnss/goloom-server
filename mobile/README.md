# Goloom Mobile SDK

Embed the Goloom Telemost-tunnel into Android and iOS VPN apps.

## Architecture

```
                     ┌────────────────────────────────────────────────┐
                     │              Mobile app (Kotlin/Swift)          │
                     │                                                 │
                     │   ┌─────────────────┐    ┌──────────────────┐   │
                     │   │  WireGuard      │    │  Goloom relay    │   │
                     │   │  userspace ─────────→  (gomobile .aar  │   │
                     │   │   (embedded)    │    │   /xcframework)  │   │
                     │   └────────┬────────┘    └────────┬─────────┘   │
                     │            │ UDP to 127.0.0.1:port│             │
                     │            └──────────────────────┘             │
                     │                       │                          │
                     │                       │ Telemost WebRTC          │
                     │                       │ (TURN/SFU)               │
                     └───────────────────────┼─────────────────────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │  goloom-wg-     │
                                    │  server (VPS)   │
                                    │  + WireGuard    │
                                    └────────┬────────┘
                                             │
                                             ▼ Internet
```

The mobile app:
1. Asks the OS for VPN permission (`VpnService` on Android, `NETunnelProvider` on iOS).
2. Calls `goloomClient.connect("goloom://…", "127.0.0.1:51820")` — joins Telemost, completes the goloom handshake, starts a UDP listener.
3. Receives back a `ConnectResult` carrying the embedded WireGuard config, the local listen address, and the list of Telemost IPs that **must bypass the VPN**.
4. Builds the platform `VpnService.Builder` / `NEPacketTunnelNetworkSettings`, calls `establish()`, takes the resulting TUN file descriptor, and feeds it to the SDK via `goloomClient.adoptTun(fd, wgUserspaceConfig)`.

The userspace WireGuard runs inside the same `.aar` / `.xcframework`, so there is no dependency on `wireguard-android` or `WireGuardKit` for kernel hand-off.

## Build

### Android

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
./scripts/build-android.sh
```

Output: `build/android/goloom.aar` (≈ 16 MB, arm64+arm). Drop it into `app/libs/` of your Android Studio project.

The build script sets `GOFLAGS=-ldflags=-checklinkname=0` to work around a `wlynxg/anet` linkname conflict on Go 1.25; remove it once that dependency is fixed upstream.

### iOS (macOS host required)

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=ios -o build/ios/Goloom.xcframework ./mobile
```

Output: `build/ios/Goloom.xcframework`. Drag into your Xcode project (Frameworks group, "Embed & Sign").

## Reference clients

The reference Android client lives in a separate repository — see [Pinnss/goloom-android](https://github.com/Pinnss/goloom-android) for a full Compose UI, profile import/export, per-app split tunnel, log viewer, and auto-reconnect.

iOS reference client TBD.

## Go API

```go
// In package mobile (gomobile-friendly subset of types):
type Client struct{}
func NewClient() *Client
func (c *Client) SetSocketProtector(p SocketProtector)  // Android only
func (c *Client) SetLogSink(s LogSink)
func (c *Client) Connect(connStr, listenAddr string) (string, error)  // returns ConnectResult JSON
func (c *Client) AdoptTun(fd int64, wgUserspaceConfig string) error    // hands the TUN to embedded wg
func (c *Client) Disconnect()
func (c *Client) IsConnected() bool
func (c *Client) StatsJSON() string
```

`ConnectResult` JSON shape:
```json
{
  "display_name": "anonymous",
  "peer_id": "26375971-…",
  "listen_addr": "127.0.0.1:51820",
  "wg_endpoint": "127.0.0.1:51820",
  "telemost_ips": ["87.250.251.10", "37.9.82.147", "..."],
  "wg_client_config": "[Interface]\nPrivateKey = …\nAddress = 10.66.1.2/24\n…",
  "wg_client_addr":   "10.66.1.2/24"
}
```

The admin panel embeds the client's WG private key, the server's WG public key, and the per-inbound subnet **inside the goloom:// connection string**, so the mobile app gets everything it needs from a single QR scan — no separate `.conf` import.

## Provisioning flow

1. Server admin opens the panel (`https://vps:9443`), creates an inbound. Panel renders one QR code carrying the meeting URL **and** the WG profile.
2. Mobile user scans the QR (or pastes the `goloom://…` string).
3. App calls `Mobile.NewClient().Connect(connStr, "127.0.0.1:51820")`.
4. App calls `Builder.establish()` to get TUN fd, then `client.adoptTun(fd, …)`.

One string, three components installed (Telemost session, WG profile, route table).

## Limitations

- **iOS background**: Apple kills the Network Extension when memory-pressured. Our relay needs to be resilient to NE restarts.
- **Power**: VP8-stream-as-tunnel keeps the radio busy 24/7 → battery cost. Add an idle-mode that sleeps the keepalive ticker when WG hasn't sent in N seconds.
- **DPI**: traffic blends in as VP8 video to a Yandex domain — but a deep traffic analyser could spot the absence of real-camera entropy.
