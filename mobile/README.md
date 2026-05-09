# Goloom Mobile SDK

Embed the Goloom tunnel into Android and iOS VPN apps. The SDK supports all three transports — Telemost, WB Stream, and VK Calls.

## Pre-built artifacts

To skip the gomobile build, the latest stable Android `.aar` is committed at:

```
mobile/dist/goloom.aar
```

Drop it into `app/libs/` of your Android project and you're good to go.

iOS `.xcframework` is not pre-built (requires a macOS host) — build it locally with the steps below.

## Architecture

```
                ┌──────────────────────────────────────────────────────┐
                │              Mobile app (Kotlin / Swift)              │
                │                                                       │
                │   ┌─────────────────┐    ┌──────────────────┐         │
                │   │  WireGuard      │    │  Goloom relay    │         │
                │   │  userspace ─────────→  (gomobile .aar  │         │
                │   │   (embedded)    │    │   /xcframework)  │         │
                │   └────────┬────────┘    └────────┬─────────┘         │
                │            │ UDP to 127.0.0.1     │                   │
                │            └──────────────────────┘                   │
                │                       │                                │
                │                       │ WebRTC (Telemost / VK / LK)    │
                └───────────────────────┼───────────────────────────────┘
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
2. Calls `Mobile.NewClient().Connect(connStr, "127.0.0.1:51820")` — joins the carrier service, completes the goloom handshake, starts a UDP listener.
3. Receives back a `ConnectResult` carrying the WireGuard config, the local listen address, and the list of carrier IPs that **must bypass the VPN**.
4. Builds the platform `VpnService.Builder` / `NEPacketTunnelNetworkSettings`, calls `establish()`, takes the resulting TUN file descriptor, and feeds it to the SDK via `client.AdoptTun(fd, wgUserspaceConfig)`.

The userspace WireGuard runs inside the same `.aar` / `.xcframework`, so there is no dependency on `wireguard-android` or `WireGuardKit`.

## Build

### Android

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
./scripts/build-android.sh
```

Output: `build/android/goloom.aar` (≈ 16 MB, arm64+arm). Drop it into `app/libs/` of your Android Studio project, or commit it back into `mobile/dist/goloom.aar` to ship a new SDK version.

### iOS (macOS host required)

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=ios -o build/ios/Goloom.xcframework ./mobile
```

Output: `build/ios/Goloom.xcframework`. Drag into your Xcode project (Frameworks group, "Embed & Sign").

## Reference clients

The reference Android client lives at [Pinnss/goloom-android](https://github.com/Pinnss/goloom-android) — full Compose UI, profile import/export, per-app split tunnel, log viewer, captcha WebView, auto-reconnect.

iOS reference client is TBD.

## Go API

```go
// Package mobile (gomobile-friendly subset of types):
type Client struct{}

func NewClient() *Client
func (c *Client) SetSocketProtector(p SocketProtector)            // Android only
func (c *Client) SetLogSink(s LogSink)
func (c *Client) SetPhaseListener(l PhaseListener)                // connection-phase callbacks
func (c *Client) SetBrowserLauncher(b BrowserLauncher)            // VK captcha WebView hook
func (c *Client) SetVKTargetMeeting(url string)                   // VK lobby flow target
func (c *Client) SetVKProfileStorePath(path string)               // VK captcha replay pool

func (c *Client) Connect(connStr, listenAddr string) (string, error)  // returns ConnectResult JSON
func (c *Client) AdoptTun(fd int64, wgUserspaceConfig string) error
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
  "carrier_ips": ["87.250.251.10", "..."],
  "wg_client_config": "[Interface]\nPrivateKey = …\nAddress = 10.66.1.2/24\n…",
  "wg_client_addr":   "10.66.1.2/24"
}
```

The admin panel embeds the client's WG private key, the server's WG public key, and the per-inbound subnet **inside the `goloom://` connection string**, so the mobile app gets everything it needs from a single QR scan — no separate `.conf` import.

## Limitations

- **iOS background**: Apple kills the Network Extension when memory-pressured. The relay needs to be resilient to NE restarts.
- **Power**: video-stream-as-tunnel keeps the radio busy → battery cost. Implement an idle sleep when WG hasn't sent in N seconds.
- **DPI**: traffic blends in as video to the carrier domain — but a deep traffic analyser could spot the absence of real-camera entropy.
