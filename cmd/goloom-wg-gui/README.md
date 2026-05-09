# Goloom WG GUI (Windows)

Wails-based desktop client. Connects via Telemost / WB Stream / VK Calls, manages profiles, and runs the WireGuard userspace tunnel in-process — no separate WireGuard install required.

## Download

Pre-built `goloom-wg-gui-windows-amd64.zip` is on the [Releases page](https://github.com/Pinnss/goloom-server/releases). Unzip, right-click `goloom-wg-gui.exe` → **Run as administrator** (needed for split-tunnel routes).

## Build from source

Prerequisites:
- Go 1.22+
- [Wails CLI v2](https://wails.io/docs/gettingstarted/installation): `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- Windows with the WebView2 runtime (already installed on Win10 21H2+ / Win11)

```bash
cd cmd/goloom-wg-gui
wails build -platform windows/amd64
```

Output: `build/bin/goloom-wg-gui.exe` (≈ 39 MB).

The icon and version metadata are baked in via the `resource_windows_*.syso` files committed alongside this README.

## Usage

See [`docs/USAGE.md`](../../docs/USAGE.md#windows-gui) ([RU](../../docs/USAGE.ru.md#windows-gui)) for the connection workflow.
