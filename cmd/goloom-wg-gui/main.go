// goloom-wg-gui is a Wails-based desktop wrapper around the goloom
// WireGuard client (pkg/wgclient). It gives operators a visual
// interface for pasting a connection string from the admin panel,
// monitoring tunnel state, and tailing the session log without
// having to run a CLI from an elevated terminal.
//
// The app needs Administrator on Windows because it edits the route
// table to keep SFU traffic out of the system WG default route. The
// embedded build/windows/info.json carries `requestedExecutionLevel
// requireAdministrator` so launching the .exe triggers UAC.
package main

import (
	"context"
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/src
var assets embed.FS

func main() {
	// Drop wintun.dll next to the .exe so the auto-WG path can find
	// it. The function is no-op on non-Windows builds (build tag).
	// We surface errors as a startup print + continue — the GUI is
	// still useful without auto-WG (operator can run external WG).
	if err := ensureWintunDLL(); err != nil {
		println("warn: wintun.dll extraction failed:", err.Error())
	}

	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "goloom",
		Width:     720,
		Height:    580,
		MinWidth:  520,
		MinHeight: 420,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 14, G: 16, B: 20, A: 1}, // matches admin panel bg-bg
		OnStartup: func(ctx context.Context) {
			app.startup(ctx)
			// Tray runs alongside Wails — energye/systray supports
			// being driven from a goroutine on Windows. Spawning here
			// (vs main()) means the App context is live, so menu
			// handlers can call runtime.Window* immediately.
			go startTray(app)
		},
		OnShutdown: app.shutdown,
		// Closing the window hides instead of quitting — the tray
		// stays alive so the operator can pop the window back open
		// without restarting the tunnel session. Use the tray "Выйти"
		// menu (or Alt+F4 from the Wails main loop) to actually quit.
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			runtime.WindowHide(ctx)
			return true
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
		},
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("goloom-wg-gui fatal:", err.Error())
	}
}
