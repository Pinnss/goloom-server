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
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/src
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "goloom",
		Width:  720,
		Height: 580,
		MinWidth:  520,
		MinHeight: 420,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 14, G: 16, B: 20, A: 1}, // matches admin panel bg-bg
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
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
