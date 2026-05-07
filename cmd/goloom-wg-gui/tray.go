// System-tray integration for the goloom GUI.
//
// We run the tray loop in a goroutine alongside the Wails main loop.
// The energye/systray fork supports this on Windows; on other
// platforms it would conflict with the OS UI thread, but the GUI is
// Windows-only today (admin manifest, route.exe, wintun deps).
//
// The tray exposes a minimal menu — Show/Hide, Connect, Disconnect,
// Quit — that mirrors what the user can do from the main window.
// Menu item state (enabled/disabled, label) is kept in sync with
// wgclient.Service via a Subscribe goroutine so the menu reflects
// reality even when the window is hidden.

package main

import (
	_ "embed"
	"errors"
	"sync/atomic"

	"github.com/Pinnss/goloom-server/pkg/wgclient"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// trayIconICO is the .ico used for both the window and the tray.
// Same file the wails build embeds for the .exe icon — pulled in via
// go:embed so the running process doesn't depend on the file being
// present on disk.
//
//go:embed build/windows/icon.ico
var trayIconICO []byte

// trayController owns the menu items so the status-watch goroutine
// can flip their enabled state and labels in response to phase
// transitions.
type trayController struct {
	app *App

	mShow       *systray.MenuItem
	mConnect    *systray.MenuItem
	mDisconnect *systray.MenuItem
	mQuit       *systray.MenuItem

	// running mirrors the wgclient phase so menu updates can short-
	// circuit when nothing relevant changed.
	running atomic.Bool
}

// startTray spawns the systray loop. Returns immediately; the loop
// itself runs on a goroutine the systray library manages.
func startTray(app *App) {
	t := &trayController{app: app}
	systray.Run(t.onReady, t.onExit)
}

func (t *trayController) onReady() {
	systray.SetIcon(trayIconICO)
	systray.SetTitle("goloom")
	systray.SetTooltip("goloom — idle")

	// Header: just the brand. Disabled, can't be clicked.
	hdr := systray.AddMenuItem("goloom (idle)", "")
	hdr.Disable()
	systray.AddSeparator()

	t.mShow = systray.AddMenuItem("Показать окно", "Show the goloom window")
	systray.AddSeparator()

	t.mConnect = systray.AddMenuItem("Connect", "Connect using the last-used profile")
	t.mDisconnect = systray.AddMenuItem("Disconnect", "Tear down the running session")
	t.mDisconnect.Disable()
	systray.AddSeparator()

	t.mQuit = systray.AddMenuItem("Выйти", "Quit goloom")

	// Wire menu item handlers. energye/systray's MenuItem.Click
	// registers a no-arg callback that fires when the user picks
	// the item — no need for per-item goroutines draining a channel.
	t.mShow.Click(t.showWindow)
	t.mConnect.Click(t.connect)
	t.mDisconnect.Click(t.disconnect)
	t.mQuit.Click(t.quit)

	// Single-click on the tray icon = show + raise the window.
	systray.SetOnClick(func(_ systray.IMenu) { t.showWindow() })

	// Reflect the wgclient.Service phase into menu state so the
	// tray UI is meaningful when the window is hidden.
	go t.watchStatus(hdr)
}

func (t *trayController) onExit() {}

// watchStatus subscribes to the service event stream and pushes
// label / enabled-state updates to the tray. Blocks until the App
// context is cancelled.
func (t *trayController) watchStatus(hdr *systray.MenuItem) {
	events, cancel := t.app.svc.Subscribe()
	defer cancel()

	// Pull the current snapshot so the initial label is right even
	// before any new event arrives.
	t.applyStatus(hdr, t.app.svc.Status())

	for {
		select {
		case <-t.app.ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if ev.Kind != wgclient.EventStatus || ev.Status == nil {
				continue
			}
			t.applyStatus(hdr, *ev.Status)
		}
	}
}

func (t *trayController) applyStatus(hdr *systray.MenuItem, st wgclient.Status) {
	running := st.Phase != wgclient.PhaseIdle && st.Phase != "" && st.Phase != wgclient.PhaseError
	t.running.Store(running)

	label := "goloom (" + string(st.Phase) + ")"
	hdr.SetTitle(label)
	systray.SetTooltip(label)

	if running {
		t.mConnect.Disable()
		t.mDisconnect.Enable()
	} else {
		// Connect is only useful if there's at least one saved profile
		// (the tray uses the last-active one).
		if t.app.profiles != nil && t.app.profiles.ActiveID() != "" {
			t.mConnect.Enable()
		} else if t.app.profiles != nil && len(t.app.profiles.List()) > 0 {
			t.mConnect.Enable()
		} else {
			t.mConnect.Disable()
		}
		t.mDisconnect.Disable()
	}
}

// ─── menu actions ───────────────────────────────────────────────

func (t *trayController) showWindow() {
	if t.app.ctx == nil {
		return
	}
	runtime.WindowShow(t.app.ctx)
	runtime.WindowUnminimise(t.app.ctx)
}

func (t *trayController) connect() {
	if t.app.profiles == nil {
		return
	}
	id := t.app.profiles.ActiveID()
	if id == "" {
		// No last-used profile — fall back to the most-recent in the
		// list (which is what the dropdown defaults to).
		list := t.app.profiles.List()
		if len(list) == 0 {
			t.showWindow()
			return
		}
		id = list[0].ID
	}
	if _, err := t.app.ConnectProfile(id); err != nil {
		// On failure, surface the window so the operator can read
		// the error in the panel.
		if !errors.Is(err, wgclient.ErrAlreadyRunning) {
			t.showWindow()
		}
	}
}

func (t *trayController) disconnect() { t.app.svc.Stop() }

func (t *trayController) quit() {
	// Mark the app as really-quitting BEFORE asking wails to close,
	// so the OnBeforeClose hook lets the close go through instead
	// of converting it back to "hide to tray".
	t.app.BeginQuit()

	// Tear down the session first so the tunnel/route cleanup
	// happens while wails is still up (and our log capture still
	// shows it). runtime.Quit then drives the OnShutdown hook for
	// the rest of the cleanup; systray.Quit drops the tray icon.
	t.app.svc.Stop()
	if t.app.ctx != nil {
		runtime.Quit(t.app.ctx)
	}
	systray.Quit()
}
