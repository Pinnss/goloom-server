// app.go wires the Wails frontend ⇄ Go backend bridge.
//
// All methods on *App are callable from JavaScript via the
// auto-generated wailsjs bindings. Real-time pushes (status changes,
// log lines) come over Wails events with the names "status" and
// "log" — see frontend/src/main.js for the consumer side.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"

	"github.com/Pinnss/goloom-server/pkg/wgclient"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the JS-visible binding surface. Holds the wgclient.Service,
// the persistent profile store, and a reference to the wails context
// so we can emit events and dialogs from anywhere on the goroutine tree.
type App struct {
	ctx      context.Context
	svc      *wgclient.Service
	profiles *profileStore

	// stopFanOut closes when shutdown begins, so fan-out goroutine
	// drops its subscription cleanly.
	stopFanOut chan struct{}

	// quitting flips to true when the tray "Выйти" menu (or any other
	// real-shutdown path) fires. OnBeforeClose checks this to decide
	// whether to actually close (true → close) or hide-to-tray
	// (false → keep alive). Without this the X-button-hides-to-tray
	// behaviour also swallowed runtime.Quit() calls from the tray.
	quitting atomic.Bool
}

// NewApp creates a new App with a fresh Service. Subscribe + event
// fan-out are wired in startup() — we need a live wails context for
// runtime.EventsEmit, which doesn't exist until OnStartup fires.
//
// Profile store init failure is non-fatal — we log it and the
// frontend will see an empty list. Common cause is a permission
// problem on %APPDATA%; ignoring it lets the user still paste a
// connstr ad-hoc.
func NewApp() *App {
	app := &App{
		svc:        wgclient.New(),
		stopFanOut: make(chan struct{}),
	}
	if ps, err := newProfileStore(); err == nil {
		app.profiles = ps
	} else {
		// Defer the error report to startup() once the wails logger
		// is available. For now stash a placeholder so binding calls
		// fail predictably rather than nil-panic.
		app.profiles = nil
		log.Printf("profiles: store init failed: %v (operating profile-less)", err)
	}
	return app
}

// startup is called once the Wails app and frontend are ready.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	a.svc.Logger().SetOutput(&teeWriter{
		primary:   a.svc.Logger().Writer(),
		secondary: os.Stderr,
	})
	log.Printf("[gui] startup")
	if a.profiles != nil {
		a.svc.Logger().Printf("profiles: %d loaded from %s", len(a.profiles.List()), a.profiles.Path())
	}

	go a.fanOutEvents()
}

// shutdown is called when the Wails main loop is winding down.
func (a *App) shutdown(ctx context.Context) {
	close(a.stopFanOut)
	a.svc.Stop()
}

// QuittingAllowed is checked from main.go's OnBeforeClose hook. When
// false (default), closing the window hides to tray. When true, the
// tray "Выйти" menu has already initiated a real exit and the close
// should proceed normally.
func (a *App) QuittingAllowed() bool { return a.quitting.Load() }

// BeginQuit marks the App as in the middle of a real shutdown. Called
// from the tray Quit handler before runtime.Quit so the OnBeforeClose
// hook lets the close go through.
func (a *App) BeginQuit() { a.quitting.Store(true) }

// fanOutEvents subscribes to the service and re-emits events through
// the Wails runtime so JS can listen via window.runtime.EventsOn.
func (a *App) fanOutEvents() {
	events, cancel := a.svc.Subscribe()
	defer cancel()

	for {
		select {
		case <-a.stopFanOut:
			return
		case <-a.ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			switch ev.Kind {
			case wgclient.EventStatus:
				if ev.Status != nil {
					runtime.EventsEmit(a.ctx, "status", ev.Status)
				}
			case wgclient.EventLog:
				if ev.Log != nil {
					runtime.EventsEmit(a.ctx, "log", ev.Log)
				}
			}
		}
	}
}

// ─── connection bindings ─────────────────────────────────────────

// Connect starts a tunnel session from a raw connstr. Convenience
// wrapper around ImportProfile + ConnectProfile that does NOT save
// — useful for one-shot debug runs without polluting the store.
func (a *App) Connect(connstr string) (wgclient.Config, error) {
	cfg, err := wgclient.FromConnStr(connstr)
	if err != nil {
		return wgclient.Config{}, fmt.Errorf("decode connstr: %w", err)
	}
	if err := a.svc.Start(a.ctx, cfg); err != nil {
		if errors.Is(err, wgclient.ErrAlreadyRunning) {
			return cfg, errors.New("session is already running — disconnect first")
		}
		return cfg, err
	}
	return cfg, nil
}

// ConnectProfile loads the profile by ID, starts a session, and
// records the use timestamp for sorting.
func (a *App) ConnectProfile(id string) (Profile, error) {
	if a.profiles == nil {
		return Profile{}, errors.New("profile store unavailable")
	}
	p, ok := a.profiles.Get(id)
	if !ok {
		return Profile{}, fmt.Errorf("profile %q not found", id)
	}
	if err := a.svc.Start(a.ctx, p.Config); err != nil {
		if errors.Is(err, wgclient.ErrAlreadyRunning) {
			return p, errors.New("session is already running — disconnect first")
		}
		return p, err
	}
	a.profiles.MarkUsed(p.ID, a.svc.Logger())
	return p, nil
}

// Disconnect tears down the running session. Idempotent.
func (a *App) Disconnect() { a.svc.Stop() }

// Status returns the current snapshot. Used by the frontend on initial
// load and as a fallback if event delivery dropped a frame.
func (a *App) Status() wgclient.Status { return a.svc.Status() }

// RecentLogs returns the last `n` captured log lines (newest last).
// Used by the frontend to backfill the log pane on page (re)load.
func (a *App) RecentLogs(n int) []wgclient.LogLine { return a.svc.RecentLogs(n) }

// SetVerbose toggles trace-line capture. When off (default), the
// SFU's RTCP / ping-ack chatter is dropped before it enters the
// ring buffer or broadcast — keeps the log pane focused on
// operationally interesting events and avoids spending CPU on
// per-feedback-report formatting.
func (a *App) SetVerbose(on bool) { a.svc.SetVerbose(on) }

// Verbose returns the current verbose flag so the frontend can
// initialise the UI checkbox state on first load.
func (a *App) Verbose() bool { return a.svc.Verbose() }

// ─── profile bindings ────────────────────────────────────────────

// ListProfiles returns all saved profiles, ordered most-recently-used
// first. Empty slice is fine for the UI (just renders an empty list).
func (a *App) ListProfiles() []Profile {
	if a.profiles == nil {
		return []Profile{}
	}
	return a.profiles.List()
}

// ActiveProfileID returns the ID of the last-connected profile so
// the UI can preselect it on launch.
func (a *App) ActiveProfileID() string {
	if a.profiles == nil {
		return ""
	}
	return a.profiles.ActiveID()
}

// ImportProfile parses a connstr, saves it as a new profile, and
// returns the persisted record. If name is empty, a default is
// inferred from the decoded transport + meeting URL. autoWG is
// stored on the profile so launching it brings up the wintun
// tunnel automatically (only effective if the connstr embedded
// the WG client config — wb-stream connstrs that ship without
// WG keys silently keep AutoWG off).
func (a *App) ImportProfile(connstr, name string, autoWG bool, vkTargetMeeting string) (Profile, error) {
	if a.profiles == nil {
		return Profile{}, errors.New("profile store unavailable")
	}
	cfg, err := wgclient.FromConnStr(connstr)
	if err != nil {
		return Profile{}, fmt.Errorf("decode connstr: %w", err)
	}
	cfg.AutoWG = autoWG && cfg.WG.Valid()
	// Для VK lobby connstr'ов (нет 'm', есть 'lm'+'b') target meeting
	// приходит из UI отдельным полем — frontend парсит connstr,
	// детектит lobby режим, показывает дополнительный input.
	if cfg.LobbyMeetingURL != "" && cfg.Bearer != "" && vkTargetMeeting != "" {
		cfg.Meeting = vkTargetMeeting
	}
	return a.profiles.Add(name, cfg)
}

// SaveProfile creates or updates a profile from raw fields. Used by
// the manual-form path of the "Add profile" modal.
func (a *App) SaveProfile(id, name string, cfg wgclient.Config) (Profile, error) {
	if a.profiles == nil {
		return Profile{}, errors.New("profile store unavailable")
	}
	if id == "" {
		return a.profiles.Add(name, cfg)
	}
	return a.profiles.Update(id, name, cfg)
}

// DeleteProfile removes a profile by ID. Returns an error if the
// profile doesn't exist.
func (a *App) DeleteProfile(id string) error {
	if a.profiles == nil {
		return errors.New("profile store unavailable")
	}
	return a.profiles.Delete(id)
}

// ProfilesPath returns the on-disk JSON path so the UI can show
// "Open in explorer" or similar affordances.
func (a *App) ProfilesPath() string {
	if a.profiles == nil {
		return ""
	}
	return a.profiles.Path()
}
