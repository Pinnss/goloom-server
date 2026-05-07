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

	"github.com/Pinnss/goloom-server/pkg/wgclient"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the JS-visible binding surface. Holds the wgclient.Service
// and a reference to the wails context so we can emit events and
// dialogs from anywhere on the goroutine tree.
type App struct {
	ctx context.Context
	svc *wgclient.Service

	// stopFanOut closes when shutdown begins, so fan-out goroutine
	// drops its subscription cleanly.
	stopFanOut chan struct{}
}

// NewApp creates a new App with a fresh Service. Subscribe + event
// fan-out are wired in startup() — we need a live wails context for
// runtime.EventsEmit, which doesn't exist until OnStartup fires.
func NewApp() *App {
	return &App{
		svc:        wgclient.New(),
		stopFanOut: make(chan struct{}),
	}
}

// startup is called once the Wails app and frontend are ready.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	a.svc.Logger().SetOutput(&teeWriter{
		primary:   a.svc.Logger().Writer(),
		secondary: os.Stderr,
	})
	log.Printf("[gui] startup")

	go a.fanOutEvents()
}

// shutdown is called when the Wails main loop is winding down.
func (a *App) shutdown(ctx context.Context) {
	close(a.stopFanOut)
	a.svc.Stop()
}

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

// ─── JS bindings ──────────────────────────────────────────────────

// Connect starts a tunnel session. The connstr is a goloom://...
// link copied from the admin panel. Returns the parsed config so the
// frontend can show the operator what was decoded.
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

// Disconnect tears down the running session. Idempotent.
func (a *App) Disconnect() {
	a.svc.Stop()
}

// Status returns the current snapshot. Used by the frontend on initial
// load and as a fallback if event delivery dropped a frame.
func (a *App) Status() wgclient.Status {
	return a.svc.Status()
}

// RecentLogs returns the last `n` captured log lines (newest last).
// Used by the frontend to backfill the log pane on page (re)load.
func (a *App) RecentLogs(n int) []wgclient.LogLine {
	return a.svc.RecentLogs(n)
}

// SetVerbose toggles trace-line capture. When off (default), the
// SFU's RTCP / ping-ack chatter is dropped before it enters the
// ring buffer or broadcast — keeps the log pane focused on
// operationally interesting events and avoids spending CPU on
// per-feedback-report formatting.
func (a *App) SetVerbose(on bool) { a.svc.SetVerbose(on) }

// Verbose returns the current verbose flag so the frontend can
// initialise the UI checkbox state on first load.
func (a *App) Verbose() bool { return a.svc.Verbose() }
