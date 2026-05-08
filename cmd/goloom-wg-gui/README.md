# README

## About

This template uses plain JS / HTML and CSS.

You can configure the project by editing `wails.json`. More information about the project settings can be found
here: https://wails.io/docs/reference/project-config

## Live Development

To run in live development mode, run `wails dev` in the project directory. This will run a Vite development
server that will provide very fast hot reload of your frontend changes. If you want to develop in a browser
and have access to your Go methods, there is also a dev server that runs on http://localhost:34115. Connect
to this in your browser, and you can call your Go code from devtools.

## Building

Use the build wrapper:

```bash
./build-windows.sh
```

Output lands at `build/bin/goloom-wg-gui.exe`.

The wrapper exists because vanilla `wails build` collides with the
`resource_windows_*.syso` files we ship for icon + admin-manifest
(too many .rsrc sections). The script stashes the .syso aside,
invokes wails, then restores them.

**Caveat**: the stashed-aside .syso doesn't make it into the
binary, so the resulting exe has Wails' default asInvoker
manifest. **Launch via right-click → Run as administrator** (or
pin a shortcut with the "Run as administrator" advanced flag).
A clean fix would post-process the binary with rcedit/mt.exe —
not currently wired up.

If you'd rather skip the wails pipeline and rely on the embedded
`//go:embed all:frontend/src` (smaller binary, no Wails-runtime
hooks), `go build .` works too — but you'll lose the live-reload
dev server and may hit subtle differences vs. the Wails-built
version. Stick with `build-windows.sh` for production.
