#!/usr/bin/env bash
# Wails-build wrapper that side-steps the "too many .rsrc sections"
# linker error caused by our goversioninfo-generated .syso resources
# colliding with Wails' own embedded manifest.
#
# The .syso files (resource_windows_*.syso) supply our
# requireAdministrator manifest + icon + version info. Wails build
# unconditionally embeds its own asInvoker manifest in a parallel
# .rsrc section, so when both are present `go build` (which Wails
# invokes) bails on the duplicate.
#
# Workaround: stash the .syso aside, run wails build, restore them.
# The resulting binary in build/bin/ ends up with Wails' default
# asInvoker manifest — user must right-click → Run as administrator.
# Embedding our manifest into the wails-built exe post-hoc would
# need rcedit/mt.exe; not done here.
#
# Usage:
#   ./build-windows.sh        # build for windows/amd64
#   ./build-windows.sh -clean # also clear build/bin first
set -euo pipefail
cd "$(dirname "$0")"

WAILS_BIN="${WAILS_BIN:-$HOME/go/bin/wails}"
if [[ ! -x "$WAILS_BIN" ]]; then
    if command -v wails >/dev/null 2>&1; then
        WAILS_BIN="$(command -v wails)"
    else
        echo "ERROR: wails CLI not found. Install with:"
        echo "  go install github.com/wailsapp/wails/v2/cmd/wails@latest"
        exit 1
    fi
fi

STASH="$(mktemp -d)"
trap 'mv -f "$STASH"/*.syso . 2>/dev/null || true; rmdir "$STASH" 2>/dev/null || true' EXIT

echo "→ stashing .syso resources to $STASH"
mv resource_windows_*.syso "$STASH"/

echo "→ wails build $*"
"$WAILS_BIN" build -platform windows/amd64 -skipbindings "$@"

echo
echo "✓ build/bin/goloom-wg-gui.exe built."
echo "  NOTE: launch via right-click → Run as administrator (no embedded admin manifest in this build)."
