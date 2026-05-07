// Embed wintun.dll into the GUI binary and drop it next to the
// running .exe at startup. wireguard-go's wintun bindings load the
// DLL via syscall.LoadLibrary, which searches the application
// directory first — so co-locating the file is enough, no PATH
// manipulation needed.
//
// We extract on every launch because checking-and-skipping has the
// same race-y "what if it's a different version?" cost without the
// safety. The DLL is ~420 KB; rewriting takes single-digit ms.

//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed build/wintun/wintun.dll
var wintunDLL []byte

// ensureWintunDLL writes the embedded wintun.dll alongside the
// running executable. Returns an error only on real I/O failure;
// "file already exists with matching size" is treated as success
// without rewriting.
func ensureWintunDLL() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	target := filepath.Join(filepath.Dir(exe), "wintun.dll")

	if st, err := os.Stat(target); err == nil && st.Size() == int64(len(wintunDLL)) {
		// Same size — assume same file. Avoids a write on every
		// launch (and the AV-flag risk of touching a hot file).
		return nil
	}

	if err := os.WriteFile(target, wintunDLL, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}
