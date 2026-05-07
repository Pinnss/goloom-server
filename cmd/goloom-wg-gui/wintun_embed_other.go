// Stub so cross-platform `go vet ./...` from the parent module doesn't
// complain. The GUI is Windows-only at runtime regardless.

//go:build !windows

package main

func ensureWintunDLL() error { return nil }
