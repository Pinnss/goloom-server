// Run-once helper to compile the Windows .syso resource (icon +
// version info + admin-requesting manifest) that gets linked into
// the final .exe. The Wails build pipeline embeds its own manifest
// with `level=asInvoker`, which silently overrides the
// `requireAdministrator` we put in build/windows/wails.exe.manifest
// — generating our own resource.syso bypasses that and Go's linker
// picks ours up first.
//
// Generated file lives at resource_windows_amd64.syso (build-tag
// filtered automatically). Re-run with `go generate ./cmd/goloom-wg-gui`
// after editing versioninfo.json or the manifest.
//
//go:build generate

//go:generate goversioninfo -platform-specific=true -manifest=build/windows/goloom.exe.manifest -icon=build/windows/icon.ico versioninfo.json

package main
