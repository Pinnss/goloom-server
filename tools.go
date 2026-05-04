//go:build tools

// Package goloomtools закрепляет инструментальные зависимости в go.mod,
// которые не используются в production-коде, но нужны для билда (gomobile
// и его gobind ищут golang.org/x/mobile/bind в module-кэше).
//
// Build-tag `tools` исключает файл из обычной сборки.
package main

import (
	_ "golang.org/x/mobile/bind"
)
