package vkauth

import "strings"

// shortUA сокращает UA для логов: «Mozilla/5.0 ... Chrome/146...» →
// «Chrome/146 (Windows)» — достаточно чтобы понять какой профиль
// сработал, без замусоренных логов. Дублирует одноимённый helper из
// internal/sfu/vkcalls/auth.go — обе копии можно объединить когда
// vkcalls тоже мигрирует на vkauth.
func shortUA(ua string) string {
	chrome := ""
	if i := strings.Index(ua, "Chrome/"); i >= 0 {
		end := i + 7
		for end < len(ua) && (ua[end] == '.' || (ua[end] >= '0' && ua[end] <= '9')) {
			end++
		}
		chrome = ua[i:end]
	}
	plat := "?"
	switch {
	case strings.Contains(ua, "Windows"):
		plat = "Windows"
	case strings.Contains(ua, "Macintosh"):
		plat = "macOS"
	case strings.Contains(ua, "Linux"):
		plat = "Linux"
	}
	if chrome == "" {
		return plat
	}
	return chrome + " (" + plat + ")"
}
