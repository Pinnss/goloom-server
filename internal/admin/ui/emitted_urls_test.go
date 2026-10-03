package ui_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every URL the panel emits has to go through uipath.URL, or it resolves at the
// server root and 404s the moment the panel is mounted under a base path. The
// first sweep only rewrote attributes with literal values and missed the ones
// built by concatenation or written inside JavaScript — which silently broke
// the post-login redirect and both QR-code endpoints while everything else
// looked fine.
//
// This walks the templates so the next hard-coded path fails here rather than
// in the browser.
func TestTemplatesEmitNoRootAbsoluteURLs(t *testing.T) {
	// Attributes carrying a literal absolute path, and absolute paths inside
	// quoted strings (concatenation, inline JS). Anything already wrapped in
	// uipath.URL is fine, as is a relative target.
	attrLiteral := regexp.MustCompile(`(?:href|src|action|hx-(?:get|post|put|patch|delete)|sse-connect)="(/[^"]*)"`)
	quotedPath := regexp.MustCompile(`"(/(?:api|htmx|static|login|logout)[^"]*)"|'(/(?:api|htmx|static|login|logout)[^']*)'`)

	root := "."
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".templ") {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "uipath.URL(") {
				continue // already routed through the helper
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // prose, not markup
			}
			for _, m := range attrLiteral.FindAllStringSubmatch(line, -1) {
				offenders = append(offenders, format(path, i+1, m[1]))
			}
			for _, m := range quotedPath.FindAllStringSubmatch(line, -1) {
				got := m[1]
				if got == "" {
					got = m[2]
				}
				offenders = append(offenders, format(path, i+1, got))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("%d emitted URL(s) bypass uipath.URL and will 404 under a base path:\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

func format(path string, line int, url string) string {
	return filepath.ToSlash(path) + ":" + itoa(line) + "  " + url
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
