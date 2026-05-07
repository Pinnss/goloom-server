package telemost

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ResolveSFUIPs returns the public IPs that the Telemost SFU and
// signalling endpoints currently resolve to, so the client can exclude
// them from its WG default-route capture (otherwise the very pion
// sockets we use to connect to Telemost would be tunnelled, breaking
// the bootstrap).
//
// Mirrors the inline helper that used to live in
// cmd/goloom-wg-client/main.go::resolveTelemostIPs — moved here so the
// transport-specific knowledge stays in transport-specific code.
//
// Returns the union of A/AAAA records across the standard Yandex hosts
// plus whatever host is in the meeting URL. Errors only when zero IPs
// could be resolved.
func ResolveSFUIPs(meetingURL string) ([]net.IP, error) {
	hosts := []string{
		"cloud-api.yandex.ru",
		"telemost.yandex.ru",
		"goloom.strm.yandex.net",
		"strm.yandex.net",
	}
	if u, err := url.Parse(meetingURL); err == nil && u.Host != "" {
		// Append meeting host if it differs from telemost.yandex.ru
		// (rare but happens for staging links).
		seen := false
		for _, h := range hosts {
			if h == u.Host {
				seen = true
				break
			}
		}
		if !seen {
			hosts = append(hosts, u.Host)
		}
	}

	var allIPs []net.IP
	for _, host := range hosts {
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		allIPs = append(allIPs, ips...)
	}
	if len(allIPs) == 0 {
		return nil, fmt.Errorf("telemost: no IPs resolved for %v", hosts)
	}
	return allIPs, nil
}

// ExtractICEHost pulls the host portion from a TURN/STUN URL emitted
// by Telemost in serverHello.RtcConfiguration.ICEServers. Used to add
// dynamically-discovered TURN servers to the route-exclusion list.
//
// Examples:
//
//	"turn:turn.yandex.ru:3478?transport=udp" → "turn.yandex.ru"
//	"stuns:stun.yandex.ru:5349"              → "stun.yandex.ru"
//	"https://goloom.strm.yandex.net/foo"     → "goloom.strm.yandex.net"
func ExtractICEHost(rawURL string) string {
	for _, prefix := range []string{"turn:", "turns:", "stun:", "stuns:"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
			if idx := strings.Index(rest, "?"); idx >= 0 {
				rest = rest[:idx]
			}
			host, _, err := net.SplitHostPort(rest)
			if err == nil && host != "" {
				return host
			}
			return rest
		}
	}
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host, _, _ := net.SplitHostPort(u.Host)
		if host != "" {
			return host
		}
		return u.Host
	}
	return ""
}
