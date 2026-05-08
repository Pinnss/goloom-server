package vkcalls

import (
	"fmt"
	"net"
)

// ResolveSFUIPs returns the public IPs that the VK Calls auth chain
// + signalling endpoints currently resolve to, so the client can
// exclude them from its WG default-route capture before AutoWG
// hijacks the default route.
//
// Without this pre-resolve the bootstrap DNS for login.vk.ru /
// api.vk.com / id.vk.com / calls.okcdn.ru / videowebrtc.okcdn.ru
// goes through the WG tunnel, which doesn't exist yet → auth fails
// with `getaddrinfow: name valid but no data of the requested type`.
//
// Mirror of [telemost.ResolveSFUIPs]. Returns the union of A/AAAA
// records across the well-known VK auth + signaling hosts. Errors
// only when zero IPs could be resolved.
func ResolveSFUIPs() ([]net.IP, error) {
	hosts := []string{
		"login.vk.ru",          // step 0 — anonym seed token
		"api.vk.com",           // step 1 — calls.getAnonymousToken
		"id.vk.com",            // captcha redirect target
		"id.vk.ru",             // captcha redirect alias
		"calls.okcdn.ru",       // step 2/3 — anonymLogin + joinByLink
		"videowebrtc.okcdn.ru", // signaling WSS
		"vk.com",               // generic, used as Origin/Referer
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
		return nil, fmt.Errorf("vkcalls: no IPs resolved for %v", hosts)
	}
	return allIPs, nil
}
