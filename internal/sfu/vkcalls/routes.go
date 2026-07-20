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
	// VK мигрирует vk.com -> vk.ru, причём вразнобой: на 2026-07-20 капча
	// уже отдаётся с id.vk.ru + static.vk.ru, а domain= в redirect_uri всё
	// ещё vk.com. Держим ОБА набора — лишний хост стоит одного DNS-запроса,
	// а пропущенный роняет auth до поднятия туннеля.
	hosts := []string{
		"login.vk.ru",          // step 0 — anonym seed token
		"api.vk.ru",            // step 1 — calls.getAnonymousToken (актуальный)
		"api.vk.com",           // step 1 — legacy алиас
		"id.vk.ru",             // captcha redirect target
		"id.vk.com",            // captcha redirect, legacy алиас
		"static.vk.ru",         // captcha JS-бандл (not_robot_captcha.js)
		"ad.mail.ru",           // sync-loader.js — источник adFp для капчи
		"calls.okcdn.ru",       // step 2/3 — anonymLogin + joinByLink
		"videowebrtc.okcdn.ru", // signaling WSS
		"vk.ru",                // generic, used as Origin/Referer
		"vk.com",               // generic, legacy алиас
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
