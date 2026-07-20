// VK Calls транспорт для мобильного клиента. Адаптирует captcha solver
// к native WebView через [BrowserLauncher] callback.

package mobile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/pkg/vkauth"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// runVKSession — мобильный аналог wgclient.runOnce для VK Calls.
// Серверный inbound уже peer-join'ится в этот же call (по ссылке из
// connstr); клиент здесь идёт в тот же call вторым peer'ом.
func (c *Client) runVKSession(parentCtx context.Context, params *connstr.Params, listenAddr string) (ConnectResult, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	displayName := identity.NameOrGenerate(params.DisplayName)
	c.mu.Lock()
	c.displayName = displayName
	c.mu.Unlock()

	if params.Meeting == "" {
		cancel()
		return ConnectResult{}, errors.New("vk-calls: meeting URL не задан в connstr")
	}

	captchaSolver := c.buildVKCaptchaSolver()
	if captchaSolver == nil {
		c.logger.Printf("vk-calls: WARN no captcha solver registered — auth will fail on captcha")
	}

	c.emitPhase("auth", "VK auth ladder")

	spec := sfu.ConnectSpec{
		Kind:        sfu.KindVKCalls,
		DisplayName: displayName,
		Logger:      c.logger,
		VKCalls: &sfu.VKCallsConnect{
			MeetingURL:    params.Meeting,
			Role:          "caller",
			Codec:         params.Codec,
			CaptchaSolver: captchaSolver,
		},
	}
	transport, err := sfu.Get(sfu.KindVKCalls)
	if err != nil {
		cancel()
		return ConnectResult{}, fmt.Errorf("vk-calls transport: %w", err)
	}

	c.emitPhase("target_connect", "VK SFU peer-join + SDP exchange")
	sess, err := transport.Connect(ctx, spec)
	if err != nil {
		cancel()
		return ConnectResult{}, fmt.Errorf("vk-calls connect: %w", err)
	}

	// Resolve external hosts that should bypass the VPN tunnel —
	// VK Calls SFU edges + auth hosts. Native side (Kotlin) добавит
	// в VpnService.Builder.addDisallowedRoute.
	var bypassIPs []net.IP
	if hp, ok := sess.(sfu.ICEHostsProvider); ok {
		for _, host := range hp.ICEHosts() {
			if ips, err := net.LookupIP(host); err == nil {
				bypassIPs = append(bypassIPs, ips...)
			}
		}
	}

	c.emitPhase("bridge_up", "WireGuard bridge listen "+listenAddr)
	bridge := wgrelay.NewClientBridge(listenAddr, sess, c.logger)

	// Bridge.Run блокирует. Гоним в горутину и сообщаем о результате
	// через c.sessionDone — supervisor разрешит retry.
	done := make(chan error, 1)
	c.mu.Lock()
	prevDone := c.sessionDone
	c.sessionDone = done
	c.mu.Unlock()
	if prevDone != nil {
		select {
		case prevDone <- context.Canceled:
		default:
		}
	}
	go func() {
		bridgeErr := bridge.Run(ctx)
		sess.Close()
		cancel()
		select {
		case done <- bridgeErr:
		default:
		}
	}()

	res := ConnectResult{
		DisplayName: displayName,
		ListenAddr:  listenAddr,
		WGEndpoint:  listenAddr,
		TelemostIPs: ipsToStrings(bypassIPs),
	}
	if params.HasWG() {
		params.WGEndpoint = listenAddr
		res.WGClientConfig = params.WGClientConfig()
		res.WGClientAddr = params.WGClientAddr
	}
	return res, nil
}

// buildVKCaptchaSolver возвращает captcha solver с client-side
// auto-replay (если SetVKProfileStorePath задан):
//
//  1. Pool попыток сначала: vkauth.WithReplaySolver берёт freshest
//     профиль из пула, гонит captcha_v2 через VK API напрямую — без
//     UI, ~3 сек. Успех → MarkSuccess + return token.
//  2. Fallback на manual: если пул пуст / replay фейлнулся / VK
//     прислал slider — поднимаем local reverse-proxy
//     (vkauth.AutoProxyCaptchaSolverWithOpener) + зовём native
//     [BrowserLauncher] открыть WebView. Параллельно loggingTransport
//     внутри proxy ловит componentDone/check тела и кормит профиль в
//     пул — следующий коннект в этой же сессии работает без UI.
func (c *Client) buildVKCaptchaSolver() sfu.VKCaptchaSolver {
	c.phaseMu.Lock()
	launcher := c.browserCB
	c.phaseMu.Unlock()
	if launcher == nil {
		return nil
	}

	c.mu.Lock()
	storePath := c.vkProfileStorePath
	c.mu.Unlock()
	var store *vkauth.ProfileStore
	if storePath != "" {
		s, err := vkauth.NewProfileStore(vkauth.ProfileStoreOptions{Path: storePath})
		if err != nil {
			c.logger.Printf("vk-calls: client profile store init failed (%v); manual captcha each time", err)
		} else {
			store = s
			c.logger.Printf("vk-calls: client profile store: %s (%d profiles)", storePath, len(store.Snapshot()))
		}
	}

	opener := func(url string) {
		c.emitPhase("captcha", "open captcha in WebView")
		launcher.Open(url)
	}

	// VK'шный URL уходит в WebView КАК ЕСТЬ, без localhost-прокси: иначе
	// ломается CORS для adFp (privacy-cs.mail.ru) и подменяется JA3, и VK
	// отдаёт status=BOT даже на настоящий тап. Подробности — в
	// [vkauth.NativeCaptchaSolver]. Токен присылает native через
	// [Client.SubmitVKCaptchaToken].
	native := vkauth.NewNativeCaptchaSolver(2*time.Minute, c.logger, opener)
	c.mu.Lock()
	c.captchaNative = native
	c.captchaStore = store
	c.mu.Unlock()

	base := sfu.VKCaptchaSolver(native.Solve)
	if store != nil {
		return vkauth.WithReplaySolver(store, base, c.logger)
	}
	return base
}

// SubmitVKCaptchaToken принимает success_token, который native-сторона
// выцепила из ответа captchaNotRobot.check в WebView. Вызывается из Kotlin
// через JS-мост; безопасен если никто не ждёт токен.
func (c *Client) SubmitVKCaptchaToken(token string) {
	c.mu.Lock()
	native := c.captchaNative
	c.mu.Unlock()
	if native == nil {
		c.logger.Printf("vkcalls/captcha-native: token submitted before solver was built — ignored")
		return
	}
	native.Submit(token)
}

// SubmitVKCaptchaProfile складывает в пул отпечаток, снятый native-стороной со
// страницы captcha. Вызывается из Kotlin через JS-мост.
//
// Раньше это делал loggingTransport внутри локального прокси, но прокси убран
// (он же и ломал captcha), а VK к тому же раскладывает отпечаток по двум
// запросам: device в componentDone, browser_fp в check. Native-хук копит обе
// половины и присылает их сюда одним вызовом — [vkauth.ProfileStore.Capture]
// молча отбрасывает профиль с любым пустым полем.
//
// Смысл пула: следующий коннект проходит captcha автоматически, без UI.
func (c *Client) SubmitVKCaptchaProfile(deviceJSON, browserFP, userAgent string) {
	c.mu.Lock()
	store := c.captchaStore
	c.mu.Unlock()
	if store == nil {
		return
	}
	if deviceJSON == "" || browserFP == "" || userAgent == "" {
		c.logger.Printf("vkcalls/captcha-native: incomplete profile (device=%dB browser_fp=%dB ua=%dB) — not pooled",
			len(deviceJSON), len(browserFP), len(userAgent))
		return
	}
	store.Capture(vkauth.CapturedProfile{
		UserAgent:  userAgent,
		DeviceJSON: deviceJSON,
		BrowserFP:  browserFP,
	})
	c.logger.Printf("vkcalls/captcha-native: fingerprint pooled (device=%dB browser_fp=%dB); pool=%d",
		len(deviceJSON), len(browserFP), len(store.Snapshot()))
}

// strconv used elsewhere in mobile; keep import alias consumer.
var _ = strconv.Itoa
