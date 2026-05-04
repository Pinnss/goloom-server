//go:build linux

// AdoptTun and the embedded wireguard-go device live in this file only
// on Linux (which is what gomobile bind -target=android produces). On
// other targets there is a stub in wgembed_other.go so the API surface
// stays uniform — desktop builds (e.g. CI on macOS/Windows) compile
// cleanly even though they never actually drive a kernel TUN.

package mobile

import (
	"errors"
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Встроенный pure-go WireGuard userspace, который мы запускаем на TUN-fd
// от VpnService.Builder.establish() (Android) или NEPacketTunnelProvider
// (iOS).
//
// Зачем не wireguard-android (com.wireguard.android:tunnel):
//   1) Его native-сторона хардкодит путь /data/data/com.wireguard.android
//      для UAPI socket — наш package (`app.goloom.client`) туда писать
//      не может, и uapi-горутина крашится через nil-fd → SIGSEGV.
//   2) GoBackend.setState() поднимает свой VpnService и конфликтует с
//      нашим (нельзя два VpnService одновременно).
//
// Встраивая wireguard-go прямо сюда, мы получаем единый .aar с обоими
// стеками (Goloom-relay + WG) и не зависим от внешней .aar.

// wgEmbed держит активный экземпляр wg-userspace device. Реентерабельно
// безопасен (один туннель за раз, сериализуем доступ через mutex).
type wgEmbed struct {
	mu     sync.Mutex
	dev    *device.Device
	tunDev tun.Device
}

var embedded wgEmbed

// AdoptTun забирает уже открытый TUN-fd (полученный native-стороной из
// VpnService.Builder.establish()), создаёт wireguard-go device и
// конфигурирует его UAPI-командами из [wgUserspaceConfig].
//
// Native-сторона вызывает этот метод сразу после Connect() — TUN-fd
// должен соответствовать interface'у с тем же address/peer, что в
// connstr (поля wga/wgsp/wgcp/wge), иначе пакеты пойдут не туда.
//
// Возвращает nil при успехе. При ошибке tunFd закрывается изнутри.
func (c *Client) AdoptTun(tunFd int, wgUserspaceConfig string) error {
	embedded.mu.Lock()
	defer embedded.mu.Unlock()

	if embedded.dev != nil {
		return errors.New("tunnel already adopted; call Disconnect first")
	}
	if tunFd < 0 {
		return errors.New("invalid tun fd")
	}

	// CreateTUNFromFile принимает *os.File; для fd используем
	// CreateUnmonitoredTUNFromFD — он не пытается читать /proc/net/dev.
	tunDev, name, err := tun.CreateUnmonitoredTUNFromFD(tunFd)
	if err != nil {
		return fmt.Errorf("create tun from fd: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[wg-go] ")
	logger.Verbosef = func(format string, args ...interface{}) {
		c.logger.Printf("[wg-go-verbose] "+format, args...)
	}
	logger.Errorf = func(format string, args ...interface{}) {
		c.logger.Printf("[wg-go-error] "+format, args...)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(wgUserspaceConfig); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("ipcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("device up: %w", err)
	}

	embedded.dev = dev
	embedded.tunDev = tunDev
	c.logger.Printf("wg-userspace adopted tun '%s' fd=%d", name, tunFd)
	return nil
}

// disconnectEmbedded закрывает активный wireguard-device, если он есть.
// Вызывается из Client.Disconnect — не публичная часть API.
func disconnectEmbedded(logger interface{ Printf(string, ...any) }) {
	embedded.mu.Lock()
	defer embedded.mu.Unlock()
	if embedded.dev == nil {
		return
	}
	embedded.dev.Close()
	embedded.dev = nil
	if embedded.tunDev != nil {
		_ = embedded.tunDev.Close()
		embedded.tunDev = nil
	}
	logger.Printf("wg-userspace torn down")
}
