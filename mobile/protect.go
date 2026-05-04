package mobile

import (
	"sync"
	"sync/atomic"
	"syscall"
)

// Socket-protect plumbing.
//
// Android VpnService captures all the app's outbound traffic through the
// TUN. To prevent our Telemost WebRTC sockets from looping back into the
// VPN we have to call VpnService.protect(fd) on every socket BEFORE the
// connect() syscall. We expose this as a SocketProtector interface; the
// mobile app implements it on top of VpnService.
//
// On iOS NEPacketTunnelProvider does this automatically — there is no
// equivalent of Android's protect(). The interface accepts no-op
// implementations.

var (
	protectorMu sync.RWMutex
	protector   SocketProtector
)

func setSocketProtector(p SocketProtector) {
	protectorMu.Lock()
	protector = p
	protectorMu.Unlock()
}

// protectFD calls the registered protector if any.
func protectFD(fd uintptr) {
	protectorMu.RLock()
	p := protector
	protectorMu.RUnlock()
	if p == nil {
		return
	}
	_ = p.Protect(int64(fd))
}

// dialerControl is the net.Dialer.Control hook that pulls out the raw
// fd and hands it to the protector. Wired into the global pion
// transport configuration during package init.
func dialerControl(network, address string, c syscall.RawConn) error {
	var protected int32
	err := c.Control(func(fd uintptr) {
		protectFD(fd)
		atomic.StoreInt32(&protected, 1)
	})
	if err != nil {
		return err
	}
	return nil
}
