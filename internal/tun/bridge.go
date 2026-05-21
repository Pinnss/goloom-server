//go:build windows

package tun

import (
	"context"
	"log"
)

func RunBridge(ctx context.Context, dev *Device, st *Stack, lg *log.Logger) {
	toStack := make(chan []byte, 256)
	fromStack := make(chan []byte, 256)

	dev.RunPacketPump(ctx, toStack, fromStack)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-toStack:
				st.InjectPacket(pkt)
			}
		}
	}()

	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			pkt, ok := st.ReadPacket()
			if !ok {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			select {
			case fromStack <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}()

	lg.Printf("TUN-BRIDGE running (dev ↔ gVisor netstack)")
}
