package tunnel

import (
	"context"
	"log"
)

// Dispatcher reads from a merged ReceivedFrame channel and routes frames
// to the appropriate consumer based on flags:
//   - FlagKCP → TunnelPacketConn.Deliver (KCP transport datagrams)
//   - FlagHandshake/FlagHandshakeAck → handshake channel
//   - FlagPing/FlagPong → legacy test channel
//
// Run blocks until ctx is done or the input channel closes.
type Dispatcher struct {
	KCPConn      *TunnelPacketConn
	Handshake    chan<- ReceivedFrame
	Legacy       chan<- ReceivedFrame // ping/pong/test frames

	DroppedKCP   uint64
	DroppedOther uint64
}

func (d *Dispatcher) Run(ctx context.Context, in <-chan ReceivedFrame, lg *log.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-in:
			if !ok {
				return
			}
			if f.Flags.Has(FlagKCP) {
				cp := make([]byte, len(f.Payload))
				copy(cp, f.Payload)
				if !d.KCPConn.Deliver(cp) {
					d.DroppedKCP++
				}
				continue
			}
			if f.Flags.Has(FlagHandshake) || f.Flags.Has(FlagHandshakeAck) {
				select {
				case d.Handshake <- f:
				default:
					d.DroppedOther++
				}
				continue
			}
			select {
			case d.Legacy <- f:
			default:
				d.DroppedOther++
			}
		}
	}
}
