// Package peer wraps Pion's RTCPeerConnection with the few extras goloom
// requires: ICE candidate buffering until remote description is set, and a
// uniform logging prefix so PUB and SUB events are easy to tell apart.
package peer

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/pion/webrtc/v4"
)

// Wrapper owns one Pion PeerConnection plus the bits we need around it.
type Wrapper struct {
	Name string // "PUB" or "SUB"
	PC   *webrtc.PeerConnection
	Log  *log.Logger

	// remoteSet flips true the moment SetRemoteDescriptionAndFlush succeeds.
	remoteSet atomic.Bool

	// pending ICE candidates that arrived before remote description was set.
	mu         sync.Mutex
	pendingICE []webrtc.ICECandidateInit
}

// New builds a PeerConnection from the supplied API + Configuration. The
// caller wires OnICECandidate / OnTrack / OnDataChannel / OnConnectionStateChange
// before adding tracks or applying SDP.
func New(name string, api *webrtc.API, cfg webrtc.Configuration, lg *log.Logger) (*Wrapper, error) {
	pc, err := api.NewPeerConnection(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: NewPeerConnection: %w", name, err)
	}
	w := &Wrapper{Name: name, PC: pc, Log: lg}

	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		lg.Printf("%s connectionState: %s", name, s)
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		lg.Printf("%s iceConnectionState: %s", name, s)
	})
	pc.OnICEGatheringStateChange(func(s webrtc.ICEGatheringState) {
		lg.Printf("%s iceGatheringState: %s", name, s)
	})
	pc.OnSignalingStateChange(func(s webrtc.SignalingState) {
		lg.Printf("%s signalingState: %s", name, s)
	})
	pc.OnNegotiationNeeded(func() {
		lg.Printf("%s negotiationNeeded (ignored — no renegotiation in PoC #1)", name)
	})
	return w, nil
}

// AddICECandidate buffers if remote description not yet applied, applies
// directly otherwise. The double-check pattern avoids losing candidates that
// arrive concurrently with SetRemoteDescriptionAndFlush.
func (w *Wrapper) AddICECandidate(c webrtc.ICECandidateInit) error {
	if w.remoteSet.Load() {
		return w.PC.AddICECandidate(c)
	}
	w.mu.Lock()
	if w.remoteSet.Load() {
		w.mu.Unlock()
		return w.PC.AddICECandidate(c)
	}
	w.pendingICE = append(w.pendingICE, c)
	w.mu.Unlock()
	w.Log.Printf("%s ICE buffered (remote not set yet, total pending=%d)", w.Name, len(w.pendingICE))
	return nil
}

// SetRemoteDescriptionAndFlush applies the SDP, marks the remote-set flag,
// and drains any ICE candidates that arrived before it.
func (w *Wrapper) SetRemoteDescriptionAndFlush(d webrtc.SessionDescription) error {
	if err := w.PC.SetRemoteDescription(d); err != nil {
		return fmt.Errorf("%s SetRemoteDescription: %w", w.Name, err)
	}
	w.mu.Lock()
	pending := w.pendingICE
	w.pendingICE = nil
	w.remoteSet.Store(true)
	w.mu.Unlock()

	added := 0
	for _, c := range pending {
		if err := w.PC.AddICECandidate(c); err != nil {
			w.Log.Printf("%s ICE flush AddICECandidate err: %v", w.Name, err)
			continue
		}
		added++
	}
	if len(pending) > 0 {
		w.Log.Printf("%s ICE flushed %d/%d pending candidates", w.Name, added, len(pending))
	}
	return nil
}

// Close shuts the underlying PC. Safe to call once.
func (w *Wrapper) Close() error {
	if w.PC == nil {
		return nil
	}
	return w.PC.Close()
}
