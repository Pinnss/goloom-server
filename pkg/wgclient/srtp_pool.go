package wgclient

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/internal/relay/vkturnsrtp"
)

// srtpHandshakeTimeout bounds one TURN allocate plus its DTLS-SRTP handshake.
const srtpHandshakeTimeout = 15 * time.Second

// ErrTURNQuota reports that VK refused an allocation because the credential is
// already at its limit — STUN error 486, "Allocation Quota Reached". Measured
// against VK in October 2026 the ceiling is 20 concurrent allocations per
// credential: asking for 50 yields 20 up and 30 refused.
//
// It is worth a distinct error because retrying is pointless: the quota cannot
// free up while our own allocations hold it, so every retry is a request VK
// answers 486 — and VK throttles a credential that asks too often, which would
// cost us the allocations we DO have.
var ErrTURNQuota = errors.New("TURN allocation quota reached")

// ErrTURNCredentialExpired reports that the identity behind a slot is past the
// expiry baked into its own username. VK issues credentials good for about
// eight hours (measured: 7.7-8.0 h across four captures), and pion refreshes
// each allocation with the SAME credential — so when one expires its
// allocations die and nothing the client does will bring them back.
//
// It is worth its own error because the retry is futile in a different way from
// a quota refusal: no amount of waiting helps, only a fresh VK authentication.
// Without it the watchdog rebuilds the slot every redialBackoff forever,
// hammering VK with requests that cannot succeed.
var ErrTURNCredentialExpired = errors.New("TURN credential expired")

// quotaErr wraps err with ErrTURNQuota when the response says the quota is
// reached. pion surfaces this only in the message text, so matching on it is
// the only option; both the numeric code and the reason phrase are checked so a
// reworded reason or a renumbered code still leaves one working signal.
func quotaErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "486") || strings.Contains(msg, "Allocation Quota Reached") {
		return fmt.Errorf("%w: %v", ErrTURNQuota, err)
	}
	return err
}

// SRTPPool owns the TURN allocations behind an [SRTPBind]'s slots and can
// rebuild any one of them on demand.
//
// It exists because a dead allocation used to stay dead: the bind's watchdog
// killed the conn, dropped it from the round-robin, and nothing ever replaced
// it. Allocations die for ordinary reasons — the phone sleeps, a NAT mapping
// expires, VK resets a relay, the server is redeployed — so over hours the pool
// shrank towards zero while the UI still reported a healthy tunnel. Wiring
// Pool.Redial into SRTPBind.Redial lets the watchdog heal instead of only
// diagnose.
type SRTPPool struct {
	// groupID ties every conn in this pool together for the server, which then
	// feeds them all from ONE socket to WireGuard and spreads the downlink
	// across them. Without it the kernel roams the peer endpoint to whichever
	// allocation spoke last, so the whole downlink rides a single one at VK's
	// ~247 KiB/s per-allocation budget. See internal/relay/vkturnsrtp/group.go.
	groupID [16]byte

	identities []TURNIdentity
	plan       []slotPlan // one per slot, fixed at construction
	peerAddr   string
	logger     *log.Logger

	mu     sync.Mutex
	allocs []*TURNAllocation // one per slot; nil once closed
	closed bool
}

// TURNIdentity is one VK anonymous identity: the TURN credential it was issued
// and the relays that credential may allocate on.
//
// The pool takes several because VK's quota is per credential, not per client —
// see [TURNAllocationsPerRelay]. Each identity costs the user one pass through
// the captcha, so they are scarce and the pool must make the most of each.
type TURNIdentity struct {
	Creds     TURNCreds
	Endpoints []string
}

// TURNAllocationsPerRelay is how many concurrent allocations VK grants one
// credential on one relay. Measured against the live service on 2026-10-03:
// with the two relays VK hands out, one identity tops out at 20 allocations and
// every request past that is answered 486. Throughput is linear up to the wall
// at ~1.85 Mbit/s per allocation, so the only way past 37 Mbit/s is more
// identities.
const TURNAllocationsPerRelay = 10

// IdentitiesNeeded is how many VK identities it takes to carry want
// allocations, given how many relays each identity may allocate on. It lives
// beside [TURNAllocationsPerRelay] so the quota is reasoned about in one place.
func IdentitiesNeeded(want, relays int) int {
	per := relays * TURNAllocationsPerRelay
	if per <= 0 || want <= 0 {
		return 1
	}
	if n := (want + per - 1) / per; n > 1 {
		return n
	}
	return 1
}

// TURNUserID returns the VK user a credential belongs to, and when the
// credential expires.
//
// VK issues standard TURN REST long-term credentials: the username is
// "<unix expiry>:<vk user id>" and the password is an HMAC over it. Both halves
// matter to us. The quota that caps the tunnel is keyed on the user, so two
// identities that decode to the SAME user share one quota and the second buys
// nothing. And the expiry is hours out, not minutes, so a credential can be
// reused across reconnects for far longer than any TTL we would guess.
//
// ok is false when the username is not in that form, in which case the caller
// must fall back to its own conservative policy rather than trusting a zero.
func TURNUserID(username string) (user string, expires time.Time, ok bool) {
	head, tail, found := strings.Cut(username, ":")
	if !found || head == "" || tail == "" {
		return "", time.Time{}, false
	}
	secs, err := strconv.ParseInt(head, 10, 64)
	if err != nil || secs <= 0 {
		return "", time.Time{}, false
	}
	return tail, time.Unix(secs, 0), true
}

// EarliestExpiry is when the first of these identities goes dead, i.e. when the
// tunnel starts losing allocations it cannot rebuild. Identities minted minutes
// apart expire minutes apart, so the pool narrows in steps rather than stopping
// at once — the first one going is the moment worth warning about.
//
// The zero time means no identity carried a readable expiry.
func EarliestExpiry(identities []TURNIdentity) time.Time {
	var first time.Time
	for _, id := range identities {
		_, exp, ok := TURNUserID(id.Creds.Username)
		if !ok {
			continue
		}
		if first.IsZero() || exp.Before(first) {
			first = exp
		}
	}
	return first
}

// slotPlan fixes which identity and relay a slot belongs to. It is decided once,
// at construction, because [SRTPPool.Redial] must rebuild slot i on the SAME
// identity: moving it would land on a credential that is already at its quota
// and the slot would never come back.
type slotPlan struct {
	identity int
	endpoint string
}

// planSlots lays n slots out over the identities, filling each identity to its
// quota before moving on and round-robining relays inside it. Returns the plan,
// which is shorter than n when the identities cannot carry that many.
func planSlots(identities []TURNIdentity, n int) []slotPlan {
	plan := make([]slotPlan, 0, n)
	for id := range identities {
		eps := identities[id].Endpoints
		if len(eps) == 0 {
			continue
		}
		for k := 0; k < len(eps)*TURNAllocationsPerRelay && len(plan) < n; k++ {
			plan = append(plan, slotPlan{identity: id, endpoint: eps[k%len(eps)]})
		}
		if len(plan) >= n {
			break
		}
	}
	return plan
}

// NewSRTPPool allocates n slots, round-robining over endpoints. It returns the
// pool and a slice of EXACTLY n conns, nil where a slot failed, so slot indices
// line up with the bind's — a redial for index i must rebuild the same
// allocation the bind thinks lives at i, and a compacted slice would silently
// shift them and tear down a healthy one. It errors only when NOT A SINGLE slot
// came up; partial success is normal and the bind's watchdog fills the nil gaps.
func NewSRTPPool(ctx context.Context, identities []TURNIdentity, peerAddr string, n int, lg *log.Logger) (*SRTPPool, []net.Conn, error) {
	if len(identities) == 0 {
		return nil, nil, fmt.Errorf("srtp pool: no TURN identities")
	}
	if n <= 0 {
		return nil, nil, fmt.Errorf("srtp pool: n must be positive, got %d", n)
	}
	plan := planSlots(identities, n)
	if len(plan) == 0 {
		return nil, nil, fmt.Errorf("srtp pool: no TURN endpoints across %d identities", len(identities))
	}
	p := &SRTPPool{
		identities: identities,
		plan:       plan,
		peerAddr:   peerAddr,
		logger:     lg,
		allocs:     make([]*TURNAllocation, len(plan)),
	}
	if _, err := rand.Read(p.groupID[:]); err != nil {
		return nil, nil, fmt.Errorf("srtp pool: group id: %w", err)
	}
	if len(plan) < n {
		p.logf("srtp pool: %d identities carry %d of the %d allocations asked for "+
			"(VK allows %d per relay per credential)", len(identities), len(plan), n, TURNAllocationsPerRelay)
	}

	conns := make([]net.Conn, len(plan))
	up := 0
	// quotaHit marks an identity VK has refused: the rest of ITS slots would get
	// the same 486, so they are skipped. Skipping the whole fill instead — which
	// is what a single-identity pool did — would strand every later identity's
	// slots behind the first one's exhausted quota.
	quotaHit := make([]bool, len(identities))
	for i := range plan {
		if quotaHit[plan[i].identity] {
			continue
		}
		c, err := p.dial(ctx, i)
		if err != nil {
			p.logf("srtp pool: slot %d/%d (identity %d): %v", i+1, len(plan), plan[i].identity, err)
			if errors.Is(err, ErrTURNQuota) {
				quotaHit[plan[i].identity] = true
				p.logf("srtp pool: identity %d is at its VK quota — skipping its remaining slots",
					plan[i].identity)
			}
			continue
		}
		conns[i] = c
		up++
	}
	if up == 0 {
		p.Close()
		return nil, nil, fmt.Errorf("srtp pool: every TURN allocate / DTLS handshake failed")
	}
	p.logf("srtp pool: %d/%d allocations up across %d identities (group %x)",
		up, len(plan), len(identities), p.groupID[:4])
	return p, conns, nil
}

// GroupHello is the hello every conn in this pool announces, for
// [SRTPBind.GroupHello] to repeat.
func (p *SRTPPool) GroupHello() []byte { return vkturnsrtp.GroupHello(p.groupID) }

// Redial rebuilds one slot. Suitable as [SRTPBind.Redial]. The context lets a
// teardown abort a dial in progress — a TURN allocate plus DTLS handshake can
// take the better part of 20 s, and Close used to wait it out.
func (p *SRTPPool) Redial(ctx context.Context, idx int) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, srtpHandshakeTimeout)
	defer cancel()
	return p.dial(dialCtx, idx)
}

// dial establishes slot idx, replacing whatever allocation it held.
func (p *SRTPPool) dial(ctx context.Context, idx int) (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	if idx < 0 || idx >= len(p.allocs) {
		p.mu.Unlock()
		return nil, fmt.Errorf("srtp pool: slot %d out of range", idx)
	}
	// The plan is fixed at construction, so a redial rebuilds this slot on the
	// identity it already belonged to. Picking a different one would spend a
	// credential that is already at its quota.
	sp := p.plan[idx]
	endpoint := sp.endpoint
	creds := p.identities[sp.identity].Creds
	peerAddr := p.peerAddr
	p.mu.Unlock()

	// Refuse before asking VK: the credential carries its own expiry, so a dead
	// one is knowable without a round trip.
	if _, exp, ok := TURNUserID(creds.Username); ok && !time.Now().Before(exp) {
		return nil, fmt.Errorf("%w: identity %d expired at %s",
			ErrTURNCredentialExpired, sp.identity, exp.UTC().Format(time.RFC3339))
	}

	alloc, err := AllocateTURN(ctx, endpoint, peerAddr, creds)
	if err != nil {
		return nil, quotaErr(fmt.Errorf("TURN allocate via %s: %w", endpoint, err))
	}
	hsCtx, hsCancel := context.WithTimeout(ctx, srtpHandshakeTimeout)
	conn, err := vkturnsrtp.Client(hsCtx, alloc.Relay(), alloc.PeerAddr())
	hsCancel()
	if err != nil {
		alloc.Close()
		return nil, fmt.Errorf("DTLS-SRTP handshake via %s: %w", endpoint, err)
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		alloc.Close()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	old := p.allocs[idx]
	p.allocs[idx] = alloc
	p.mu.Unlock()
	if old != nil {
		old.Close()
	}

	// Announce the group before any WireGuard traffic, and again on every
	// replacement conn, so a rebuilt slot rejoins the same shared socket instead
	// of splitting the peer endpoint off on its own.
	if err := conn.SetWriteDeadline(time.Now().Add(srtpHandshakeTimeout)); err == nil {
		if _, err := conn.Write(vkturnsrtp.GroupHello(p.groupID)); err != nil {
			p.logf("srtp pool: slot %d group hello: %v", idx, err)
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
	p.logf("srtp pool: slot %d up via %s (identity %d, group %x)", idx, endpoint, sp.identity, p.groupID[:4])
	return conn, nil
}

// Close releases every allocation. The conns themselves belong to the
// SRTPBind, which closes them on its own Close.
func (p *SRTPPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	allocs := p.allocs
	p.allocs = nil
	p.mu.Unlock()
	for _, a := range allocs {
		if a != nil {
			a.Close()
		}
	}
}

func (p *SRTPPool) logf(format string, args ...any) {
	if p.logger != nil {
		p.logger.Printf(format, args...)
	}
}
