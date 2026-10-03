package wgclient

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func ident(user string, eps ...string) TURNIdentity {
	return TURNIdentity{Creds: TURNCreds{Username: user}, Endpoints: eps}
}

// VK's quota is per credential, so the planner must exhaust one identity before
// spending the next. Interleaving them would spread every identity thin and hit
// 486 on all of them at once instead of filling the ones we have.
func TestPlanSlotsFillsOneIdentityBeforeTheNext(t *testing.T) {
	ids := []TURNIdentity{ident("a", "r1:1", "r2:1"), ident("b", "r1:1", "r2:1")}
	per := 2 * TURNAllocationsPerRelay

	plan := planSlots(ids, per+3)
	if len(plan) != per+3 {
		t.Fatalf("plan has %d slots, want %d", len(plan), per+3)
	}
	for i := 0; i < per; i++ {
		if plan[i].identity != 0 {
			t.Fatalf("slot %d went to identity %d before identity 0 was full", i, plan[i].identity)
		}
	}
	for i := per; i < len(plan); i++ {
		if plan[i].identity != 1 {
			t.Fatalf("slot %d went to identity %d, want 1", i, plan[i].identity)
		}
	}
}

// Relays are alternated inside an identity: VK's quota is per relay, so putting
// every allocation on one of them would waste half the capacity.
func TestPlanSlotsAlternatesRelaysWithinAnIdentity(t *testing.T) {
	plan := planSlots([]TURNIdentity{ident("a", "r1:1", "r2:1")}, 4)
	seen := map[string]int{}
	for _, sp := range plan {
		seen[sp.endpoint]++
	}
	if len(seen) != 2 {
		t.Fatalf("used %d relays, want 2 (%v)", len(seen), seen)
	}
	for ep, n := range seen {
		if n != 2 {
			t.Errorf("relay %s got %d slots, want an even split", ep, n)
		}
	}
}

// Asking for more than the identities can carry must yield a SHORTER plan, not
// slots that are doomed to 486. The pool reports the shortfall to the caller.
func TestPlanSlotsCapsAtCapacity(t *testing.T) {
	ids := []TURNIdentity{ident("a", "r1:1")}
	plan := planSlots(ids, 999)
	if len(plan) != TURNAllocationsPerRelay {
		t.Fatalf("plan has %d slots, want the one relay's quota of %d",
			len(plan), TURNAllocationsPerRelay)
	}
}

// An identity VK gave no usable relays for must be skipped, not silently used
// with an empty endpoint.
func TestPlanSlotsSkipsIdentitiesWithoutRelays(t *testing.T) {
	ids := []TURNIdentity{ident("empty"), ident("b", "r1:1")}
	plan := planSlots(ids, 5)
	if len(plan) != 5 {
		t.Fatalf("plan has %d slots, want 5", len(plan))
	}
	for i, sp := range plan {
		if sp.identity != 1 {
			t.Fatalf("slot %d used identity %d, want the one with relays", i, sp.identity)
		}
		if sp.endpoint == "" {
			t.Fatalf("slot %d has an empty endpoint", i)
		}
	}
}

// The plan is what keeps a redial on the identity its slot already belongs to;
// if it were recomputed per dial, a rebuild could land on a credential that is
// already at quota and the slot would never come back.
func TestPlanSlotsIsDeterministic(t *testing.T) {
	ids := []TURNIdentity{ident("a", "r1:1", "r2:1"), ident("b", "r3:1")}
	first := planSlots(ids, 25)
	for attempt := 0; attempt < 5; attempt++ {
		again := planSlots(ids, 25)
		if len(again) != len(first) {
			t.Fatalf("plan length changed between calls: %d vs %d", len(again), len(first))
		}
		for i := range first {
			if again[i] != first[i] {
				t.Fatalf("slot %d moved: %+v vs %+v", i, again[i], first[i])
			}
		}
	}
}

func TestIdentitiesNeeded(t *testing.T) {
	cases := []struct{ want, relays, expect int }{
		{10, 2, 1}, // inside one identity's quota
		{20, 2, 1}, // exactly one identity's quota
		{21, 2, 2}, // one over
		{60, 2, 3}, // the case we are building for
		{60, 1, 6}, // fewer relays, more identities
		{0, 2, 1},  // nonsense input still asks for one
		{10, 0, 1}, // no relays reported: do not divide by zero
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("want%d_relays%d", tc.want, tc.relays), func(t *testing.T) {
			if got := IdentitiesNeeded(tc.want, tc.relays); got != tc.expect {
				t.Errorf("IdentitiesNeeded(%d,%d) = %d, want %d", tc.want, tc.relays, got, tc.expect)
			}
		})
	}
}

// VK issues TURN REST credentials: username is "<unix expiry>:<vk user id>".
// Both halves are load-bearing — the quota is keyed on the user, so two
// identities decoding to the same user share one quota and the second is worth
// nothing; and the expiry is what makes reuse across reconnects safe.
func TestTURNUserID(t *testing.T) {
	user, exp, ok := TURNUserID("1778214637:583728693388")
	if !ok {
		t.Fatal("a well-formed VK credential did not decode")
	}
	if user != "583728693388" {
		t.Errorf("user = %q, want 583728693388", user)
	}
	if got := exp.Unix(); got != 1778214637 {
		t.Errorf("expiry = %d, want 1778214637", got)
	}
	// Observed in a capture: same user, different expiry — these MUST compare
	// equal as identities or the pool thinks it gained quota it did not.
	other, _, ok := TURNUserID("1778215242:583728693388")
	if !ok || other != user {
		t.Errorf("same VK user with a later expiry decoded as %q, want %q", other, user)
	}
}

func TestTURNUserIDRejectsOtherShapes(t *testing.T) {
	for _, bad := range []string{
		"", ":", "nocolon", "583728693388", ":583728693388", "1778214637:",
		"notanumber:583728693388", "-5:583728693388", "0:583728693388",
	} {
		t.Run(bad, func(t *testing.T) {
			if _, _, ok := TURNUserID(bad); ok {
				t.Errorf("TURNUserID(%q) reported ok; the caller would trust a bogus expiry", bad)
			}
		})
	}
}

// VK credentials last about eight hours and pion refreshes each allocation with
// the SAME one, so when it expires the allocations die and nothing the client
// does revives them. The pool must say so without a round trip, and with an
// error distinct from a quota refusal: waiting fixes a quota, only a fresh
// authentication fixes an expiry.
func TestPoolRefusesExpiredCredentialWithoutAskingVK(t *testing.T) {
	expired := fmt.Sprintf("%d:583728693388", time.Now().Add(-time.Minute).Unix())
	p := &SRTPPool{
		identities: []TURNIdentity{{Creds: TURNCreds{Username: expired}, Endpoints: []string{"r1:1"}}},
		plan:       []slotPlan{{identity: 0, endpoint: "r1:1"}},
		allocs:     make([]*TURNAllocation, 1),
	}
	_, err := p.dial(context.Background(), 0)
	if err == nil {
		t.Fatal("dial accepted an expired credential")
	}
	if !errors.Is(err, ErrTURNCredentialExpired) {
		t.Errorf("error is %v, want ErrTURNCredentialExpired", err)
	}
	if errors.Is(err, ErrTURNQuota) {
		t.Error("an expiry must not be reported as a quota refusal — they need different handling")
	}
}

// A credential that is still inside its window must NOT be refused here; the
// guard is about dead credentials, not a reason to stop dialling.
func TestPoolDoesNotRefuseLiveCredential(t *testing.T) {
	live := fmt.Sprintf("%d:583728693388", time.Now().Add(time.Hour).Unix())
	p := &SRTPPool{
		identities: []TURNIdentity{{Creds: TURNCreds{Username: live}, Endpoints: []string{"127.0.0.1:1"}}},
		plan:       []slotPlan{{identity: 0, endpoint: "127.0.0.1:1"}},
		allocs:     make([]*TURNAllocation, 1),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	// It will fail to reach a TURN server, which is fine — it must not fail
	// with the expiry error.
	_, err := p.dial(ctx, 0)
	if errors.Is(err, ErrTURNCredentialExpired) {
		t.Errorf("a credential valid for another hour was refused as expired: %v", err)
	}
}
