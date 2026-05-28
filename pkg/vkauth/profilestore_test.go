package vkauth

import (
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *ProfileStore {
	t.Helper()
	s, err := NewProfileStore(ProfileStoreOptions{Path: filepath.Join(t.TempDir(), "profiles.json")})
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	return s
}

func captureOne(t *testing.T, s *ProfileStore, fp string) string {
	t.Helper()
	s.Capture(CapturedProfile{UserAgent: "ua-" + fp, DeviceJSON: `{"fp":"` + fp + `"}`, BrowserFP: fp})
	for _, p := range s.Snapshot() {
		if p.BrowserFP == fp {
			return p.ID
		}
	}
	t.Fatalf("captured profile %s not found", fp)
	return ""
}

// A profile with a long success history that VK suddenly bans must be
// dropped after dropAfterFailures CONSECUTIVE fails — not held hostage
// by its historical Successes (the original bug: Failures>Successes
// guard kept a 9✓ profile alive forever, stranding the manual fallback).
func TestMarkFail_DropsAfterConsecutiveDespiteSuccessHistory(t *testing.T) {
	s := newTestStore(t)
	id := captureOne(t, s, "fp")
	for i := 0; i < 9; i++ {
		s.MarkSuccess(id)
	}
	s.MarkFail(id) // consec=1, default dropAfterFailures=2 → survives
	if got := len(s.Snapshot()); got != 1 {
		t.Fatalf("dropped too early after 1 fail: pool size %d", got)
	}
	s.MarkFail(id) // consec=2 → dropped
	if got := len(s.Snapshot()); got != 0 {
		t.Fatalf("expected drop after 2 consecutive fails, pool size %d", got)
	}
}

// A success between fails resets the streak — an intermittent failure
// must not evict an otherwise healthy profile.
func TestMarkSuccess_ResetsConsecutiveFails(t *testing.T) {
	s := newTestStore(t)
	id := captureOne(t, s, "fp")
	s.MarkFail(id)    // consec=1
	s.MarkSuccess(id) // reset → 0
	s.MarkFail(id)    // consec=1, not dropped
	if got := len(s.Snapshot()); got != 1 {
		t.Fatalf("intermittent fail should not drop profile, pool size %d", got)
	}
}

// Pick must prefer a freshly captured profile (0 consecutive fails)
// over a once-good-now-failing one, even when the latter has a far
// better success ratio. Both are forced into the same cooldown bucket
// so the ordering — not the cooldown — decides.
func TestPick_PrefersFewerConsecutiveFails(t *testing.T) {
	s := newTestStore(t)
	staleID := captureOne(t, s, "stale")
	for i := 0; i < 9; i++ {
		s.MarkSuccess(staleID)
	}
	s.MarkFail(staleID) // consec=1, LastUsedAt=now

	freshID := captureOne(t, s, "fresh")
	s.MarkSuccess(freshID) // consec=0, LastUsedAt=now → same (in-cooldown) bucket as stale

	picked := s.Pick()
	if picked == nil {
		t.Fatal("Pick returned nil")
	}
	if picked.BrowserFP != "fresh" {
		t.Fatalf("expected fresh profile preferred, got fp=%s consecFails=%d", picked.BrowserFP, picked.ConsecutiveFails)
	}
	_ = freshID
}
