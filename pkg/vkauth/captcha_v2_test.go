package vkauth

import "testing"

func TestPickBrowserFP(t *testing.T) {
	const fresh = "FRESHRANDOMFP"
	healthy := &CapturedProfile{BrowserFP: "SAVEDFP", ConsecutiveFails: 0}
	failing := &CapturedProfile{BrowserFP: "SAVEDFP", ConsecutiveFails: 1}

	cases := []struct {
		name        string
		saved       *CapturedProfile
		attempt     int
		wantFP      string
		wantRotated bool
	}{
		{"healthy attempt1 keeps saved fp", healthy, 1, "SAVEDFP", false},
		{"healthy retry rotates to fresh", healthy, 2, fresh, true},
		{"failing profile rotates from attempt1", failing, 1, fresh, true},
		{"no saved profile uses fresh", nil, 1, fresh, false},
		{"saved with blank fp uses fresh", &CapturedProfile{BrowserFP: "  "}, 1, fresh, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp, rotated := pickBrowserFP(c.saved, c.attempt, fresh)
			if fp != c.wantFP || rotated != c.wantRotated {
				t.Fatalf("pickBrowserFP = (%q, %v), want (%q, %v)", fp, rotated, c.wantFP, c.wantRotated)
			}
		})
	}
}
