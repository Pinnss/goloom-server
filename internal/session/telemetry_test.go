package session

import (
	"encoding/json"
	"testing"
	"time"
)

// TestBuildPublisherReport verifies the report is well-formed JSON with the
// live-encoder fields the SFU looks for, and that counters mirror the inputs.
func TestBuildPublisherReport(t *testing.T) {
	now := time.Unix(1784709618, 110089000)
	const frames, bytes, ssrc = uint64(2556), uint64(2965815), uint32(2138874305)
	// SetupSession adds audio before video, so pion gives audio mid "0" and
	// video mid "1". The report must follow the transceivers, not the reverse.
	id := PublisherIdent{VideoSSRC: ssrc, VideoMid: "1", AudioMid: "0"}
	report := buildPublisherReport(now, frames, bytes, 25.0, id)

	if len(report) == 0 {
		t.Fatal("empty report")
	}
	// Each outbound-rtp entry must sit on ITS OWN m-line. Pinning video stats
	// to the audio mid tells the SFU there is no encoder behind our video track.
	for _, entry := range report {
		var e struct{ Type, Kind, Mid string }
		if err := json.Unmarshal([]byte(entry), &e); err != nil || e.Type != "outbound-rtp" {
			continue
		}
		want := map[string]string{"video": id.VideoMid, "audio": id.AudioMid}[e.Kind]
		if e.Mid != want {
			t.Errorf("%s outbound-rtp on mid %q, want %q: %s", e.Kind, e.Mid, want, entry)
		}
	}

	var outVideo map[string]any
	for _, s := range report {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("entry is not valid JSON: %v\n%s", err, s)
		}
		if m["type"] == "outbound-rtp" && m["kind"] == "video" {
			outVideo = m
		}
	}
	if outVideo == nil {
		t.Fatal("no outbound-rtp/video entry")
	}

	// framesEncoded and bytesSent must reflect the real wire counters, not zero.
	if got := outVideo["framesEncoded"].(float64); got != float64(frames) {
		t.Errorf("framesEncoded = %v, want %d", got, frames)
	}
	if got := outVideo["bytesSent"].(float64); got != float64(bytes) {
		t.Errorf("bytesSent = %v, want %d", got, bytes)
	}
	if outVideo["ssrc"].(float64) != float64(ssrc) {
		t.Errorf("ssrc = %v, want %d", outVideo["ssrc"], ssrc)
	}
	if outVideo["qualityLimitationReason"] != "none" {
		t.Errorf("qualityLimitationReason = %v", outVideo["qualityLimitationReason"])
	}
	if kf := outVideo["keyFramesEncoded"].(float64); kf <= 0 {
		t.Errorf("keyFramesEncoded = %v, want > 0", kf)
	}
}

// TestProviderEnvelopeShape checks the full telemetry envelope carries all five
// report keys as arrays (never null), matching the browser-captured shape.
func TestProviderEnvelopeShape(t *testing.T) {
	tel := &struct {
		Pub  []string `json:"publisherRawStatsReport"`
		Sub  []string `json:"subscriberRawStatsReport"`
		Room []string `json:"roomAgentRawStatsReport"`
		Ev   []string `json:"eventsReport"`
		Cust []string `json:"customStats"`
	}{
		Pub:  buildPublisherReport(time.Now(), 100, 200000, 25, PublisherIdent{VideoSSRC: 42, VideoMid: "1", AudioMid: "0"}),
		Sub:  []string{},
		Room: []string{},
		Ev:   []string{},
		Cust: []string{},
	}
	b, err := json.Marshal(tel)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, k := range []string{"publisherRawStatsReport", "subscriberRawStatsReport", "roomAgentRawStatsReport", "eventsReport", "customStats"} {
		if !containsKey(b, k) {
			t.Errorf("envelope missing key %q: %s", k, b)
		}
	}
}

func containsKey(b []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
