// Persistent profile storage for the GUI.
//
// A profile is a saved [wgclient.Config] plus a human-friendly name
// and lifecycle metadata (created / last used). Profiles live in a
// single JSON file under the per-user config dir
// (%APPDATA%\goloom\profiles.json on Windows). Writes are atomic
// via temp-file + rename so a crash mid-save can't corrupt the
// store; concurrent reads are protected by a sync.RWMutex inside
// [profileStore].
//
// We keep this layer in the GUI binary rather than pkg/wgclient —
// the CLI doesn't need it, and storing config-tree paths inside a
// reusable library is awkward.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/pkg/wgclient"
)

// Profile is one saved tunnel configuration. The name is what the
// dropdown shows; ID is a short random hex token used as the stable
// reference from the JS frontend.
type Profile struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Config     wgclient.Config `json:"config"`
	CreatedAt  time.Time       `json:"created_at"`
	LastUsedAt time.Time       `json:"last_used_at,omitempty"`
}

// profileFile is the on-disk format. Versioned so future schema
// changes can be migrated cleanly.
type profileFile struct {
	Version         int       `json:"version"`
	ActiveProfileID string    `json:"active_profile_id,omitempty"`
	Profiles        []Profile `json:"profiles"`
}

const profileFileVersion = 1

// profileStore manages the on-disk profile JSON. Construct exactly
// one per process and share via the App struct.
type profileStore struct {
	path string

	mu       sync.RWMutex
	profiles []Profile
	active   string // id of last-connected profile
}

// newProfileStore opens (or creates) the profile file. Returns a
// store that's safe for concurrent use.
func newProfileStore() (*profileStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("user config dir: %w", err)
	}
	gdir := filepath.Join(dir, "goloom")
	if err := os.MkdirAll(gdir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", gdir, err)
	}
	st := &profileStore{path: filepath.Join(gdir, "profiles.json")}
	if err := st.load(); err != nil {
		return nil, err
	}
	return st, nil
}

// Path returns the on-disk file path. Useful for the UI's "Where
// are profiles stored?" affordance.
func (s *profileStore) Path() string { return s.path }

func (s *profileStore) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // empty store; first save creates the file
	}
	if err != nil {
		return fmt.Errorf("read profiles: %w", err)
	}
	var pf profileFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse profiles: %w", err)
	}
	s.mu.Lock()
	s.profiles = pf.Profiles
	s.active = pf.ActiveProfileID
	s.mu.Unlock()
	return nil
}

// save flushes the store to disk atomically. The caller does NOT
// hold s.mu — we acquire RLock for the snapshot and release before
// fsync to keep the critical section tight.
func (s *profileStore) save() error {
	s.mu.RLock()
	pf := profileFile{
		Version:         profileFileVersion,
		ActiveProfileID: s.active,
		Profiles:        append([]Profile(nil), s.profiles...),
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profiles: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write profiles tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		// On Windows, Rename refuses to overwrite. Remove + Rename.
		_ = os.Remove(s.path)
		if err := os.Rename(tmp, s.path); err != nil {
			return fmt.Errorf("rename profiles: %w", err)
		}
	}
	return nil
}

// List returns a deterministically-ordered snapshot. Order: most
// recently used first, then by created-at descending for never-used.
func (s *profileStore) List() []Profile {
	s.mu.RLock()
	out := append([]Profile(nil), s.profiles...)
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		// Used profiles ahead of unused.
		ui, uj := !out[i].LastUsedAt.IsZero(), !out[j].LastUsedAt.IsZero()
		if ui != uj {
			return ui
		}
		if ui && uj {
			return out[i].LastUsedAt.After(out[j].LastUsedAt)
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// ActiveID returns the ID of the last-connected profile, or "" if
// none yet.
func (s *profileStore) ActiveID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// Get returns the profile with the given ID, or false.
func (s *profileStore) Get(id string) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

// Add creates and persists a new profile, returning it with its
// assigned ID and CreatedAt populated. Validates the embedded config
// before saving.
func (s *profileStore) Add(name string, cfg wgclient.Config) (Profile, error) {
	if err := cfg.Validate(); err != nil {
		return Profile{}, err
	}
	if name == "" {
		name = inferName(cfg)
	}
	p := Profile{
		ID:        randomID(),
		Name:      name,
		Config:    cfg,
		CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.profiles = append(s.profiles, p)
	s.mu.Unlock()
	if err := s.save(); err != nil {
		// Roll back the in-memory append so a failed disk write
		// doesn't leave the store inconsistent with disk.
		s.mu.Lock()
		s.profiles = s.profiles[:len(s.profiles)-1]
		s.mu.Unlock()
		return Profile{}, err
	}
	return p, nil
}

// Update modifies the profile in-place; only Name and Config are
// updateable from the UI. Returns the updated profile.
func (s *profileStore) Update(id, name string, cfg wgclient.Config) (Profile, error) {
	if err := cfg.Validate(); err != nil {
		return Profile{}, err
	}
	s.mu.Lock()
	idx := -1
	for i, p := range s.profiles {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return Profile{}, fmt.Errorf("profile %q not found", id)
	}
	prev := s.profiles[idx]
	if name != "" {
		s.profiles[idx].Name = name
	}
	s.profiles[idx].Config = cfg
	updated := s.profiles[idx]
	s.mu.Unlock()

	if err := s.save(); err != nil {
		// Roll back.
		s.mu.Lock()
		s.profiles[idx] = prev
		s.mu.Unlock()
		return Profile{}, err
	}
	return updated, nil
}

// Delete removes a profile. If it was the active one, ActiveID is
// cleared.
func (s *profileStore) Delete(id string) error {
	s.mu.Lock()
	idx := -1
	for i, p := range s.profiles {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return fmt.Errorf("profile %q not found", id)
	}
	removed := s.profiles[idx]
	s.profiles = append(s.profiles[:idx], s.profiles[idx+1:]...)
	if s.active == id {
		s.active = ""
	}
	prev := s.profiles
	s.mu.Unlock()

	if err := s.save(); err != nil {
		// Roll back.
		s.mu.Lock()
		s.profiles = append(prev[:idx], append([]Profile{removed}, prev[idx:]...)...)
		s.mu.Unlock()
		return err
	}
	return nil
}

// MarkUsed records that a profile was just connected. Updates
// LastUsedAt and the persistent ActiveProfileID. Best-effort; a
// disk error here just logs — we don't want a flaky disk to abort
// a successful connection.
func (s *profileStore) MarkUsed(id string, lg interface {
	Printf(format string, args ...any)
}) {
	s.mu.Lock()
	for i, p := range s.profiles {
		if p.ID == id {
			s.profiles[i].LastUsedAt = time.Now()
			break
		}
	}
	s.active = id
	s.mu.Unlock()
	if err := s.save(); err != nil {
		if lg != nil {
			lg.Printf("WARN profiles: persist last-used: %v", err)
		}
	}
}

// inferName builds a reasonable default profile name from a config.
func inferName(cfg wgclient.Config) string {
	switch cfg.Transport {
	case "", "telemost":
		if cfg.Meeting != "" {
			return "Telemost — " + shortenURL(cfg.Meeting)
		}
		return "Telemost"
	case "livekit-wb-stream":
		if cfg.LiveKitRoomURL != "" {
			return "WB Stream — " + shortenURL(cfg.LiveKitRoomURL)
		}
		return "WB Stream"
	default:
		return cfg.Transport
	}
}

// shortenURL returns the path's last segment of a meeting URL (the
// room id) when it's short enough, else the host.
func shortenURL(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	last := s
	if i := strings.LastIndex(s, "/"); i >= 0 && i < len(s)-1 {
		last = s[i+1:]
	}
	if len(last) > 0 && len(last) <= 24 {
		return last
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 32 {
		s = s[:32] + "…"
	}
	return s
}

// randomID generates a 16-hex-char random ID. crypto/rand-backed —
// collisions are astronomically unlikely.
func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
