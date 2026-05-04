package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Credentials describes who can sign into the admin panel. Stored on
// disk separately from the YAML config (bcrypt hash + flags), so panel-
// initiated password changes don't churn the YAML on every save.
type Credentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	// IsDefaultPassword stays true until the operator changes the
	// auto-generated bootstrap password. The dashboard renders a "change
	// me" banner while this is set.
	IsDefaultPassword bool `json:"is_default_password"`
}

// CredentialStore wraps Credentials with a path and a mutex so that the
// password-change endpoint can persist atomically.
type CredentialStore struct {
	mu    sync.RWMutex
	path  string
	creds Credentials
}

// LoadOrInit returns a store backed by `path`. If the file does not
// exist, a fresh `admin` user is created with a 16-byte hex-encoded
// random password and IsDefaultPassword=true. The plaintext default
// password is returned (only on first init) so the caller can print
// it once for the operator — it cannot be recovered later.
func LoadOrInit(path string) (store *CredentialStore, defaultPassword string, err error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, "", fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	if data, readErr := os.ReadFile(path); readErr == nil {
		var c Credentials
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, "", fmt.Errorf("parse %s: %w", path, err)
		}
		if c.Username == "" || c.PasswordHash == "" {
			return nil, "", fmt.Errorf("%s: missing username/password", path)
		}
		return &CredentialStore{path: path, creds: c}, "", nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, "", fmt.Errorf("read %s: %w", path, readErr)
	}

	// Bootstrap.
	pw, err := generatePassword()
	if err != nil {
		return nil, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("bcrypt: %w", err)
	}
	c := Credentials{
		Username:          "admin",
		PasswordHash:      string(hash),
		IsDefaultPassword: true,
	}
	if err := writeCreds(path, c); err != nil {
		return nil, "", err
	}
	return &CredentialStore{path: path, creds: c}, pw, nil
}

// Verify returns true if `password` matches the stored hash for `username`.
// Constant-time username comparison; bcrypt is naturally constant-time.
func (s *CredentialStore) Verify(username, password string) bool {
	s.mu.RLock()
	c := s.creds
	s.mu.RUnlock()
	if c.Username != username {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), []byte(password)) == nil
}

// ChangePassword swaps the stored hash. Caller is responsible for
// verifying the *current* password through Verify first.
func (s *CredentialStore) ChangePassword(newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds.PasswordHash = string(hash)
	s.creds.IsDefaultPassword = false
	return writeCreds(s.path, s.creds)
}

// State returns a non-secret snapshot for the UI (no password hash).
func (s *CredentialStore) State() Credentials {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Credentials{
		Username:          s.creds.Username,
		IsDefaultPassword: s.creds.IsDefaultPassword,
	}
}

func writeCreds(path string, c Credentials) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func generatePassword() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
