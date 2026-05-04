package admin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// In-memory session store. Survives the server process lifetime;
// restarts log every operator out, which is the right default — there's
// no persistence requirement and avoiding disk-stored session tokens
// removes a class of attacks.

const (
	sessionCookieName = "goloom_session"
	sessionTTL        = 7 * 24 * time.Hour
)

type session struct {
	username string
	expires  time.Time
}

type sessionStore struct {
	mu    sync.RWMutex
	items map[string]session
}

func newSessionStore() *sessionStore {
	return &sessionStore{items: make(map[string]session)}
}

// New issues a fresh session token. Old sessions for the same username
// are NOT invalidated — a user who stays logged in on phone+laptop
// shouldn't be kicked off when they log into one of them again.
func (s *sessionStore) New(username string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b[:])

	s.mu.Lock()
	s.items[tok] = session{username: username, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	return tok, nil
}

// Lookup returns the session's username if the token is valid and not
// expired. Lazy GC: expired tokens are removed when first hit.
func (s *sessionStore) Lookup(token string) (string, error) {
	s.mu.RLock()
	sess, ok := s.items[token]
	s.mu.RUnlock()
	if !ok {
		return "", errors.New("unknown session")
	}
	if time.Now().After(sess.expires) {
		s.mu.Lock()
		delete(s.items, token)
		s.mu.Unlock()
		return "", errors.New("session expired")
	}
	return sess.username, nil
}

func (s *sessionStore) Revoke(token string) {
	s.mu.Lock()
	delete(s.items, token)
	s.mu.Unlock()
}
