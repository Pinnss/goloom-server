package mobile

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Error codes classifying Connect failures. Plain int constants so
// gomobile exposes them to Java/Swift as static fields the native code
// can compare against. Values are stable across releases; new codes are
// appended at the end.
const (
	ErrUnknown           = 0
	ErrInvalidConnString = 1 // connection string couldn't be decoded
	ErrSessionSetup      = 2 // Telemost WebRTC setup failed (network/DNS/blocked)
	ErrPeerWaitTimeout   = 3 // joined the meeting but no peer showed up
	ErrHandshake         = 4 // in-tunnel HELLO/ACK timed out
	ErrAlreadyConnected  = 5 // Connect called while a session is live
	ErrCancelled         = 6 // context cancelled (Disconnect/app shutdown)
)

// errorCodeName is the canonical lowercase identifier used in error
// messages — handy for log filtering on the native side.
func errorCodeName(c int) string {
	switch c {
	case ErrInvalidConnString:
		return "invalid_conn_string"
	case ErrSessionSetup:
		return "session_setup_failed"
	case ErrPeerWaitTimeout:
		return "peer_wait_timeout"
	case ErrHandshake:
		return "handshake_failed"
	case ErrAlreadyConnected:
		return "already_connected"
	case ErrCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

// MobileError carries a typed error code alongside a human message.
// Through gomobile bindings the native side sees this as java.lang.Exception
// (Android) / NSError (iOS); the Code is also retrievable post-hoc via
// Client.LastErrorCode() so UIs can render translated strings without
// parsing English text.
type MobileError struct {
	Code    int
	Message string
	wrapped error
}

func (e *MobileError) Error() string {
	if e.Message != "" {
		return errorCodeName(e.Code) + ": " + e.Message
	}
	return errorCodeName(e.Code)
}

func (e *MobileError) Unwrap() error { return e.wrapped }

// codeOf walks the error chain looking for a MobileError to extract
// the code. Returns ErrUnknown on plain errors so callers always get a
// non-negative classification.
func codeOf(err error) int {
	if err == nil {
		return ErrUnknown
	}
	var me *MobileError
	if errors.As(err, &me) {
		return me.Code
	}
	return ErrUnknown
}

func mobileErr(code int, wrapped error) *MobileError {
	msg := ""
	if wrapped != nil {
		msg = wrapped.Error()
	}
	return &MobileError{Code: code, Message: msg, wrapped: wrapped}
}

// classify takes the raw error from runSession and turns it into a
// MobileError with the right code, by looking at substrings of the
// message. Keeps the runSession code clean — it just returns
// fmt.Errorf-wrapped errors with stable prefixes.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return mobileErr(ErrCancelled, err)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "session setup"):
		return mobileErr(ErrSessionSetup, err)
	case strings.Contains(msg, "wait for peer"):
		return mobileErr(ErrPeerWaitTimeout, err)
	case strings.Contains(msg, "handshake"):
		return mobileErr(ErrHandshake, err)
	}
	return mobileErr(ErrUnknown, err)
}

// LastErrorCode returns the code of the most recent error from this
// client, or ErrUnknown if the last operation succeeded. Lets the native
// UI render a typed message even after the original error string was
// passed to LogSink and lost.
func (c *Client) LastErrorCode() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr == nil {
		return ErrUnknown
	}
	return codeOf(c.lastErr)
}

// LastErrorMessage returns the human-readable message of the most
// recent error, or "" if none.
func (c *Client) LastErrorMessage() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr == nil {
		return ""
	}
	return c.lastErr.Error()
}

// recordErr stashes the latest error for LastErrorCode/Message lookups.
func (c *Client) recordErr(err error) {
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
}

// for fmt to be referenced in build (avoid import lint when message
// formatting moves around). Cheap.
var _ = fmt.Sprintf
