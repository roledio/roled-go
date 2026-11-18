// Package web provides framework-agnostic helpers for the Roled OAuth 2.0
// PKCE login flow. Framework adapters (stdlib, fiber, ...) implement the
// Session interface on top of their native session mechanism and reuse Flow
// for all authentication logic.
package web

import (
	"encoding/json"

	"github.com/roledio/roled-go"
)

// authSessionKey is the session key under which the AuthSession JSON payload
// is stored.
const authSessionKey = "roled_auth_session"

// Session is a minimal string key-value session abstraction. Each framework
// adapter wraps its native session store (gorilla/sessions, Fiber session
// middleware, ...) and implements persistence in Save.
type Session interface {
	// Get returns the value stored under key.
	Get(key string) (string, bool)
	// Set stores value under key.
	Set(key string, value string)
	// Delete removes key from the session.
	Delete(key string)
	// Save persists pending changes. Adapters backed by automatically saved
	// session middleware may implement this as a no-op.
	Save() error
}

// LoadAuthSession reads the stored AuthSession from s. It returns an empty
// AuthSession when none exists.
func LoadAuthSession(s Session) (*roled.AuthSession, error) {
	raw, ok := s.Get(authSessionKey)
	if !ok || raw == "" {
		return &roled.AuthSession{}, nil
	}

	var authSess roled.AuthSession
	if err := json.Unmarshal([]byte(raw), &authSess); err != nil {
		return nil, err
	}
	return &authSess, nil
}

// SetAuthSession marshals authSess into the session. It does not persist
// anything; call s.Save() afterwards to write the session.
func SetAuthSession(s Session, authSess *roled.AuthSession) error {
	raw, err := json.Marshal(authSess)
	if err != nil {
		return err
	}
	s.Set(authSessionKey, string(raw))
	return nil
}

// ClearAuthSession removes the stored AuthSession from s.
func ClearAuthSession(s Session) {
	s.Delete(authSessionKey)
}
