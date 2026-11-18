package roledhttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/roledio/roled-go/web"
)

// Store loads the session for an HTTP request. Implementations may be swapped
// for server-side stores (Redis, database, ...) via WithSessionStore.
type Store interface {
	// Open returns the session for the request. Changes are persisted when
	// Session.Save is called. w may be nil for read-only access; calling Save
	// on such a session returns an error.
	Open(r *http.Request, w http.ResponseWriter) (web.Session, error)
}

// CookieStore is the default Store: it keeps the session in an encrypted and
// integrity-protected cookie, so no server-side storage is required.
type CookieStore struct {
	secret   []byte
	name     string
	maxAge   int
	path     string
	secure   bool
	httpOnly bool
	sameSite http.SameSite
}

// CookieOption configures a CookieStore.
type CookieOption func(*CookieStore)

// WithCookieName sets the session cookie name. Defaults to "roled_session".
func WithCookieName(name string) CookieOption {
	return func(s *CookieStore) {
		if name != "" {
			s.name = name
		}
	}
}

// WithCookieMaxAge sets the session lifetime. Defaults to 8 hours; values <= 0
// produce a browser-session cookie.
func WithCookieMaxAge(d time.Duration) CookieOption {
	return func(s *CookieStore) {
		s.maxAge = int(d.Seconds())
	}
}

// WithCookiePath sets the cookie path. Defaults to "/".
func WithCookiePath(path string) CookieOption {
	return func(s *CookieStore) {
		if path != "" {
			s.path = path
		}
	}
}

// WithCookieSecure marks the cookie Secure (HTTPS only). Defaults to false.
func WithCookieSecure(secure bool) CookieOption {
	return func(s *CookieStore) {
		s.secure = secure
	}
}

// WithCookieHTTPOnly marks the cookie HttpOnly. Defaults to true.
func WithCookieHTTPOnly(httpOnly bool) CookieOption {
	return func(s *CookieStore) {
		s.httpOnly = httpOnly
	}
}

// WithCookieSameSite sets the SameSite attribute. Defaults to Lax.
func WithCookieSameSite(sameSite http.SameSite) CookieOption {
	return func(s *CookieStore) {
		s.sameSite = sameSite
	}
}

// NewCookieStore creates a CookieStore. The secret is hashed with SHA-256 and
// used as the AES-256-GCM key; it must be kept confidential.
func NewCookieStore(secret []byte, opts ...CookieOption) *CookieStore {
	s := &CookieStore{
		secret:   secret,
		name:     defaultSessionName,
		maxAge:   int((8 * time.Hour).Seconds()),
		path:     "/",
		httpOnly: true,
		sameSite: http.SameSiteLaxMode,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Open implements Store.
func (s *CookieStore) Open(r *http.Request, w http.ResponseWriter) (web.Session, error) {
	return &cookieSession{store: s, r: r, w: w}, nil
}

// cookieSession is a web.Session backed by a single encrypted cookie holding a
// map of string values.
type cookieSession struct {
	store  *CookieStore
	r      *http.Request
	w      http.ResponseWriter
	values map[string]string
	loaded bool
}

func (s *cookieSession) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	s.values = map[string]string{}

	cookie, err := s.r.Cookie(s.store.name)
	if err != nil || cookie.Value == "" {
		return
	}

	values, err := s.store.decode(cookie.Value)
	if err != nil {
		// Treat undecryptable or expired cookies as a fresh session.
		return
	}
	s.values = values
}

func (s *cookieSession) Get(key string) (string, bool) {
	s.load()
	value, ok := s.values[key]
	return value, ok
}

func (s *cookieSession) Set(key string, value string) {
	s.load()
	s.values[key] = value
}

func (s *cookieSession) Delete(key string) {
	s.load()
	delete(s.values, key)
}

func (s *cookieSession) Save() error {
	if s.w == nil {
		return errors.New("nethttp: cannot save session without a response writer")
	}

	if len(s.values) == 0 {
		http.SetCookie(s.w, &http.Cookie{
			Name:     s.store.name,
			Value:    "",
			Path:     s.store.path,
			HttpOnly: s.store.httpOnly,
			Secure:   s.store.secure,
			SameSite: s.store.sameSite,
			MaxAge:   -1,
		})
		return nil
	}

	encoded, err := s.store.encode(s.values)
	if err != nil {
		return err
	}

	http.SetCookie(s.w, &http.Cookie{
		Name:     s.store.name,
		Value:    encoded,
		Path:     s.store.path,
		HttpOnly: s.store.httpOnly,
		Secure:   s.store.secure,
		SameSite: s.store.sameSite,
		MaxAge:   s.store.maxAge,
	})
	return nil
}

type cookiePayload struct {
	Values   map[string]string `json:"v"`
	ExpireAt int64             `json:"exp,omitempty"`
}

func (s *CookieStore) encode(values map[string]string) (string, error) {
	payload := cookiePayload{Values: values}
	if s.maxAge > 0 {
		payload.ExpireAt = time.Now().Add(time.Duration(s.maxAge) * time.Second).Unix()
	}

	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sessionKey(s.secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := gcm.Seal(nil, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func (s *CookieStore) decode(value string) (map[string]string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey(s.secret))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("nethttp: session cookie too short")
	}

	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	var payload cookiePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, err
	}
	if payload.ExpireAt != 0 && time.Now().Unix() > payload.ExpireAt {
		return nil, errors.New("nethttp: session cookie expired")
	}
	return payload.Values, nil
}

func sessionKey(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}
