package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/roledio/roled-go"
)

// memSession is an in-memory web.Session implementation for tests.
type memSession struct {
	mu     sync.Mutex
	values map[string]string
	saves  int
}

func newMemSession() *memSession {
	return &memSession{values: map[string]string{}}
}

func (m *memSession) Get(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[key]
	return v, ok
}

func (m *memSession) Set(key string, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
}

func (m *memSession) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, key)
}

func (m *memSession) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	return nil
}

func (m *memSession) saveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saves
}

func (m *memSession) hasKey(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.values[key]
	return ok
}

type fakeRoled struct {
	mu sync.Mutex

	inspectCalls     int
	inspectFailFirst int // number of initial inspect calls to fail
	lastInspectToken string
	refreshCalls     int
	revokeCalls      int
	lastRevokeToken  string
}

func newFakeRoled(t *testing.T) (*httptest.Server, *fakeRoled) {
	t.Helper()

	fake := &fakeRoled{}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeToken := func(access, refresh string) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"access_token":             access,
					"expires_in":               3600,
					"token_type":               "bearer",
					"refresh_token":            refresh,
					"refresh_token_expires_in": 604800,
				},
			})
		}

		switch r.FormValue("grant_type") {
		case "authorization_code":
			if r.FormValue("authorization_code") == "" || r.FormValue("code_verifier") == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error":   map[string]string{"code": "invalid_request", "message": "missing params"},
				})
				return
			}
			writeToken("access_token_initial", "refresh_token_initial")
		case "refresh_token":
			fake.mu.Lock()
			fake.refreshCalls++
			rt := r.FormValue("refresh_token")
			fake.mu.Unlock()
			if rt == "rt_bad" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error":   map[string]string{"code": "invalid_grant", "message": "bad refresh token"},
				})
				return
			}
			writeToken("access_token_refreshed", "refresh_token_rotated")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	mux.HandleFunc("GET /api/v1/tokens/current", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		fake.inspectCalls++
		fake.lastInspectToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		fail := fake.inspectCalls <= fake.inspectFailFirst
		fake.mu.Unlock()

		if fail {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"error":   map[string]string{"code": "unauthorized", "message": "token rejected"},
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"id":          "tok_123",
				"permissions": []string{"docs:read"},
			},
		})
	})

	mux.HandleFunc("POST /api/v1/tokens/current/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		fake.mu.Lock()
		fake.revokeCalls++
		fake.lastRevokeToken = body.RefreshToken
		fake.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, fake
}

func newTestFlow(t *testing.T, server *httptest.Server) *Flow {
	t.Helper()

	client, err := roled.NewClient(
		roled.WithBaseURL(server.URL),
		roled.WithClientID("client_123"),
		roled.WithRedirectURI("http://app.test/auth/callback"),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return NewFlow(client.Auth)
}

// seedAuthenticated stores a completed auth session directly.
func seedAuthenticated(t *testing.T, sess *memSession, accessToken, refreshToken string, accessExpiry, refreshExpiry time.Time) {
	t.Helper()
	authSess := &roled.AuthSession{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiry,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiry,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
	if err := SetAuthSession(sess, authSess); err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}
}

func TestBeginLogin(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()

	authURL, err := flow.BeginLogin(context.Background(), sess)
	if err != nil {
		t.Fatalf("BeginLogin failed: %v", err)
	}
	if !strings.Contains(authURL, "code_challenge=") || !strings.Contains(authURL, "state=") {
		t.Fatalf("authorize URL missing PKCE params: %s", authURL)
	}

	authSess, err := LoadAuthSession(sess)
	if err != nil {
		t.Fatal(err)
	}
	if authSess.OAuthState == "" || authSess.PKCEVerifier == "" {
		t.Fatal("expected OAuthState and PKCEVerifier to be stored")
	}
	if sess.saveCount() != 1 {
		t.Fatalf("expected session to be saved once, got %d", sess.saveCount())
	}
}

func TestCompleteLoginSuccess(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()

	if _, err := flow.BeginLogin(context.Background(), sess); err != nil {
		t.Fatalf("BeginLogin failed: %v", err)
	}
	authSess, _ := LoadAuthSession(sess)

	err := flow.CompleteLogin(context.Background(), sess, CallbackParams{
		Code:  "auth_code_123",
		State: authSess.OAuthState,
	})
	if err != nil {
		t.Fatalf("CompleteLogin failed: %v", err)
	}

	got, _ := LoadAuthSession(sess)
	if got.AccessToken != "access_token_initial" || got.RefreshToken != "refresh_token_initial" {
		t.Fatalf("unexpected tokens: %+v", got)
	}
	if got.OAuthState != "" || got.PKCEVerifier != "" {
		t.Fatal("expected one-time state and verifier to be cleared")
	}
	if got.AccessTokenExpiresAt.IsZero() || got.RefreshTokenExpiresAt.IsZero() {
		t.Fatal("expected token expiry timestamps to be set")
	}
}

func TestCompleteLoginOAuthError(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()

	err := flow.CompleteLogin(context.Background(), sess, CallbackParams{
		OAuthError: "access_denied",
	})
	if !errors.Is(err, ErrOAuthProvider) {
		t.Fatalf("expected ErrOAuthProvider, got %v", err)
	}
}

func TestCompleteLoginInvalidState(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()

	if _, err := flow.BeginLogin(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	cases := []CallbackParams{
		{Code: "c", State: "wrong-state"},
		{Code: "c", State: ""},
		{Code: "", State: "anything"},
	}
	for _, params := range cases {
		if err := flow.CompleteLogin(context.Background(), sess, params); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("params %+v: expected ErrInvalidState, got %v", params, err)
		}
	}
}

func TestCompleteLoginNoSession(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()

	err := flow.CompleteLogin(context.Background(), sess, CallbackParams{
		Code:  "c",
		State: "s",
	})
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestLogoutRevokesAndClears(t *testing.T) {
	server, fake := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()
	seedAuthenticated(t, sess, "at", "rt_secret", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	if err := flow.Logout(context.Background(), sess); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.revokeCalls != 1 || fake.lastRevokeToken != "rt_secret" {
		t.Fatalf("expected one revoke call with refresh token, got %d calls token=%q", fake.revokeCalls, fake.lastRevokeToken)
	}
	if sess.hasKey(authSessionKey) {
		t.Fatal("expected session to be cleared")
	}
}

func TestLogoutUnauthenticated(t *testing.T) {
	server, fake := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()

	if err := flow.Logout(context.Background(), sess); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}
	if fake.revokeCalls != 0 {
		t.Fatal("expected no revoke call for unauthenticated session")
	}
}

func TestAuthenticateNotAuthenticated(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()

	if _, _, err := flow.Authenticate(context.Background(), sess); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestAuthenticateValidToken(t *testing.T) {
	server, fake := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()
	seedAuthenticated(t, sess, "at_valid", "rt", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	authSess, inspection, err := flow.Authenticate(context.Background(), sess)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if authSess.AccessToken != "at_valid" {
		t.Fatalf("unexpected access token: %q", authSess.AccessToken)
	}
	if inspection == nil || inspection.ID != "tok_123" {
		t.Fatalf("unexpected inspection: %+v", inspection)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.refreshCalls != 0 {
		t.Fatal("expected no refresh for valid access token")
	}
	if fake.lastInspectToken != "at_valid" {
		t.Fatalf("expected inspect with at_valid, got %q", fake.lastInspectToken)
	}
}

func TestAuthenticateRefreshesExpiredAccessToken(t *testing.T) {
	server, fake := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()
	seedAuthenticated(t, sess, "at_old", "rt", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	authSess, _, err := flow.Authenticate(context.Background(), sess)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if authSess.AccessToken != "access_token_refreshed" {
		t.Fatalf("expected refreshed token, got %q", authSess.AccessToken)
	}
	if authSess.RefreshToken != "refresh_token_rotated" {
		t.Fatalf("expected rotated refresh token, got %q", authSess.RefreshToken)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.refreshCalls != 1 {
		t.Fatalf("expected 1 refresh call, got %d", fake.refreshCalls)
	}
	if fake.inspectCalls != 1 {
		t.Fatalf("expected 1 inspect call, got %d", fake.inspectCalls)
	}
}

func TestAuthenticateRetriesAfterInspectFailure(t *testing.T) {
	server, fake := newFakeRoled(t)
	fake.inspectFailFirst = 1 // first inspect fails, retry after refresh succeeds
	flow := newTestFlow(t, server)
	sess := newMemSession()
	seedAuthenticated(t, sess, "at_stale", "rt", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	_, inspection, err := flow.Authenticate(context.Background(), sess)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if inspection == nil {
		t.Fatal("expected inspection after retry")
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.refreshCalls != 1 {
		t.Fatalf("expected 1 refresh call, got %d", fake.refreshCalls)
	}
	if fake.inspectCalls != 2 {
		t.Fatalf("expected 2 inspect calls, got %d", fake.inspectCalls)
	}
}

func TestAuthenticateFailsWhenRefreshRejected(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()
	seedAuthenticated(t, sess, "at_old", "rt_bad", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	if _, _, err := flow.Authenticate(context.Background(), sess); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
	if sess.hasKey(authSessionKey) {
		t.Fatal("expected failed session to be cleared")
	}
}

func TestAuthenticateFailsWhenRefreshTokenExpired(t *testing.T) {
	server, fake := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()
	seedAuthenticated(t, sess, "at_old", "rt", time.Now().Add(-time.Minute), time.Now().Add(-time.Hour))

	if _, _, err := flow.Authenticate(context.Background(), sess); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
	if fake.refreshCalls != 0 {
		t.Fatal("expected no refresh call for expired refresh token")
	}
	if sess.hasKey(authSessionKey) {
		t.Fatal("expected failed session to be cleared")
	}
}

func TestAuthenticateMissingRefreshToken(t *testing.T) {
	server, _ := newFakeRoled(t)
	flow := newTestFlow(t, server)
	sess := newMemSession()
	// Access token present but expired, and no refresh token stored —
	// IsAuthenticated is false, so Authenticate must fail early.
	authSess := &roled.AuthSession{
		AccessToken:          "at_old",
		AccessTokenExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := SetAuthSession(sess, authSess); err != nil {
		t.Fatal(err)
	}
	if _, _, err := flow.Authenticate(context.Background(), sess); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}
