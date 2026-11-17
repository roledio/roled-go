package stdlib

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/roledio/roled-go"
)

var testKeyPairs = [][]byte{
	[]byte("0123456789abcdef0123456789abcdef"), // hash key
	[]byte("0123456789abcdef0123456789abcdef"), // block key
}

type fakeRoled struct {
	mu sync.Mutex

	inspectCalls     int
	lastInspectToken string
	refreshCalls     int
	revokeCalls      int
	lastRevokeBody   string

	inspection roled.TokenInspection
}

func newFakeRoled(t *testing.T) (*httptest.Server, *fakeRoled) {
	t.Helper()

	fake := &fakeRoled{
		inspection: roled.TokenInspection{
			ID:        "tok_123",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			Project: roled.TokenProjectSummary{
				ID:   "proj_1",
				Name: "Test Project",
			},
			Client: roled.TokenClientSummary{
				ID:   "client_123",
				Name: "Test Client",
			},
			Permissions: []string{"docs:read"},
		},
	}

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
			fake.mu.Unlock()
			writeToken("access_token_refreshed", "refresh_token_rotated")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	mux.HandleFunc("GET /api/v1/tokens/current", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		fake.inspectCalls++
		fake.lastInspectToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		fake.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    fake.inspection,
		})
	})

	mux.HandleFunc("POST /api/v1/tokens/current/revoke", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		fake.revokeCalls++
		fake.lastRevokeBody = r.Header.Get("Authorization")
		fake.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, fake
}

func newTestHandler(t *testing.T, baseURL string, opts ...Option) (*Handler, sessions.Store) {
	t.Helper()

	client, err := roled.NewClient(
		roled.WithBaseURL(baseURL),
		roled.WithClientID("client_123"),
		roled.WithRedirectURI("http://app.test/auth/callback"),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	store := sessions.NewCookieStore(testKeyPairs...)
	h := New(client.Auth, store, opts...)
	return h, store
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == defaultSessionName {
			return c
		}
	}
	t.Fatal("session cookie not found")
	return nil
}

func loadSessionForCookie(t *testing.T, store sessions.Store, cookie *http.Cookie) *roled.AuthSession {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	sess, err := store.Get(req, defaultSessionName)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	authSess, err := loadAuthSession(sess)
	if err != nil {
		t.Fatalf("failed to load auth session: %v", err)
	}
	return authSess
}

// authenticate runs the full login + callback flow and returns the session
// cookie to use on subsequent requests.
func authenticate(t *testing.T, h *Handler, store sessions.Store) *http.Cookie {
	t.Helper()

	// Login
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login: expected redirect, got %d", rec.Code)
	}
	cookie := sessionCookie(t, rec)

	// Read state stored in session
	authSess := loadSessionForCookie(t, store, cookie)
	if authSess.OAuthState == "" || authSess.PKCEVerifier == "" {
		t.Fatal("login did not store OAuth state or PKCE verifier")
	}

	// Callback
	cbRec := httptest.NewRecorder()
	cbReq := httptest.NewRequest(
		http.MethodGet,
		"/auth/callback?code=test_code&state="+url.QueryEscape(authSess.OAuthState),
		nil,
	)
	cbReq.AddCookie(cookie)
	h.Callback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback: expected redirect, got %d", cbRec.Code)
	}

	return sessionCookie(t, cbRec)
}

func TestLoginRedirectsToAuthorizeURL(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL)

	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("missing Location header")
	}
	if !strings.HasPrefix(location, server.URL+"/authorize?") {
		t.Fatalf("unexpected redirect location: %s", location)
	}
	for _, want := range []string{
		"client_id=client_123",
		"response_type=code",
		"code_challenge_method=S256",
		"state=",
		"code_challenge=",
	} {
		if !strings.Contains(location, want) {
			t.Errorf("authorize URL missing %q: %s", want, location)
		}
	}

	authSess := loadSessionForCookie(t, store, sessionCookie(t, rec))
	if authSess.OAuthState == "" {
		t.Error("OAuthState not stored in session")
	}
	if authSess.PKCEVerifier == "" {
		t.Error("PKCEVerifier not stored in session")
	}
}

func TestCallbackSuccess(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL,
		WithOnCallbackSuccess(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		}),
	)

	cookie := authenticate(t, h, store)

	authSess := loadSessionForCookie(t, store, cookie)
	if authSess.AccessToken != "access_token_initial" {
		t.Errorf("unexpected access token: %q", authSess.AccessToken)
	}
	if authSess.RefreshToken != "refresh_token_initial" {
		t.Errorf("unexpected refresh token: %q", authSess.RefreshToken)
	}
	if !authSess.IsAuthenticated() {
		t.Error("session should be authenticated")
	}
	if authSess.OAuthState != "" || authSess.PKCEVerifier != "" {
		t.Error("one-time OAuth values should be cleared after callback")
	}
}

func TestCallbackRejectsInvalidState(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, _ := newTestHandler(t, server.URL)

	// Login to obtain a session with a pending state
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	cookie := sessionCookie(t, rec)

	cbRec := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=test_code&state=wrong_state", nil)
	cbReq.AddCookie(cookie)
	h.Callback(cbRec, cbReq)

	if cbRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", cbRec.Code)
	}
}

func TestCallbackRejectsMissingSession(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, _ := newTestHandler(t, server.URL)

	rec := httptest.NewRecorder()
	h.Callback(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=x&state=y", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCallbackHandlesOAuthError(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, _ := newTestHandler(t, server.URL)

	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	cookie := sessionCookie(t, rec)

	cbRec := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil)
	cbReq.AddCookie(cookie)
	h.Callback(cbRec, cbReq)

	if cbRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", cbRec.Code)
	}
}

func TestLogoutRevokesAndClearsSession(t *testing.T) {
	server, fake := newFakeRoled(t)
	var loggedOut bool
	h, store := newTestHandler(t, server.URL,
		WithOnLogoutSuccess(func(w http.ResponseWriter, r *http.Request) {
			loggedOut = true
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	)

	cookie := authenticate(t, h, store)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	h.Logout(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if !loggedOut {
		t.Error("onLogoutSuccess was not called")
	}
	if fake.revokeCalls != 1 {
		t.Errorf("expected 1 revoke call, got %d", fake.revokeCalls)
	}

	// Session must be cleared: reload via store using the *new* cookie if set,
	// otherwise the old one still decodes but holds no tokens.
	newCookie := cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == defaultSessionName {
			newCookie = c
		}
	}
	authSess := loadSessionForCookie(t, store, newCookie)
	if authSess.IsAuthenticated() {
		t.Error("session should not be authenticated after logout")
	}
}
