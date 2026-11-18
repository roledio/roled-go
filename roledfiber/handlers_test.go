package roledfiber

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	fibersession "github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roledio/roled-go"
)

type fakeRoled struct {
	mu sync.Mutex

	inspectCalls     int
	lastInspectToken string
	refreshCalls     int
	revokeCalls      int

	inspection roled.TokenInspection
}

func newFakeRoled(t *testing.T) (*httptest.Server, *fakeRoled) {
	t.Helper()

	fake := &fakeRoled{
		inspection: roled.TokenInspection{
			ID:          "tok_123",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(time.Hour),
			Project:     roled.TokenProjectSummary{ID: "proj_1", Name: "Test Project"},
			Client:      roled.TokenClientSummary{ID: "client_123", Name: "Test Client"},
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
		fake.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, fake
}

func newTestApp(t *testing.T, opts ...Option) (*fiber.App, *fakeRoled) {
	t.Helper()

	server, fake := newFakeRoled(t)

	client, err := roled.NewClient(
		roled.WithBaseURL(server.URL),
		roled.WithClientID("client_123"),
		roled.WithRedirectURI("http://app.test/auth/callback"),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	h := New(client, opts...)

	app := fiber.New()
	app.Use(fibersession.New())

	app.Get("/login", h.Login)
	app.Get("/auth/callback", h.Callback)
	app.Post("/logout", h.Logout)
	app.Get("/dashboard", h.RequireAuth(func(c fiber.Ctx) error {
		return c.SendString("dashboard")
	}))

	return app, fake
}

func doRequest(t *testing.T, app *fiber.App, method, path, cookie string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func sessionCookieFrom(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "session_id" {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

// authenticate runs login + callback and returns the session cookie header.
func authenticate(t *testing.T, app *fiber.App) string {
	t.Helper()

	loginResp := doRequest(t, app, http.MethodGet, "/login", "")
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", loginResp.StatusCode)
	}
	cookie := sessionCookieFrom(loginResp)
	if cookie == "" {
		t.Fatal("session cookie not found after login")
	}

	// Extract state from the session via the session cookie: the authorize
	// redirect URL contains the state parameter.
	location := loginResp.Header.Get("Location")
	state := extractQueryParam(t, location, "state")

	cbResp := doRequest(t, app, http.MethodGet,
		"/auth/callback?code=test_code&state="+url.QueryEscape(state), cookie)
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d", cbResp.StatusCode)
	}

	return sessionCookieFrom(cbResp)
}

func extractQueryParam(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	value := u.Query().Get(key)
	if value == "" {
		t.Fatalf("missing %q in URL %q", key, rawURL)
	}
	return value
}

func TestLoginRedirectsToAuthorizeURL(t *testing.T) {
	app, _ := newTestApp(t)

	resp := doRequest(t, app, http.MethodGet, "/login", "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("missing Location header")
	}
	for _, want := range []string{
		"/authorize?",
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
	if sessionCookieFrom(resp) == "" {
		t.Error("expected session cookie after login")
	}
}

func TestCallbackSuccess(t *testing.T) {
	app, _ := newTestApp(t)

	cookie := authenticate(t, app)
	if cookie == "" {
		t.Fatal("no session cookie after callback")
	}
}

func TestCallbackRejectsInvalidState(t *testing.T) {
	app, _ := newTestApp(t)

	loginResp := doRequest(t, app, http.MethodGet, "/login", "")
	cookie := sessionCookieFrom(loginResp)

	resp := doRequest(t, app, http.MethodGet,
		"/auth/callback?code=test_code&state=wrong_state", cookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
