package roledfiber

import (
	"net/http"
	"testing"
)

func TestRequireAuthRedirectsWhenUnauthenticated(t *testing.T) {
	app, _ := newTestApp(t)

	resp := doRequest(t, app, http.MethodGet, "/dashboard", "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != defaultLoginPath {
		t.Errorf("expected redirect to %q, got %q", defaultLoginPath, loc)
	}
}

func TestRequireAuthAllowsAuthenticated(t *testing.T) {
	app, fake := newTestApp(t)
	cookie := authenticate(t, app)

	resp := doRequest(t, app, http.MethodGet, "/dashboard", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	fake.mu.Lock()
	lastToken := fake.lastInspectToken
	fake.mu.Unlock()
	if lastToken != "access_token_initial" {
		t.Errorf("inspect used token %q", lastToken)
	}
}

func TestLogoutRevokesAndClearsSession(t *testing.T) {
	app, fake := newTestApp(t)
	cookie := authenticate(t, app)

	resp := doRequest(t, app, http.MethodPost, "/logout", cookie)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	if fake.revokeCalls != 1 {
		t.Errorf("expected 1 revoke call, got %d", fake.revokeCalls)
	}

	// After logout the session is cleared; dashboard must redirect to login.
	resp = doRequest(t, app, http.MethodGet, "/dashboard", cookie)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect after logout, got %d", resp.StatusCode)
	}
}
