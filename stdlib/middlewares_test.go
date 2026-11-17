package stdlib

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/roledio/roled-go"
)

func TestRequireAuthRedirectsWhenUnauthenticated(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, _ := newTestHandler(t, server.URL)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	h.RequireAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != defaultLoginPath {
		t.Errorf("expected redirect to %q, got %q", defaultLoginPath, loc)
	}
}

func TestRequireAuthInjectsSessionAndInspection(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL)
	cookie := authenticate(t, h, store)

	var gotSession *roled.AuthSession
	var gotInspection *roled.TokenInspection
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = AuthSessionFromContext(r.Context())
		gotInspection = TokenInspectionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	h.RequireAuth(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotSession == nil || gotSession.AccessToken != "access_token_initial" {
		t.Errorf("unexpected auth session in context: %+v", gotSession)
	}
	if gotInspection == nil || gotInspection.ID != "tok_123" {
		t.Errorf("unexpected token inspection in context: %+v", gotInspection)
	}
}

func TestRequireAuthRefreshesExpiredAccessToken(t *testing.T) {
	server, fake := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL)
	cookie := authenticate(t, h, store)

	// Force the stored access token to be expired
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	sess, err := store.Get(req, defaultSessionName)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	authSess, err := loadAuthSession(sess)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	authSess.AccessTokenExpiresAt = time.Now().Add(-time.Hour)
	if err := setAuthSession(sess, authSess); err != nil {
		t.Fatalf("set session: %v", err)
	}

	// Persist using a recorder, then extract the new cookie
	saveRec := httptest.NewRecorder()
	if err := sess.Save(req, saveRec); err != nil {
		t.Fatalf("save session: %v", err)
	}
	cookie = sessionCookie(t, saveRec)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	h.RequireAuth(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if fake.refreshCalls != 1 {
		t.Errorf("expected 1 refresh call, got %d", fake.refreshCalls)
	}

	fake.mu.Lock()
	lastToken := fake.lastInspectToken
	fake.mu.Unlock()
	if lastToken != "access_token_refreshed" {
		t.Errorf("inspect used token %q, expected refreshed token", lastToken)
	}
}

func TestRequireAuthClearsSessionOnRefreshFailure(t *testing.T) {
	server, fake := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL)
	cookie := authenticate(t, h, store)

	// Corrupt the session: empty refresh token makes refresh fail
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	sess, err := store.Get(req, defaultSessionName)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	authSess, _ := loadAuthSession(sess)
	authSess.RefreshToken = ""
	authSess.AccessTokenExpiresAt = time.Now().Add(-time.Hour)
	_ = setAuthSession(sess, authSess)

	saveRec := httptest.NewRecorder()
	_ = sess.Save(req, saveRec)
	cookie = sessionCookie(t, saveRec)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	h.RequireAuth(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d", rec.Code)
	}
	if fake.refreshCalls != 0 {
		t.Errorf("refresh should not be called without a refresh token, got %d calls", fake.refreshCalls)
	}
}

func TestRequirePermission(t *testing.T) {
	server, fake := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL)
	cookie := authenticate(t, h, store)

	fake.mu.Lock()
	fake.inspection.Permissions = []string{"docs:read", "docs:write"}
	fake.mu.Unlock()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Allowed permission
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	req.AddCookie(cookie)
	h.RequireAuth(h.RequirePermission("docs:write")(ok)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Missing permission -> 403
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	h.RequireAuth(h.RequirePermission("admin:write")(ok)).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequirePermissionCustomForbiddenHandler(t *testing.T) {
	server, fake := newFakeRoled(t)
	var forbiddenCalled bool
	h, store := newTestHandler(t, server.URL,
		WithOnForbidden(func(w http.ResponseWriter, r *http.Request) {
			forbiddenCalled = true
			w.WriteHeader(http.StatusTeapot)
		}),
	)
	cookie := authenticate(t, h, store)

	fake.mu.Lock()
	fake.inspection.Permissions = []string{}
	fake.mu.Unlock()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	h.RequireAuth(h.RequirePermission("admin:write")(ok)).ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("expected 418, got %d", rec.Code)
	}
	if !forbiddenCalled {
		t.Error("onForbidden was not called")
	}
}

func TestRequireRole(t *testing.T) {
	server, fake := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL)
	cookie := authenticate(t, h, store)

	fake.mu.Lock()
	fake.inspection.Role = &roled.TokenRoleSummary{ID: "role_1", Code: "admin", Name: "Admin"}
	fake.mu.Unlock()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Matching role
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	h.RequireAuth(h.RequireRole("admin")(ok)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Non-matching role
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	h.RequireAuth(h.RequireRole("member")(ok)).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAuthSessionHelper(t *testing.T) {
	server, _ := newFakeRoled(t)
	h, store := newTestHandler(t, server.URL)
	cookie := authenticate(t, h, store)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	authSess, err := h.AuthSession(req)
	if err != nil {
		t.Fatalf("AuthSession: %v", err)
	}
	if !authSess.IsAuthenticated() {
		t.Error("expected authenticated session")
	}
}
