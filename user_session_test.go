package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestUserSessionClient_AutoRefreshOn401(t *testing.T) {
	var userCalls int32
	var refreshCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Token refresh endpoint
		if r.URL.Path == "/api/v1/tokens" && r.Method == http.MethodPost {
			atomic.AddInt32(&refreshCalls, 1)
			_ = r.ParseForm()
			if r.FormValue("refresh_token") != "initial_refresh_token" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
					Success: false,
					Error: &struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					}{Code: ErrCodeInvalidRefreshToken, Message: "Invalid refresh token"},
				})
				return
			}

			_ = json.NewEncoder(w).Encode(responseEnvelope[TokenResponse]{
				Success: true,
				Data: TokenResponse{
					AccessToken:  "refreshed_access_token",
					RefreshToken: "new_refresh_token",
					ExpiresIn:    3600,
					TokenType:    "bearer",
				},
			})
			return
		}

		// User profile endpoint
		if r.URL.Path == "/api/v1/users/current" && r.Method == http.MethodGet {
			count := atomic.AddInt32(&userCalls, 1)
			auth := r.Header.Get("Authorization")

			// First request has expired access token -> return 401
			if auth == "Bearer expired_access_token" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
					Success: false,
					Error: &struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					}{Code: ErrCodeInvalidAuthorizationToken, Message: "Token expired"},
				})
				return
			}

			// Second request with refreshed token -> return user
			if auth == "Bearer refreshed_access_token" {
				_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
					Success: true,
					Data: UserDetails{
						ID:          "user_123",
						DisplayName: "Alice",
						Email:       StringPtr("alice@example.com"),
						RoleName:    "Admin",
					},
				})
				return
			}

			t.Errorf("unexpected call #%d with auth: %s", count, auth)
			http.Error(w, "bad auth", http.StatusBadRequest)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithClientID("client_123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userClient := client.ForUser("expired_access_token", "initial_refresh_token")

	if userClient.IsRefreshed() {
		t.Errorf("expected IsRefreshed to be false initially")
	}

	ctx := context.Background()
	user, err := userClient.GetCurrentUser(ctx)
	if err != nil {
		t.Fatalf("unexpected error during auto-refreshed call: %v", err)
	}

	if user.ID != "user_123" {
		t.Errorf("expected user_123, got %s", user.ID)
	}

	// Verify token refresh happened
	if !userClient.IsRefreshed() {
		t.Errorf("expected IsRefreshed to be true after auto-refresh")
	}

	newAccess, newRefresh := userClient.Tokens()
	if newAccess != "refreshed_access_token" {
		t.Errorf("expected refreshed_access_token, got %s", newAccess)
	}
	if newRefresh != "new_refresh_token" {
		t.Errorf("expected new_refresh_token, got %s", newRefresh)
	}

	if atomic.LoadInt32(&userCalls) != 2 {
		t.Errorf("expected 2 user calls (1 fail, 1 retry), got %d", atomic.LoadInt32(&userCalls))
	}
	if atomic.LoadInt32(&refreshCalls) != 1 {
		t.Errorf("expected 1 refresh call, got %d", atomic.LoadInt32(&refreshCalls))
	}
}

func TestUserSessionClient_ConcurrentCalls(t *testing.T) {
	var refreshCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/tokens" {
			atomic.AddInt32(&refreshCalls, 1)
			_ = json.NewEncoder(w).Encode(responseEnvelope[TokenResponse]{
				Success: true,
				Data: TokenResponse{
					AccessToken:  "refreshed_concurrent_token",
					RefreshToken: "new_refresh_token",
				},
			})
			return
		}

		if r.URL.Path == "/api/v1/users/current" {
			if r.Header.Get("Authorization") == "Bearer initial_expired_token" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
					Success: false,
					Error: &struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					}{Code: ErrCodeInvalidAuthorizationToken, Message: "Token expired"},
				})
				return
			}

			_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
				Success: true,
				Data: UserDetails{
					ID:          "user_concurrent",
					DisplayName: "Concurrent User",
				},
			})
			return
		}
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithClientID("client_123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userClient := client.ForUser("initial_expired_token", "valid_refresh_token")
	ctx := context.Background()

	const concurrency = 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			u, err := userClient.GetCurrentUser(ctx)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if u.ID != "user_concurrent" {
				t.Errorf("unexpected user ID: %s", u.ID)
			}
		}()
	}

	wg.Wait()

	if userClient.AccessToken() != "refreshed_concurrent_token" {
		t.Errorf("expected access token 'refreshed_concurrent_token', got %s", userClient.AccessToken())
	}
}

func TestUserSessionClient_UpdateInspectRevoke(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/users/current" && r.Method == http.MethodPut {
			_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
				Success: true,
				Data: UserDetails{
					ID:          "u1",
					DisplayName: "Updated Name",
				},
			})
			return
		}

		if r.URL.Path == "/api/v1/tokens/current" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[TokenInspection]{
				Success: true,
				Data: TokenInspection{
					ID: "insp_1",
				},
			})
			return
		}

		if r.URL.Path == "/api/v1/tokens/current/revoke" && r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: true,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithClientID("c1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userClient := client.ForUser("token_1", "refresh_1")
	ctx := context.Background()

	// Update current user
	updated, err := userClient.UpdateCurrentUser(ctx, UpdateCurrentUserParams{
		DisplayName: "Updated Name",
		Email:       "alice@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error updating current user: %v", err)
	}
	if updated.DisplayName != "Updated Name" {
		t.Errorf("expected 'Updated Name', got %s", updated.DisplayName)
	}

	// Inspect token
	insp, err := userClient.InspectToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error inspecting token: %v", err)
	}
	if insp.ID != "insp_1" {
		t.Errorf("expected insp_1, got %s", insp.ID)
	}

	// Revoke
	err = userClient.Revoke(ctx)
	if err != nil {
		t.Fatalf("unexpected error revoking token: %v", err)
	}
}

func TestUserSessionClient_RefreshFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/users/current" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: false,
				Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: ErrCodeInvalidAuthorizationToken, Message: "Expired token"},
			})
			return
		}

		if r.URL.Path == "/api/v1/tokens" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: false,
				Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: ErrCodeRefreshTokenExpired, Message: "Refresh token is expired"},
			})
			return
		}
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithClientID("c1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userClient := client.ForUser("token_bad", "refresh_bad")
	ctx := context.Background()

	_, err = userClient.GetCurrentUser(ctx)
	if err == nil {
		t.Fatalf("expected error when refresh token fails")
	}
}
