package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthService_BuildAuthorizeURL(t *testing.T) {
	client, err := NewClient(
		WithBaseURL("https://auth.roled.io"),
		WithClientID("client_123"),
		WithRedirectURI("https://app.com/callback"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	authURL, err := client.Auth.BuildAuthorizeURL(AuthorizeURLParams{
		CodeChallenge: "challenge_abc",
		State:         "state_xyz",
		IsSignup:      true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(authURL, "https://auth.roled.io/authorize?") {
		t.Errorf("unexpected URL prefix: %s", authURL)
	}
	if !strings.Contains(authURL, "client_id=client_123") {
		t.Errorf("missing client_id in %s", authURL)
	}
	if !strings.Contains(authURL, "redirect_uri=https%3A%2F%2Fapp.com%2Fcallback") {
		t.Errorf("missing redirect_uri in %s", authURL)
	}
	if !strings.Contains(authURL, "response_type=code") {
		t.Errorf("missing response_type in %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("missing code_challenge_method in %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge=challenge_abc") {
		t.Errorf("missing code_challenge in %s", authURL)
	}
	if !strings.Contains(authURL, "state=state_xyz") {
		t.Errorf("missing state in %s", authURL)
	}
	if !strings.Contains(authURL, "signup=true") {
		t.Errorf("missing signup in %s", authURL)
	}

	// Missing code challenge should return error
	_, err = client.Auth.BuildAuthorizeURL(AuthorizeURLParams{})
	if err == nil {
		t.Errorf("expected error when code_challenge is missing")
	}
}

func TestAuthService_ExchangeAuthorizationCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/tokens" {
			http.NotFound(w, r)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if r.FormValue("grant_type") != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: false,
				Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: ErrCodeInvalidParams, Message: "grant_type must be authorization_code"},
			})
			return
		}

		if r.FormValue("authorization_code") == "invalid_code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: false,
				Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: ErrCodeInvalidAuthorizationCode, Message: "The provided authorization code is invalid."},
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responseEnvelope[TokenResponse]{
			Success: true,
			Data: TokenResponse{
				AccessToken:           "access_token_123",
				ExpiresIn:             3600,
				TokenType:             "bearer",
				RefreshToken:          "refresh_token_456",
				RefreshTokenExpiresIn: 604800,
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(
		WithBaseURL(server.URL),
		WithClientID("client_123"),
		WithRedirectURI("https://app.com/callback"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()

	// Success case
	resp, err := client.Auth.ExchangeAuthorizationCode(ctx, ExchangeAuthorizationCodeParams{
		Code:         "valid_code",
		CodeVerifier: "verifier_123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "access_token_123" {
		t.Errorf("expected access_token_123, got %s", resp.AccessToken)
	}
	if resp.RefreshToken != "refresh_token_456" {
		t.Errorf("expected refresh_token_456, got %s", resp.RefreshToken)
	}

	// Error case: invalid code
	_, err = client.Auth.ExchangeAuthorizationCode(ctx, ExchangeAuthorizationCodeParams{
		Code:         "invalid_code",
		CodeVerifier: "verifier_123",
	})
	if err == nil {
		t.Fatalf("expected error for invalid_code")
	}
	if ErrorCode(err) != ErrCodeInvalidAuthorizationCode {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidAuthorizationCode, ErrorCode(err))
	}
}

func TestAuthService_RefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/tokens" {
			http.NotFound(w, r)
			return
		}

		_ = r.ParseForm()
		if r.FormValue("grant_type") != "refresh_token" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		if r.FormValue("refresh_token") == "expired_token" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: false,
				Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: ErrCodeRefreshTokenExpired, Message: "This refresh token has expired."},
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responseEnvelope[TokenResponse]{
			Success: true,
			Data: TokenResponse{
				AccessToken:  "new_access_token",
				ExpiresIn:    3600,
				TokenType:    "bearer",
				RefreshToken: "new_refresh_token",
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithClientID("client_123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	tokens, err := client.Auth.RefreshToken(ctx, "valid_refresh_token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken != "new_access_token" {
		t.Errorf("expected new_access_token, got %s", tokens.AccessToken)
	}

	_, err = client.Auth.RefreshToken(ctx, "expired_token")
	if err == nil {
		t.Fatalf("expected error for expired_token")
	}
	if ErrorCode(err) != ErrCodeRefreshTokenExpired {
		t.Errorf("expected code %s, got %s", ErrCodeRefreshTokenExpired, ErrorCode(err))
	}
}

func TestAuthService_ExchangeClientCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/tokens" {
			http.NotFound(w, r)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != "client_123" || password != "secret_456" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: false,
				Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: ErrCodeInvalidClientCredentials, Message: "Invalid client credentials provided."},
			})
			return
		}

		_ = r.ParseForm()
		if r.FormValue("grant_type") != "client_credentials" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responseEnvelope[TokenResponse]{
			Success: true,
			Data: TokenResponse{
				AccessToken: "m2m_access_token",
				ExpiresIn:   3600,
				TokenType:   "bearer",
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(
		WithBaseURL(server.URL),
		WithClientID("client_123"),
		WithClientSecret("secret_456"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	tokens, err := client.Auth.ExchangeClientCredentials(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken != "m2m_access_token" {
		t.Errorf("expected m2m_access_token, got %s", tokens.AccessToken)
	}
}

func TestAuthService_InspectAndRevoke(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/tokens/current" && r.Method == http.MethodGet {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer valid_token" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
					Success: false,
					Error: &struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					}{Code: ErrCodeInvalidAuthorizationToken, Message: "Unauthorized request."},
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(responseEnvelope[TokenInspection]{
				Success: true,
				Data: TokenInspection{
					ID: "token_123",
					Project: TokenProjectSummary{
						ID:   "proj_123",
						Name: "Test Project",
					},
					Client: TokenClientSummary{
						ID:   "client_123",
						Name: "Test Client",
					},
					User: &TokenUserSummary{
						ID:          "user_123",
						DisplayName: "Alice",
					},
					Permissions: []string{"users:read", "users:write"},
				},
			})
			return
		}

		if r.URL.Path == "/api/v1/tokens/current/revoke" && r.Method == http.MethodPost {
			var body struct {
				ClientID     string `json:"client_id"`
				RefreshToken string `json:"refresh_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)

			if body.ClientID != "client_123" || body.RefreshToken == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: true,
				Data:    nil,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithClientID("client_123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()

	// Inspect success
	inspection, err := client.Auth.InspectToken(ctx, "valid_token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inspection.ID != "token_123" {
		t.Errorf("expected token_123, got %s", inspection.ID)
	}
	if len(inspection.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(inspection.Permissions))
	}

	// Inspect failure (invalid token)
	_, err = client.Auth.InspectToken(ctx, "bad_token")
	if err == nil {
		t.Fatalf("expected error for bad_token")
	}
	if !IsUnauthorized(err) {
		t.Errorf("expected IsUnauthorized to be true")
	}

	// Revoke success
	err = client.Auth.RevokeToken(ctx, RevokeTokenParams{
		RefreshToken: "refresh_123",
	})
	if err != nil {
		t.Fatalf("unexpected error on revoke: %v", err)
	}
}
