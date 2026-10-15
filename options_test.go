package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOptions(t *testing.T) {
	customHTTP := &http.Client{Timeout: 5 * time.Second}

	client, err := NewClient(
		WithBaseURL("https://custom.roled.io/"),
		WithClientID("client_123"),
		WithClientSecret("secret_456"),
		WithRedirectURI("https://app.com/callback"),
		WithToken("bearer_token_789"),
		WithHTTPClient(customHTTP),
		WithUserAgent("my-custom-app/1.0"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.BaseURL() != "https://custom.roled.io" {
		t.Errorf("expected base URL 'https://custom.roled.io', got %q", client.BaseURL())
	}
	if client.ClientID() != "client_123" {
		t.Errorf("expected client ID 'client_123', got %q", client.ClientID())
	}
	if client.clientSecret != "secret_456" {
		t.Errorf("expected client secret 'secret_456', got %q", client.clientSecret)
	}
	if client.RedirectURI() != "https://app.com/callback" {
		t.Errorf("expected redirect URI 'https://app.com/callback', got %q", client.RedirectURI())
	}
	if client.Token() != "bearer_token_789" {
		t.Errorf("expected token 'bearer_token_789', got %q", client.Token())
	}
	if client.httpClient != customHTTP {
		t.Errorf("expected custom HTTP client")
	}
	if client.userAgent != "my-custom-app/1.0" {
		t.Errorf("expected user agent 'my-custom-app/1.0', got %q", client.userAgent)
	}
}

func TestDefaultClient(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.BaseURL() != DefaultBaseURL {
		t.Errorf("expected %q, got %q", DefaultBaseURL, client.BaseURL())
	}
	if client.userAgent != DefaultUserAgent {
		t.Errorf("expected %q, got %q", DefaultUserAgent, client.userAgent)
	}
}

func TestWithBearerToken(t *testing.T) {
	client, err := New(WithBearerToken("my_bearer_token"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Token() != "my_bearer_token" {
		t.Errorf("expected 'my_bearer_token', got %q", client.Token())
	}

	client.SetToken("updated_token")
	if client.Token() != "updated_token" {
		t.Errorf("expected 'updated_token', got %q", client.Token())
	}
}

func TestClient_Authenticate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/tokens" {
			http.NotFound(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != "client_1" || pass != "secret_1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responseEnvelope[TokenResponse]{
			Success: true,
			Data: TokenResponse{
				AccessToken: "token_from_auth",
				ExpiresIn:   3600,
				TokenType:   "bearer",
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(
		WithBaseURL(server.URL),
		WithClientID("client_1"),
		WithClientSecret("secret_1"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	resp, err := client.Authenticate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AccessToken != "token_from_auth" {
		t.Errorf("expected 'token_from_auth', got %s", resp.AccessToken)
	}
	if client.Token() != "token_from_auth" {
		t.Errorf("expected client.Token() to be updated, got %s", client.Token())
	}
}
