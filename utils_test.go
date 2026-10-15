package roled

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerToken(t *testing.T) {
	if BearerToken(nil) != "" {
		t.Errorf("expected empty string for nil request")
	}

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	if BearerToken(req1) != "" {
		t.Errorf("expected empty string when Authorization header is absent")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if BearerToken(req2) != "" {
		t.Errorf("expected empty string when Authorization is not Bearer")
	}

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("Authorization", "Bearer my_secret_token_123")
	if BearerToken(req3) != "my_secret_token_123" {
		t.Errorf("expected 'my_secret_token_123', got %q", BearerToken(req3))
	}

	req4 := httptest.NewRequest(http.MethodGet, "/", nil)
	req4.Header.Set("Authorization", "Bearer    token_with_spaces   ")
	if BearerToken(req4) != "token_with_spaces" {
		t.Errorf("expected 'token_with_spaces', got %q", BearerToken(req4))
	}
}
