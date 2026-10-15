package roled

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	v1, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(v1) < 43 {
		t.Errorf("expected verifier length >= 43, got %d", len(v1))
	}

	// Verify URL safety (no '+', '/', or '=')
	if strings.ContainsAny(v1, "+/=") {
		t.Errorf("verifier contains invalid characters: %s", v1)
	}

	v2, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v1 == v2 {
		t.Errorf("expected unique verifiers, got duplicates")
	}
}

func TestComputeCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedHash := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(expectedHash[:])

	actual := ComputeCodeChallenge(verifier)
	if actual != expected {
		t.Errorf("expected code challenge %s, got %s", expected, actual)
	}

	// Known RFC 7636 Appendix B test vector:
	// verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
	// challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
	rfcVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcExpected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	rfcActual := ComputeCodeChallenge(rfcVerifier)
	if rfcActual != rfcExpected {
		t.Errorf("RFC 7636 test vector mismatch: expected %s, got %s", rfcExpected, rfcActual)
	}
}

func TestGenerateState(t *testing.T) {
	s1, err := GenerateState()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s1) == 0 {
		t.Errorf("expected non-empty state")
	}

	s2, err := GenerateState()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s1 == s2 {
		t.Errorf("expected unique states, got duplicates")
	}
}
