package roled

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateCodeVerifier generates a cryptographically secure random code verifier
// according to RFC 7636 for PKCE (Proof Key for Code Exchange).
// It returns a 43-character URL-safe string.
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("roled: failed to generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ComputeCodeChallenge computes the S256 code challenge for a given code verifier
// according to RFC 7636.
//
//	code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
func ComputeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GenerateState generates a cryptographically secure random state parameter
// used to prevent CSRF attacks in OAuth 2.0 flows.
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("roled: failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
