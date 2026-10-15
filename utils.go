package roled

import (
	"net/http"
	"strings"
)

// BearerToken extracts the Bearer token from an incoming HTTP request's Authorization header.
// It returns an empty string if the header is missing, malformed, or does not start with "Bearer ".
func BearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[len("Bearer "):])
	}
	return ""
}
