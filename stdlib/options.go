package stdlib

import "net/http"

// Option configures a Handler.
type Option func(*Handler)

// WithSessionName sets the session/cookie name used to store the auth session.
func WithSessionName(name string) Option {
	return func(h *Handler) {
		if name != "" {
			h.sessionName = name
		}
	}
}

// WithLoginPath sets the path users are redirected to when authentication is
// required but missing or expired. Defaults to "/login".
func WithLoginPath(path string) Option {
	return func(h *Handler) {
		if path != "" {
			h.loginPath = path
		}
	}
}

// WithOnUnauthenticated overrides the default behavior of RequireAuth when a
// request is not authenticated. When nil, users are redirected to the login
// path.
func WithOnUnauthenticated(fn http.HandlerFunc) Option {
	return func(h *Handler) {
		h.onUnauthenticated = fn
	}
}

// WithOnCallbackSuccess runs after a successful OAuth callback instead of the
// default redirect to "/".
func WithOnCallbackSuccess(fn http.HandlerFunc) Option {
	return func(h *Handler) {
		h.onCallbackSuccess = fn
	}
}

// WithOnLogoutSuccess runs after logout instead of the default redirect to "/".
func WithOnLogoutSuccess(fn http.HandlerFunc) Option {
	return func(h *Handler) {
		h.onLogoutSuccess = fn
	}
}

// WithOnForbidden overrides the default behavior of RequirePermission and
// RequireRole when the authenticated user lacks the required permission or
// role. When nil, a plain 403 Forbidden response is written.
func WithOnForbidden(fn http.HandlerFunc) Option {
	return func(h *Handler) {
		h.onForbidden = fn
	}
}
