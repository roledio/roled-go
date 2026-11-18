package roledhttp

import (
	"net/http"
)

// Option configures a Handler.
type Option func(*Handler)

// WithSessionSecret sets the secret used to encrypt and sign the default
// cookie session store. Required unless WithSessionStore is used.
func WithSessionSecret(secret []byte) Option {
	return func(h *Handler) {
		h.sessionSecret = secret
	}
}

// WithSessionStore replaces the default cookie session store with a custom
// Store implementation (e.g. Redis or database backed).
func WithSessionStore(store Store) Option {
	return func(h *Handler) {
		h.store = store
	}
}

// WithCookie applies CookieOptions to the default cookie session store. It has
// no effect when WithSessionStore is used.
func WithCookie(opts ...CookieOption) Option {
	return func(h *Handler) {
		h.cookieOpts = append(h.cookieOpts, opts...)
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
