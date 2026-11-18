package roledfiber

import "github.com/gofiber/fiber/v3"

// Option configures a Handler.
type Option func(*Handler)

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
func WithOnUnauthenticated(fn fiber.Handler) Option {
	return func(h *Handler) {
		h.onUnauthenticated = fn
	}
}

// WithOnCallbackSuccess runs after a successful OAuth callback instead of the
// default redirect to "/".
func WithOnCallbackSuccess(fn fiber.Handler) Option {
	return func(h *Handler) {
		h.onCallbackSuccess = fn
	}
}

// WithOnLogoutSuccess runs after logout instead of the default redirect to "/".
func WithOnLogoutSuccess(fn fiber.Handler) Option {
	return func(h *Handler) {
		h.onLogoutSuccess = fn
	}
}

// WithOnForbidden overrides the default behavior of RequirePermission and
// RequireRole when the authenticated user lacks the required permission or
// role. When nil, a plain 403 Forbidden response is written.
func WithOnForbidden(fn fiber.Handler) Option {
	return func(h *Handler) {
		h.onForbidden = fn
	}
}
