package roledfiber

import (
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/roledio/roled-go"
)

const (
	authSessionLocalsKey     = "roled_auth_session"
	tokenInspectionLocalsKey = "roled_token_inspection"
)

// AuthSessionFromContext returns the auth session injected by RequireAuth.
func AuthSessionFromContext(c fiber.Ctx) *roled.AuthSession {
	sess, _ := c.Locals(authSessionLocalsKey).(*roled.AuthSession)
	return sess
}

// TokenInspectionFromContext returns the token inspection injected by
// RequireAuth.
func TokenInspectionFromContext(c fiber.Ctx) *roled.TokenInspection {
	inspection, _ := c.Locals(tokenInspectionLocalsKey).(*roled.TokenInspection)
	return inspection
}

// RequireAuth returns middleware that ensures the request carries a valid Roled
// session. It refreshes expired access tokens, inspects the token, and stores
// the auth session and token inspection in c.Locals. Unauthenticated or
// expired sessions are redirected to the login path (or handled by
// WithOnUnauthenticated).
func (h *Handler) RequireAuth(next fiber.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		sess, err := h.session(c)
		if err != nil {
			log.Printf("roled: could not get session: %v", err)
			return h.unauthorized(c)
		}

		authSess, inspection, err := h.flow.Authenticate(c.Context(), sess)
		if err != nil {
			log.Printf("roled: authentication failed: %v", err)
			return h.unauthorized(c)
		}

		c.Locals(authSessionLocalsKey, authSess)
		c.Locals(tokenInspectionLocalsKey, inspection)

		return next(c)
	}
}

// RequirePermission returns middleware that requires the authenticated token to
// carry the given permission. It must be chained after RequireAuth so the token
// inspection is available in the context locals.
func (h *Handler) RequirePermission(permission string) func(fiber.Handler) fiber.Handler {
	return func(next fiber.Handler) fiber.Handler {
		return func(c fiber.Ctx) error {
			inspection := TokenInspectionFromContext(c)
			if inspection == nil {
				return h.unauthorized(c)
			}
			for _, p := range inspection.Permissions {
				if p == permission {
					return next(c)
				}
			}
			return h.forbidden(c)
		}
	}
}

// RequireRole returns middleware that requires the authenticated token to
// belong to the given role code. It must be chained after RequireAuth so the
// token inspection is available in the context locals.
func (h *Handler) RequireRole(roleCode string) func(fiber.Handler) fiber.Handler {
	return func(next fiber.Handler) fiber.Handler {
		return func(c fiber.Ctx) error {
			inspection := TokenInspectionFromContext(c)
			if inspection == nil {
				return h.unauthorized(c)
			}
			if inspection.Role != nil && inspection.Role.Code == roleCode {
				return next(c)
			}
			return h.forbidden(c)
		}
	}
}

func (h *Handler) unauthorized(c fiber.Ctx) error {
	if h.onUnauthenticated != nil {
		return h.onUnauthenticated(c)
	}
	return c.Redirect().Status(fiber.StatusFound).To(h.loginPath)
}

func (h *Handler) forbidden(c fiber.Ctx) error {
	if h.onForbidden != nil {
		return h.onForbidden(c)
	}
	return c.SendStatus(fiber.StatusForbidden)
}
