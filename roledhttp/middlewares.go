package roledhttp

import (
	"context"
	"log"
	"net/http"

	"github.com/roledio/roled-go"
)

type contextKey string

const (
	authSessionContextKey     contextKey = "roled_auth_session"
	tokenInspectionContextKey contextKey = "roled_token_inspection"
)

// AuthSessionFromContext returns the auth session injected by RequireAuth.
func AuthSessionFromContext(ctx context.Context) *roled.AuthSession {
	sess, _ := ctx.Value(authSessionContextKey).(*roled.AuthSession)
	return sess
}

// TokenInspectionFromContext returns the token inspection injected by
// RequireAuth.
func TokenInspectionFromContext(ctx context.Context) *roled.TokenInspection {
	inspection, _ := ctx.Value(tokenInspectionContextKey).(*roled.TokenInspection)
	return inspection
}

// RequireAuth returns middleware that ensures the request carries a valid Roled
// session. It refreshes expired access tokens, inspects the token, and injects
// the auth session and token inspection into the request context. Unauthenticated
// or expired sessions are redirected to the login path (or handled by
// WithOnUnauthenticated).
func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.session(r, w)
		if err != nil {
			log.Printf("roled: could not get session: %v", err)
			h.unauthorized(w, r)
			return
		}

		authSess, inspection, err := h.flow.Authenticate(r.Context(), sess)
		if err != nil {
			log.Printf("roled: authentication failed: %v", err)
			h.unauthorized(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), authSessionContextKey, authSess)
		ctx = context.WithValue(ctx, tokenInspectionContextKey, inspection)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission returns middleware that requires the authenticated token to
// carry the given permission. It must be chained after RequireAuth so the token
// inspection is available in the request context.
func (h *Handler) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inspection := TokenInspectionFromContext(r.Context())
			if inspection == nil {
				h.unauthorized(w, r)
				return
			}
			for _, p := range inspection.Permissions {
				if p == permission {
					next.ServeHTTP(w, r)
					return
				}
			}
			h.forbidden(w, r)
		})
	}
}

// RequireRole returns middleware that requires the authenticated token to
// belong to the given role code. It must be chained after RequireAuth so the
// token inspection is available in the request context.
func (h *Handler) RequireRole(roleCode string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inspection := TokenInspectionFromContext(r.Context())
			if inspection == nil {
				h.unauthorized(w, r)
				return
			}
			if inspection.Role != nil && inspection.Role.Code == roleCode {
				next.ServeHTTP(w, r)
				return
			}
			h.forbidden(w, r)
		})
	}
}

func (h *Handler) unauthorized(w http.ResponseWriter, r *http.Request) {
	if h.onUnauthenticated != nil {
		h.onUnauthenticated(w, r)
		return
	}
	http.Redirect(w, r, h.loginPath, http.StatusFound)
}

func (h *Handler) forbidden(w http.ResponseWriter, r *http.Request) {
	if h.onForbidden != nil {
		h.onForbidden(w, r)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}
