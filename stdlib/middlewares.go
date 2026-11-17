package stdlib

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/roledio/roled-go"
)

const refreshSkew = 30 * time.Second

var errRefreshTokenExpired = errors.New("roled: refresh token expired")

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
		sess, err := h.sessionStore.Get(r, h.sessionName)
		if err != nil {
			log.Printf("roled: could not get session: %v", err)
			h.unauthorized(w, r)
			return
		}

		authSess, err := loadAuthSession(sess)
		if err != nil || !authSess.IsAuthenticated() {
			h.unauthorized(w, r)
			return
		}

		refreshed := false

		if !authSess.AccessTokenValid(refreshSkew) {
			if err := h.refreshSession(r.Context(), authSess); err != nil {
				log.Printf("roled: authentication failed: %v", err)
				h.failSession(w, r, sess)
				return
			}
			refreshed = true
		}

		inspection, err := h.authService.InspectToken(r.Context(), authSess.AccessToken)
		if err != nil {
			// The locally known expiry may be slightly out of sync with Roled.
			// If the token is rejected, refresh once and retry.
			if refreshErr := h.refreshSession(r.Context(), authSess); refreshErr != nil {
				log.Printf("roled: token inspection failed and refresh failed: %v / %v", err, refreshErr)
				h.failSession(w, r, sess)
				return
			}
			refreshed = true

			inspection, err = h.authService.InspectToken(r.Context(), authSess.AccessToken)
			if err != nil {
				log.Printf("roled: token inspection failed after refresh: %v", err)
				h.failSession(w, r, sess)
				return
			}
		}

		// Only persist the session when tokens were actually refreshed.
		if refreshed {
			if err := setAuthSession(sess, authSess); err != nil {
				log.Printf("roled: could not save refreshed session: %v", err)
			} else if err := sess.Save(r, w); err != nil {
				log.Printf("roled: could not save refreshed session: %v", err)
			}
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

// failSession clears the stored auth session and redirects to login.
func (h *Handler) failSession(w http.ResponseWriter, r *http.Request, sess *sessions.Session) {
	clearAuthSession(sess)
	if err := sess.Save(r, w); err != nil {
		log.Printf("roled: could not clear failed session: %v", err)
	}
	h.unauthorized(w, r)
}

func (h *Handler) refreshSession(ctx context.Context, authSess *roled.AuthSession) error {
	if authSess.RefreshToken == "" {
		return errors.New("roled: missing refresh token")
	}
	if authSess.RefreshTokenExpired() {
		return errRefreshTokenExpired
	}

	tokens, err := h.authService.RefreshToken(ctx, authSess.RefreshToken)
	if err != nil {
		return err
	}

	now := time.Now()
	authSess.AccessToken = tokens.AccessToken
	authSess.AccessTokenExpiresAt = now.Add(time.Duration(tokens.ExpiresIn) * time.Second)

	// Roled rotates refresh tokens. Always replace the old refresh token.
	if tokens.RefreshToken != "" {
		authSess.RefreshToken = tokens.RefreshToken
	}
	if tokens.RefreshTokenExpiresIn > 0 {
		authSess.RefreshTokenExpiresAt = now.Add(time.Duration(tokens.RefreshTokenExpiresIn) * time.Second)
	}
	authSess.UpdatedAt = now

	return nil
}
