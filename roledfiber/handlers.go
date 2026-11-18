package roledfiber

import (
	"errors"
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/roledio/roled-go"
	"github.com/roledio/roled-go/web"
)

const (
	defaultLoginPath = "/login"
	defaultRedirect  = "/"
)

// Handler provides Fiber handlers and middleware for the Roled OAuth 2.0 PKCE
// login flow. It relies on the Fiber session middleware (session.New()) being
// registered before the auth routes; any fiber.Storage backend can be used.
type Handler struct {
	flow              *web.Flow
	loginPath         string
	onUnauthenticated fiber.Handler
	onCallbackSuccess fiber.Handler
	onLogoutSuccess   fiber.Handler
	onForbidden       fiber.Handler
}

// New creates a Handler for Fiber v3 from a configured Roled client.
func New(client *roled.Client, opts ...Option) *Handler {
	h := &Handler{
		flow:      web.NewFlow(client.Auth),
		loginPath: defaultLoginPath,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

// AuthSession loads the stored auth session for the request without requiring
// it to be authenticated. It returns an empty AuthSession when none exists.
func (h *Handler) AuthSession(c fiber.Ctx) (*roled.AuthSession, error) {
	sess, err := h.session(c)
	if err != nil {
		return nil, err
	}
	return web.LoadAuthSession(sess)
}

// Login starts the OAuth 2.0 PKCE flow: it stores a fresh state and code
// verifier in the session and redirects to the Roled authorization URL.
func (h *Handler) Login(c fiber.Ctx) error {
	sess, err := h.session(c)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	authorizeURL, err := h.flow.BeginLogin(c.Context(), sess)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not start login")
	}

	return c.Redirect().Status(fiber.StatusFound).To(authorizeURL)
}

// Callback completes the OAuth 2.0 PKCE flow: it validates the state, exchanges
// the authorization code for tokens, and stores them in the session.
func (h *Handler) Callback(c fiber.Ctx) error {
	sess, err := h.session(c)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	err = h.flow.CompleteLogin(c.Context(), sess, web.CallbackParams{
		Code:       c.Query("code"),
		State:      c.Query("state"),
		OAuthError: c.Query("error"),
	})
	if err != nil {
		switch {
		case errors.Is(err, web.ErrInvalidState), errors.Is(err, web.ErrOAuthProvider):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		case errors.Is(err, web.ErrTokenExchange):
			log.Printf("roled: %v", err)
			return fiber.NewError(fiber.StatusBadGateway, "could not exchange authorization code")
		default:
			return fiber.NewError(fiber.StatusInternalServerError, "could not complete login")
		}
	}

	if h.onCallbackSuccess != nil {
		return h.onCallbackSuccess(c)
	}
	return c.Redirect().Status(fiber.StatusFound).To(defaultRedirect)
}

// Logout revokes the stored tokens at Roled (best effort), clears the auth
// session, and redirects. Revocation failures are logged but never block
// local logout.
func (h *Handler) Logout(c fiber.Ctx) error {
	sess, err := h.session(c)
	if err != nil {
		log.Printf("roled: could not get session during logout: %v", err)
	} else if err := h.flow.Logout(c.Context(), sess); err != nil {
		log.Printf("roled: could not save session during logout: %v", err)
	}

	if h.onLogoutSuccess != nil {
		return h.onLogoutSuccess(c)
	}
	return c.Redirect().Status(fiber.StatusFound).To(defaultRedirect)
}
