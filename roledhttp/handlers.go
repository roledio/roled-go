package roledhttp

import (
	"errors"
	"log"
	"net/http"

	"github.com/roledio/roled-go"
	"github.com/roledio/roled-go/web"
)

const (
	defaultSessionName = "roled_session"
	defaultLoginPath   = "/login"
	defaultRedirect    = "/"
)

// Handler provides net/http handlers and middleware for the Roled OAuth 2.0
// PKCE login flow.
type Handler struct {
	flow              *web.Flow
	store             Store
	loginPath         string
	onUnauthenticated http.HandlerFunc
	onCallbackSuccess http.HandlerFunc
	onLogoutSuccess   http.HandlerFunc
	onForbidden       http.HandlerFunc

	sessionSecret []byte
	cookieOpts    []CookieOption
}

// New creates a Handler for the net/http standard library from a configured
// Roled client.
//
// By default sessions are stored in an encrypted cookie; a secret is required
// via WithSessionSecret. A custom Store can be provided with WithSessionStore.
func New(client *roled.Client, opts ...Option) (*Handler, error) {
	h := &Handler{
		flow:      web.NewFlow(client.Auth),
		loginPath: defaultLoginPath,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}

	if h.store == nil {
		if len(h.sessionSecret) == 0 {
			return nil, errors.New("nethttp: session secret is required (use WithSessionSecret) or provide a custom store (WithSessionStore)")
		}
		h.store = NewCookieStore(h.sessionSecret, h.cookieOpts...)
	}

	return h, nil
}

// AuthSession loads the stored auth session for the request without requiring
// it to be authenticated. It returns an empty AuthSession when none exists.
func (h *Handler) AuthSession(r *http.Request) (*roled.AuthSession, error) {
	sess, err := h.store.Open(r, nil)
	if err != nil {
		return nil, err
	}
	return web.LoadAuthSession(sess)
}

// session returns the request's session.
func (h *Handler) session(r *http.Request, w http.ResponseWriter) (web.Session, error) {
	return h.store.Open(r, w)
}

// Login starts the OAuth 2.0 PKCE flow: it stores a fresh state and code
// verifier in the session and redirects to the Roled authorization URL.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	sess, err := h.session(r, w)
	if err != nil {
		http.Error(w, "could not get session", http.StatusInternalServerError)
		return
	}

	authorizeURL, err := h.flow.BeginLogin(r.Context(), sess)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// Callback completes the OAuth 2.0 PKCE flow: it validates the state, exchanges
// the authorization code for tokens, and stores them in the session.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	sess, err := h.session(r, w)
	if err != nil {
		http.Error(w, "could not get session", http.StatusInternalServerError)
		return
	}

	err = h.flow.CompleteLogin(r.Context(), sess, web.CallbackParams{
		Code:       r.URL.Query().Get("code"),
		State:      r.URL.Query().Get("state"),
		OAuthError: r.URL.Query().Get("error"),
	})
	if err != nil {
		switch {
		case errors.Is(err, web.ErrInvalidState), errors.Is(err, web.ErrOAuthProvider):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, web.ErrTokenExchange):
			log.Printf("roled: %v", err)
			http.Error(w, "could not exchange authorization code", http.StatusBadGateway)
		default:
			http.Error(w, "could not complete login", http.StatusInternalServerError)
		}
		return
	}

	if h.onCallbackSuccess != nil {
		h.onCallbackSuccess(w, r)
		return
	}
	http.Redirect(w, r, defaultRedirect, http.StatusFound)
}

// Logout revokes the stored tokens at Roled (best effort), clears the auth
// session, and redirects. Revocation failures are logged but never block
// local logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	sess, err := h.session(r, w)
	if err != nil {
		log.Printf("roled: could not get session during logout: %v", err)
	} else if err := h.flow.Logout(r.Context(), sess); err != nil {
		log.Printf("roled: could not save session during logout: %v", err)
	}

	if h.onLogoutSuccess != nil {
		h.onLogoutSuccess(w, r)
		return
	}
	http.Redirect(w, r, defaultRedirect, http.StatusFound)
}
