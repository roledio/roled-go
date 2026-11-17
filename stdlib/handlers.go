package stdlib

import (
	"crypto/subtle"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/roledio/roled-go"
)

const (
	defaultSessionName = "roled_session"
	defaultLoginPath   = "/login"
	defaultRedirect    = "/"
)

// Handler provides net/http handlers and middleware for the Roled OAuth 2.0
// PKCE login flow. Session data is stored through a gorilla/sessions Store,
// which can be swapped for any compatible implementation.
type Handler struct {
	authService       *roled.AuthService
	sessionStore      sessions.Store
	sessionName       string
	loginPath         string
	onUnauthenticated http.HandlerFunc
	onCallbackSuccess http.HandlerFunc
	onLogoutSuccess   http.HandlerFunc
	onForbidden       http.HandlerFunc
}

// New creates a Handler for the net/http standard library.
func New(
	authService *roled.AuthService,
	sessionStore sessions.Store,
	opts ...Option,
) *Handler {
	h := &Handler{
		authService:  authService,
		sessionStore: sessionStore,
		sessionName:  defaultSessionName,
		loginPath:    defaultLoginPath,
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
func (h *Handler) AuthSession(r *http.Request) (*roled.AuthSession, error) {
	sess, err := h.sessionStore.Get(r, h.sessionName)
	if err != nil {
		return nil, err
	}
	return loadAuthSession(sess)
}

// Login starts the OAuth 2.0 PKCE flow: it stores a fresh state and code
// verifier in the session and redirects to the Roled authorization URL.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sessionStore.Get(r, h.sessionName)
	if err != nil {
		http.Error(w, "could not get session", http.StatusInternalServerError)
		return
	}

	authSess, err := loadAuthSession(sess)
	if err != nil {
		http.Error(w, "could not load session", http.StatusInternalServerError)
		return
	}

	state, err := roled.GenerateState()
	if err != nil {
		http.Error(w, "could not generate state", http.StatusInternalServerError)
		return
	}

	codeVerifier, err := roled.GenerateCodeVerifier()
	if err != nil {
		http.Error(w, "could not generate code verifier", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	if authSess.CreatedAt.IsZero() {
		authSess.CreatedAt = now
	}
	authSess.OAuthState = state
	authSess.PKCEVerifier = codeVerifier
	authSess.UpdatedAt = now

	if err := setAuthSession(sess, authSess); err != nil {
		http.Error(w, "could not save session", http.StatusInternalServerError)
		return
	}
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "could not save session", http.StatusInternalServerError)
		return
	}

	codeChallenge := roled.ComputeCodeChallenge(codeVerifier)
	authorizeURL, err := h.authService.BuildAuthorizeURL(roled.AuthorizeURLParams{
		State:         state,
		CodeChallenge: codeChallenge,
	})
	if err != nil {
		http.Error(w, "could not build authorize URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// Callback completes the OAuth 2.0 PKCE flow: it validates the state, exchanges
// the authorization code for tokens, and stores them in the session.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sessionStore.Get(r, h.sessionName)
	if err != nil {
		http.Error(w, "could not get session", http.StatusInternalServerError)
		return
	}

	authSess, err := loadAuthSession(sess)
	if err != nil {
		http.Error(w, "could not load session", http.StatusInternalServerError)
		return
	}

	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		http.Error(w, "oauth error: "+oauthErr, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	expectedState := authSess.OAuthState

	stateValid := subtle.ConstantTimeCompare([]byte(state), []byte(expectedState)) == 1
	if state == "" || expectedState == "" || !stateValid || code == "" {
		http.Error(w, "invalid OAuth state or code", http.StatusBadRequest)
		return
	}

	resp, err := h.authService.ExchangeAuthorizationCode(r.Context(), roled.ExchangeAuthorizationCodeParams{
		Code:         code,
		CodeVerifier: authSess.PKCEVerifier,
	})
	if err != nil {
		log.Printf("roled: authorization code exchange failed: %v", err)
		http.Error(w, "could not exchange authorization code", http.StatusBadGateway)
		return
	}

	now := time.Now()
	authSess.AccessToken = resp.AccessToken
	authSess.AccessTokenExpiresAt = now.Add(time.Duration(resp.ExpiresIn) * time.Second)
	authSess.RefreshToken = resp.RefreshToken
	authSess.RefreshTokenExpiresAt = now.Add(time.Duration(resp.RefreshTokenExpiresIn) * time.Second)

	// OAuth state and the PKCE verifier are one-time values.
	authSess.OAuthState = ""
	authSess.PKCEVerifier = ""
	authSess.UpdatedAt = now

	if err := setAuthSession(sess, authSess); err != nil {
		http.Error(w, "could not save session", http.StatusInternalServerError)
		return
	}
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "could not save session", http.StatusInternalServerError)
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
	sess, err := h.sessionStore.Get(r, h.sessionName)
	if err != nil {
		log.Printf("roled: could not get session during logout: %v", err)
	} else {
		if authSess, loadErr := loadAuthSession(sess); loadErr != nil {
			log.Printf("roled: could not load session during logout: %v", loadErr)
		} else if authSess.IsAuthenticated() {
			if revokeErr := h.authService.RevokeToken(r.Context(), roled.RevokeTokenParams{
				AccessToken:  authSess.AccessToken,
				RefreshToken: authSess.RefreshToken,
			}); revokeErr != nil {
				log.Printf("roled: token revocation failed during logout: %v", revokeErr)
			}
		}

		clearAuthSession(sess)
		if saveErr := sess.Save(r, w); saveErr != nil {
			log.Printf("roled: could not save session during logout: %v", saveErr)
		}
	}

	if h.onLogoutSuccess != nil {
		h.onLogoutSuccess(w, r)
		return
	}
	http.Redirect(w, r, defaultRedirect, http.StatusFound)
}
