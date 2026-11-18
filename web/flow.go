package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/roledio/roled-go"
)

const defaultRefreshSkew = 30 * time.Second

var (
	// ErrOAuthProvider is returned when the OAuth provider redirects back with
	// an error parameter (e.g. the user denied consent).
	ErrOAuthProvider = errors.New("web: OAuth provider returned an error")

	// ErrInvalidState is returned when the callback state is missing or does
	// not match the state stored in the session.
	ErrInvalidState = errors.New("web: invalid OAuth state or missing code")

	// ErrTokenExchange wraps failures of the authorization code exchange.
	ErrTokenExchange = errors.New("web: failed to exchange authorization code")

	// ErrUnauthenticated is returned by Authenticate when the session is
	// missing, expired beyond refresh, or rejected by Roled. The stored
	// session has already been cleared in this case.
	ErrUnauthenticated = errors.New("web: not authenticated")
)

// Flow implements the framework-agnostic parts of the Roled OAuth 2.0 PKCE
// login flow: starting the login, completing the callback, logging out, and
// authenticating requests with automatic token refresh.
type Flow struct {
	auth        *roled.AuthService
	refreshSkew time.Duration
}

// FlowOption configures a Flow.
type FlowOption func(*Flow)

// WithRefreshSkew sets how long before the access token expiry a refresh is
// triggered. Defaults to 30 seconds.
func WithRefreshSkew(d time.Duration) FlowOption {
	return func(f *Flow) {
		if d > 0 {
			f.refreshSkew = d
		}
	}
}

// NewFlow creates a Flow bound to the given AuthService.
func NewFlow(auth *roled.AuthService, opts ...FlowOption) *Flow {
	f := &Flow{
		auth:        auth,
		refreshSkew: defaultRefreshSkew,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(f)
		}
	}
	return f
}

// CallbackParams carries the parameters returned by the OAuth provider to the
// callback endpoint.
type CallbackParams struct {
	Code       string
	State      string
	OAuthError string
}

// BeginLogin generates a fresh OAuth state and PKCE verifier, stores them in
// the session, and returns the Roled authorization URL to redirect to.
func (f *Flow) BeginLogin(ctx context.Context, sess Session) (string, error) {
	authSess, err := LoadAuthSession(sess)
	if err != nil {
		return "", err
	}

	state, err := roled.GenerateState()
	if err != nil {
		return "", err
	}

	codeVerifier, err := roled.GenerateCodeVerifier()
	if err != nil {
		return "", err
	}

	now := time.Now()
	if authSess.CreatedAt.IsZero() {
		authSess.CreatedAt = now
	}
	authSess.OAuthState = state
	authSess.PKCEVerifier = codeVerifier
	authSess.UpdatedAt = now

	if err := SetAuthSession(sess, authSess); err != nil {
		return "", err
	}
	if err := sess.Save(); err != nil {
		return "", err
	}

	return f.auth.BuildAuthorizeURL(roled.AuthorizeURLParams{
		State:         state,
		CodeChallenge: roled.ComputeCodeChallenge(codeVerifier),
	})
}

// CompleteLogin validates the callback parameters, exchanges the
// authorization code for tokens, stores them in the session, and clears the
// one-time OAuth state and PKCE verifier.
func (f *Flow) CompleteLogin(ctx context.Context, sess Session, params CallbackParams) error {
	if params.OAuthError != "" {
		return fmt.Errorf("%w: %s", ErrOAuthProvider, params.OAuthError)
	}

	authSess, err := LoadAuthSession(sess)
	if err != nil {
		return err
	}

	expectedState := authSess.OAuthState
	stateValid := subtle.ConstantTimeCompare([]byte(params.State), []byte(expectedState)) == 1
	if params.State == "" || expectedState == "" || !stateValid || params.Code == "" {
		return ErrInvalidState
	}

	resp, err := f.auth.ExchangeAuthorizationCode(ctx, roled.ExchangeAuthorizationCodeParams{
		Code:         params.Code,
		CodeVerifier: authSess.PKCEVerifier,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTokenExchange, err)
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

	if err := SetAuthSession(sess, authSess); err != nil {
		return err
	}
	return sess.Save()
}

// Logout revokes the stored tokens at Roled on a best-effort basis, clears the
// auth session, and persists it. Revocation failures are logged but never
// block local logout.
func (f *Flow) Logout(ctx context.Context, sess Session) error {
	authSess, err := LoadAuthSession(sess)
	if err != nil {
		log.Printf("roled: could not load session during logout: %v", err)
	} else if authSess.IsAuthenticated() {
		if revokeErr := f.auth.RevokeToken(ctx, roled.RevokeTokenParams{
			AccessToken:  authSess.AccessToken,
			RefreshToken: authSess.RefreshToken,
		}); revokeErr != nil {
			log.Printf("roled: token revocation failed during logout: %v", revokeErr)
		}
	}

	ClearAuthSession(sess)
	return sess.Save()
}

// Authenticate verifies the session is authenticated, refreshing the access
// token when needed, and inspects the token against Roled. On success it
// returns the auth session and token inspection. When the session cannot be
// authenticated it is cleared, persisted, and ErrUnauthenticated is returned.
func (f *Flow) Authenticate(ctx context.Context, sess Session) (*roled.AuthSession, *roled.TokenInspection, error) {
	authSess, err := LoadAuthSession(sess)
	if err != nil || !authSess.IsAuthenticated() {
		return nil, nil, ErrUnauthenticated
	}

	refreshed := false

	if !authSess.AccessTokenValid(f.refreshSkew) {
		if err := f.refreshSession(ctx, authSess); err != nil {
			f.failSession(sess)
			return nil, nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
		}
		refreshed = true
	}

	inspection, err := f.auth.InspectToken(ctx, authSess.AccessToken)
	if err != nil {
		// The locally known expiry may be slightly out of sync with Roled.
		// If the token is rejected, refresh once and retry.
		if refreshErr := f.refreshSession(ctx, authSess); refreshErr != nil {
			f.failSession(sess)
			return nil, nil, fmt.Errorf("%w: %v / %v", ErrUnauthenticated, err, refreshErr)
		}
		refreshed = true

		inspection, err = f.auth.InspectToken(ctx, authSess.AccessToken)
		if err != nil {
			f.failSession(sess)
			return nil, nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
		}
	}

	// Only persist the session when tokens were actually refreshed.
	if refreshed {
		if err := SetAuthSession(sess, authSess); err == nil {
			if saveErr := sess.Save(); saveErr != nil {
				log.Printf("roled: could not save refreshed session: %v", saveErr)
			}
		}
	}

	return authSess, inspection, nil
}

// failSession clears the stored auth session and persists it.
func (f *Flow) failSession(sess Session) {
	ClearAuthSession(sess)
	if err := sess.Save(); err != nil {
		log.Printf("roled: could not clear failed session: %v", err)
	}
}

func (f *Flow) refreshSession(ctx context.Context, authSess *roled.AuthSession) error {
	if authSess.RefreshToken == "" {
		return errors.New("roled: missing refresh token")
	}
	if authSess.RefreshTokenExpired() {
		return errors.New("roled: refresh token expired")
	}

	tokens, err := f.auth.RefreshToken(ctx, authSess.RefreshToken)
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
