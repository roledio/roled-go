package roled

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AuthService provides methods for OAuth 2.0 PKCE, token exchange, and inspection.
type AuthService struct {
	client *Client
}

// AuthorizeURLParams contains parameters for building the OAuth 2.0 authorization URL.
type AuthorizeURLParams struct {
	// ClientID is the OAuth 2.0 client ID (defaults to client.ClientID()).
	ClientID string

	// RedirectURI is the OAuth 2.0 redirect URI (defaults to client.RedirectURI()).
	RedirectURI string

	// CodeChallenge is the Base64URL-encoded SHA256 code challenge for PKCE.
	CodeChallenge string

	// State is an opaque value used to maintain state between the request and the callback.
	State string

	// IsSignup sets whether the authorization screen should display the signup tab by default.
	IsSignup bool
}

// TokenResponse represents the data returned by the OAuth 2.0 token endpoint.
type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int    `json:"expires_in"`
	TokenType             string `json:"token_type"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in,omitempty"`
}

// ExchangeAuthorizationCodeParams contains parameters to exchange an authorization code for tokens.
type ExchangeAuthorizationCodeParams struct {
	// Code is the authorization code received from the callback.
	Code string

	// CodeVerifier is the PKCE code verifier generated before the authorization request.
	CodeVerifier string

	// RedirectURI is the redirect URI used in the authorization request (defaults to client.RedirectURI()).
	RedirectURI string

	// ClientID is the OAuth 2.0 client ID (defaults to client.ClientID()).
	ClientID string

	// State is the optional state parameter received in the callback.
	State string
}

// ClientCredentialsParams contains parameters for client credentials grant.
type ClientCredentialsParams struct {
	ClientID     string
	ClientSecret string
}

// RevokeTokenParams contains parameters for revoking an access or refresh token.
type RevokeTokenParams struct {
	// ClientID is the OAuth 2.0 client ID (defaults to client.ClientID()).
	ClientID string `json:"client_id"`

	// RefreshToken is the refresh token to revoke.
	RefreshToken string `json:"refresh_token"`

	// AccessToken is an optional Bearer access token to revoke alongside the refresh token.
	AccessToken string `json:"-"`
}

// TokenProjectSummary describes project info inside a token inspection response.
type TokenProjectSummary struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	LogoURL     *string `json:"logo_url"`
}

// TokenClientSummary describes client info inside a token inspection response.
type TokenClientSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TokenUserSummary describes user info inside a token inspection response.
type TokenUserSummary struct {
	ID             string  `json:"id"`
	DisplayName    string  `json:"display_name"`
	Email          *string `json:"email"`
	ExternalUserID *string `json:"external_user_id"`
	AvatarURL      *string `json:"avatar_url"`
}

// TokenRoleSummary describes role info inside a token inspection response.
type TokenRoleSummary struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// TokenInspection represents the details of an inspected access token.
type TokenInspection struct {
	ID          string              `json:"id"`
	IssuedAt    time.Time           `json:"issued_at"`
	ExpiresAt   time.Time           `json:"expires_at"`
	Project     TokenProjectSummary `json:"project"`
	Client      TokenClientSummary  `json:"client"`
	User        *TokenUserSummary   `json:"user,omitempty"`
	Role        *TokenRoleSummary   `json:"role,omitempty"`
	Permissions []string            `json:"permissions"`
}

// BuildAuthorizeURL constructs the OAuth 2.0 authorization URL for PKCE authentication.
func (s *AuthService) BuildAuthorizeURL(params AuthorizeURLParams) (string, error) {
	clientID := params.ClientID
	if clientID == "" {
		clientID = s.client.clientID
	}
	if clientID == "" {
		return "", fmt.Errorf("roled: client_id is required to build authorize URL")
	}

	redirectURI := params.RedirectURI
	if redirectURI == "" {
		redirectURI = s.client.redirectURI
	}
	if redirectURI == "" {
		return "", fmt.Errorf("roled: redirect_uri is required to build authorize URL")
	}

	if params.CodeChallenge == "" {
		return "", fmt.Errorf("roled: code_challenge is required for PKCE authorization URL")
	}

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge_method", "S256")
	q.Set("code_challenge", params.CodeChallenge)
	if params.State != "" {
		q.Set("state", params.State)
	}
	if params.IsSignup {
		q.Set("signup", "true")
	}

	authorizeURL := s.client.baseURL.ResolveReference(&url.URL{
		Path:     "authorize",
		RawQuery: q.Encode(),
	})

	return authorizeURL.String(), nil
}

// ExchangeAuthorizationCode exchanges an authorization code and PKCE code verifier for tokens.
func (s *AuthService) ExchangeAuthorizationCode(
	ctx context.Context,
	params ExchangeAuthorizationCodeParams,
) (*TokenResponse, error) {
	clientID := params.ClientID
	if clientID == "" {
		clientID = s.client.clientID
	}
	if clientID == "" {
		return nil, fmt.Errorf("roled: client_id is required for token exchange")
	}

	redirectURI := params.RedirectURI
	if redirectURI == "" {
		redirectURI = s.client.redirectURI
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("roled: redirect_uri is required for token exchange")
	}

	if params.Code == "" {
		return nil, fmt.Errorf("roled: authorization code is required for token exchange")
	}
	if params.CodeVerifier == "" {
		return nil, fmt.Errorf("roled: code_verifier is required for PKCE token exchange")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("authorization_code", params.Code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", params.CodeVerifier)
	if params.State != "" {
		form.Set("state", params.State)
	}

	var tokenResp TokenResponse
	_, err := s.client.execute(ctx, http.MethodPost, "/api/v1/tokens", nil, form, &tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// RefreshToken exchanges a valid refresh token for a new access token and refresh token.
func (s *AuthService) RefreshToken(
	ctx context.Context,
	refreshToken string,
	clientID ...string,
) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("roled: refresh_token is required")
	}

	cid := s.client.clientID
	if len(clientID) > 0 && clientID[0] != "" {
		cid = clientID[0]
	}
	if cid == "" {
		return nil, fmt.Errorf("roled: client_id is required for token refresh")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", cid)
	form.Set("refresh_token", refreshToken)

	var tokenResp TokenResponse
	_, err := s.client.execute(ctx, http.MethodPost, "/api/v1/tokens", nil, form, &tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// ExchangeClientCredentials obtains an access token using OAuth 2.0 client credentials grant.
func (s *AuthService) ExchangeClientCredentials(
	ctx context.Context,
	params ...ClientCredentialsParams,
) (*TokenResponse, error) {
	cid := s.client.clientID
	secret := s.client.clientSecret

	if len(params) > 0 {
		if params[0].ClientID != "" {
			cid = params[0].ClientID
		}
		if params[0].ClientSecret != "" {
			secret = params[0].ClientSecret
		}
	}

	if cid == "" || secret == "" {
		return nil, fmt.Errorf("roled: client_id and client_secret are required for client credentials grant")
	}

	basicAuth := base64.StdEncoding.EncodeToString([]byte(cid + ":" + secret))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	var tokenResp TokenResponse
	_, err := s.client.execute(
		ctx,
		http.MethodPost,
		"/api/v1/tokens",
		nil,
		form,
		&tokenResp,
		WithHeader("Authorization", "Basic "+basicAuth),
	)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// InspectToken inspects the given access token and returns associated metadata, user, role, and permissions.
func (s *AuthService) InspectToken(ctx context.Context, accessToken string) (*TokenInspection, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("roled: access token is required for inspection")
	}

	var inspection TokenInspection
	_, err := s.client.execute(
		ctx,
		http.MethodGet,
		"/api/v1/tokens/current",
		nil,
		nil,
		&inspection,
		WithRequestToken(accessToken),
	)
	if err != nil {
		return nil, err
	}

	return &inspection, nil
}

// RevokeToken revokes an access token and/or refresh token.
func (s *AuthService) RevokeToken(ctx context.Context, params RevokeTokenParams) error {
	cid := params.ClientID
	if cid == "" {
		cid = s.client.clientID
	}
	if cid == "" {
		return fmt.Errorf("roled: client_id is required for token revocation")
	}
	if params.RefreshToken == "" {
		return fmt.Errorf("roled: refresh_token is required for token revocation")
	}

	payload := struct {
		ClientID     string `json:"client_id"`
		RefreshToken string `json:"refresh_token"`
	}{
		ClientID:     cid,
		RefreshToken: params.RefreshToken,
	}

	var reqOpts []RequestOption
	if params.AccessToken != "" {
		reqOpts = append(reqOpts, WithRequestToken(params.AccessToken))
	}

	_, err := s.client.execute(ctx, http.MethodPost, "/api/v1/tokens/current/revoke", nil, payload, nil, reqOpts...)
	return err
}
