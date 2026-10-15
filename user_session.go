package roled

import (
	"context"
	"fmt"
	"sync"
)

// UserSessionClient is a stateful client bound to a user's access and refresh tokens.
// It wraps user-scoped endpoints with automatic 401 Unauthorized token refresh and retry.
// It is safe for concurrent use by multiple goroutines.
type UserSessionClient struct {
	client       *Client
	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	isRefreshed  bool
}

// NewUserSession creates a new stateful UserSessionClient.
func NewUserSession(client *Client, accessToken, refreshToken string) *UserSessionClient {
	return &UserSessionClient{
		client:       client,
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}
}

// Tokens returns the current access and refresh tokens.
// If the tokens were automatically refreshed during API calls, the refreshed values are returned.
func (s *UserSessionClient) Tokens() (accessToken, refreshToken string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessToken, s.refreshToken
}

// AccessToken returns the current access token.
func (s *UserSessionClient) AccessToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessToken
}

// RefreshToken returns the current refresh token.
func (s *UserSessionClient) RefreshToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshToken
}

// IsRefreshed returns true if the tokens were refreshed during this session client's lifetime.
// Web applications and backend services can use this to detect when new tokens should be
// persisted to storage or user session cookies.
func (s *UserSessionClient) IsRefreshed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRefreshed
}

// execute executes an action with the current access token. If a 401 Unauthorized error occurs,
// it attempts to refresh the access token once using the refresh token and then retries the action.
func (s *UserSessionClient) execute(ctx context.Context, action func(token string) error) error {
	s.mu.RLock()
	token := s.accessToken
	s.mu.RUnlock()

	err := action(token)
	if err == nil || !IsUnauthorized(err) {
		return err
	}

	// Token may be expired; acquire write lock to refresh
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double check if another goroutine has already refreshed the token
	if s.accessToken != token {
		// Try with the already refreshed token
		err = action(s.accessToken)
		if err == nil || !IsUnauthorized(err) {
			return err
		}
	}

	if s.refreshToken == "" {
		return err // Cannot refresh without refresh token
	}

	tokenData, refreshErr := s.client.Auth.RefreshToken(ctx, s.refreshToken)
	if refreshErr != nil {
		// Return the original unauthorized error wrapped or directly
		return fmt.Errorf("roled: automatic token refresh failed (%w): %w", refreshErr, err)
	}

	s.accessToken = tokenData.AccessToken
	if tokenData.RefreshToken != "" {
		s.refreshToken = tokenData.RefreshToken
	}
	s.isRefreshed = true

	// Retry action with the new access token
	return action(s.accessToken)
}

// GetCurrentUser retrieves the current authenticated user's profile.
func (s *UserSessionClient) GetCurrentUser(ctx context.Context, opts ...UserOption) (*UserDetails, error) {
	var user *UserDetails
	err := s.execute(ctx, func(token string) error {
		var reqErr error
		user, reqErr = s.client.Users.GetCurrent(ctx, token, opts...)
		return reqErr
	})
	return user, err
}

// UpdateCurrentUser updates profile details for the authenticated user.
func (s *UserSessionClient) UpdateCurrentUser(
	ctx context.Context,
	params UpdateCurrentUserParams,
) (*UserDetails, error) {
	var user *UserDetails
	err := s.execute(ctx, func(token string) error {
		var reqErr error
		user, reqErr = s.client.Users.UpdateCurrent(ctx, token, params)
		return reqErr
	})
	return user, err
}

// InspectToken inspects the active access token and returns its metadata, user, role, and permissions.
func (s *UserSessionClient) InspectToken(ctx context.Context) (*TokenInspection, error) {
	var inspection *TokenInspection
	err := s.execute(ctx, func(token string) error {
		var reqErr error
		inspection, reqErr = s.client.Auth.InspectToken(ctx, token)
		return reqErr
	})
	return inspection, err
}

// Revoke revokes the current session's tokens.
func (s *UserSessionClient) Revoke(ctx context.Context) error {
	s.mu.RLock()
	accessToken := s.accessToken
	refreshToken := s.refreshToken
	s.mu.RUnlock()

	return s.client.Auth.RevokeToken(ctx, RevokeTokenParams{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
