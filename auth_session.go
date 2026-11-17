package roled

import (
	"time"
)

type AuthSession struct {
	ID                    string
	OAuthState            string
	PKCEVerifier          string
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// IsAuthenticated reports whether the session holds a completed OAuth login.
func (s *AuthSession) IsAuthenticated() bool {
	return s != nil && s.RefreshToken != ""
}

// AccessTokenValid reports whether the access token is present and does not
// expire within the given skew window.
func (s *AuthSession) AccessTokenValid(skew time.Duration) bool {
	return s != nil &&
		s.AccessToken != "" &&
		time.Now().Add(skew).Before(s.AccessTokenExpiresAt)
}

// RefreshTokenExpired reports whether the stored refresh token is past its
// known expiry time. A zero expiry means the lifetime is unknown and the
// token is treated as still valid.
func (s *AuthSession) RefreshTokenExpired() bool {
	return s != nil &&
		!s.RefreshTokenExpiresAt.IsZero() &&
		time.Now().After(s.RefreshTokenExpiresAt)
}
