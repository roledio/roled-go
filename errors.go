package roled

import (
	"errors"
	"fmt"
	"net/http"
)

// Common Roled API Error Codes.
const (
	ErrCodeInvalidParams                 = "invalid_params"
	ErrCodeInvalidClient                 = "invalid_client"
	ErrCodeClientNotActive               = "client_not_active"
	ErrCodeProjectNotActive              = "project_not_active"
	ErrCodeInvalidAuthorizationCode      = "invalid_authorization_code"
	ErrCodeDifferentAuthorizeRedirectURI = "different_authorize_redirect_uri"
	ErrCodeAuthCodeAlreadyUsed           = "auth_code_already_used"
	ErrCodeAuthCodeExpired               = "auth_code_expired"
	ErrCodeInvalidCodeVerifier           = "invalid_code_verifier"
	ErrCodeInvalidRefreshToken           = "invalid_refresh_token"
	ErrCodeRefreshTokenExpired           = "refresh_token_expired"
	ErrCodeRefreshTokenAlreadyUsed       = "refresh_token_already_used"
	ErrCodeInvalidClientCredentials      = "invalid_client_credentials"
	ErrCodeInvalidAuthorizationToken     = "invalid_authorization_token"
	ErrCodeInsufficientPermission        = "insufficient_permission"
	ErrCodeProjectNotFound               = "project_not_found"
	ErrCodeRoleNotFound                  = "role_not_found"
	ErrCodeResourceNotFound              = "resource_not_found"
	ErrCodeClientNotFound                = "client_not_found"
	ErrCodeUserNotFound                  = "user_not_found"
	ErrCodeSomePermissionsNotFound       = "some_permissions_not_found"
	ErrCodeRoleCodeAlreadyUsed           = "role_code_already_used"
	ErrCodeResourceCodeAlreadyUsed       = "resource_code_already_used"
	ErrCodeUserEmailAlreadyUsed          = "user_email_already_used"
	ErrCodeUserExternalIDAlreadyUsed     = "user_external_id_already_used"
	ErrCodeSystemError                   = "system_error"
)

// APIError represents an error returned by the Roled API.
type APIError struct {
	// StatusCode is the HTTP status code (e.g., 400, 401, 403, 404, 500).
	StatusCode int `json:"status_code"`

	// Code is the machine-readable error code returned by Roled (e.g., "invalid_authorization_token").
	Code string `json:"code"`

	// Message is a human-readable explanation of the error.
	Message string `json:"message"`

	// RawBody contains the unparsed response body string, if available.
	RawBody string `json:"raw_body,omitempty"`
}

// Error implements the standard Go error interface.
func (e *APIError) Error() string {
	if e == nil {
		return "roled: unknown error"
	}
	if e.Code != "" {
		return fmt.Sprintf("roled: HTTP %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	if e.Message != "" {
		return fmt.Sprintf("roled: HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("roled: HTTP status %d", e.StatusCode)
}

// IsUnauthorized returns true if err is a Roled 401 Unauthorized API error.
func IsUnauthorized(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusUnauthorized ||
			apiErr.Code == ErrCodeInvalidAuthorizationToken ||
			apiErr.Code == ErrCodeInvalidClientCredentials
	}
	return false
}

// IsForbidden returns true if err is a Roled 403 Forbidden API error.
func IsForbidden(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusForbidden ||
			apiErr.Code == ErrCodeInsufficientPermission
	}
	return false
}

// IsNotFound returns true if err is a Roled 404 Not Found API error.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound ||
			apiErr.Code == ErrCodeUserNotFound ||
			apiErr.Code == ErrCodeProjectNotFound ||
			apiErr.Code == ErrCodeRoleNotFound ||
			apiErr.Code == ErrCodeResourceNotFound ||
			apiErr.Code == ErrCodeClientNotFound
	}
	return false
}

// IsConflict returns true if err is a Roled 409 Conflict API error.
func IsConflict(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusConflict ||
			apiErr.Code == ErrCodeUserEmailAlreadyUsed ||
			apiErr.Code == ErrCodeUserExternalIDAlreadyUsed ||
			apiErr.Code == ErrCodeRoleCodeAlreadyUsed ||
			apiErr.Code == ErrCodeResourceCodeAlreadyUsed
	}
	return false
}

// ErrorCode returns the Roled error code if err is an *APIError, or an empty string otherwise.
func ErrorCode(err error) string {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return ""
}

// StatusCode returns the HTTP status code if err is an *APIError, or 0 otherwise.
func StatusCode(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}
