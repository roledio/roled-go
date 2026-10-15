package roled

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestAPIError_Error(t *testing.T) {
	var nilErr *APIError
	if nilErr.Error() != "roled: unknown error" {
		t.Errorf("expected 'roled: unknown error', got %q", nilErr.Error())
	}

	errWithCode := &APIError{
		StatusCode: http.StatusNotFound,
		Code:       ErrCodeUserNotFound,
		Message:    "The requested user could not be found.",
	}
	expected := "roled: HTTP 404 (user_not_found): The requested user could not be found."
	if errWithCode.Error() != expected {
		t.Errorf("expected %q, got %q", expected, errWithCode.Error())
	}

	errNoCode := &APIError{
		StatusCode: http.StatusInternalServerError,
		Message:    "Internal server error",
	}
	expectedNoCode := "roled: HTTP 500: Internal server error"
	if errNoCode.Error() != expectedNoCode {
		t.Errorf("expected %q, got %q", expectedNoCode, errNoCode.Error())
	}

	errOnlyStatus := &APIError{
		StatusCode: http.StatusBadRequest,
	}
	expectedStatus := "roled: HTTP status 400"
	if errOnlyStatus.Error() != expectedStatus {
		t.Errorf("expected %q, got %q", expectedStatus, errOnlyStatus.Error())
	}
}

func TestErrorHelpers(t *testing.T) {
	unauthErr := &APIError{
		StatusCode: http.StatusUnauthorized,
		Code:       ErrCodeInvalidAuthorizationToken,
		Message:    "Unauthorized",
	}

	forbidErr := &APIError{
		StatusCode: http.StatusForbidden,
		Code:       ErrCodeInsufficientPermission,
		Message:    "Forbidden",
	}

	notFoundErr := &APIError{
		StatusCode: http.StatusNotFound,
		Code:       ErrCodeUserNotFound,
		Message:    "Not found",
	}

	conflictErr := &APIError{
		StatusCode: http.StatusConflict,
		Code:       ErrCodeUserEmailAlreadyUsed,
		Message:    "Email already used",
	}

	wrappedUnauth := fmt.Errorf("outer: %w", unauthErr)
	stdErr := errors.New("something went wrong")

	// IsUnauthorized
	if !IsUnauthorized(unauthErr) || !IsUnauthorized(wrappedUnauth) {
		t.Errorf("expected IsUnauthorized to be true")
	}
	if IsUnauthorized(forbidErr) || IsUnauthorized(stdErr) {
		t.Errorf("expected IsUnauthorized to be false")
	}

	// IsForbidden
	if !IsForbidden(forbidErr) {
		t.Errorf("expected IsForbidden to be true")
	}
	if IsForbidden(unauthErr) || IsForbidden(stdErr) {
		t.Errorf("expected IsForbidden to be false")
	}

	// IsNotFound
	if !IsNotFound(notFoundErr) {
		t.Errorf("expected IsNotFound to be true")
	}
	if IsNotFound(unauthErr) || IsNotFound(stdErr) {
		t.Errorf("expected IsNotFound to be false")
	}

	// IsConflict
	if !IsConflict(conflictErr) {
		t.Errorf("expected IsConflict to be true")
	}
	if IsConflict(unauthErr) || IsConflict(stdErr) {
		t.Errorf("expected IsConflict to be false")
	}

	// ErrorCode & StatusCode
	if ErrorCode(unauthErr) != ErrCodeInvalidAuthorizationToken {
		t.Errorf("expected %s, got %s", ErrCodeInvalidAuthorizationToken, ErrorCode(unauthErr))
	}
	if ErrorCode(stdErr) != "" {
		t.Errorf("expected empty string for non-API error, got %s", ErrorCode(stdErr))
	}
	if StatusCode(unauthErr) != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, StatusCode(unauthErr))
	}
	if StatusCode(stdErr) != 0 {
		t.Errorf("expected 0, got %d", StatusCode(stdErr))
	}
}
