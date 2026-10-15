package roled

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UserService provides methods for managing users and current user profiles.
type UserService struct {
	client *Client
}

// UserDetails represents full details of a Roled user.
type UserDetails struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Email           *string   `json:"email"`
	ExternalUserID  *string   `json:"external_user_id"`
	DisplayName     string    `json:"display_name"`
	AvatarURL       *string   `json:"avatar_url"`
	IsActive        bool      `json:"is_active"`
	IsEmailVerified bool      `json:"is_email_verified"`
	RoleID          string    `json:"role_id,omitempty"`
	RoleName        string    `json:"role_name,omitempty"`
	Permissions     []string  `json:"permissions,omitempty"`
}

// GetEmail safely returns the user's email address or an empty string if nil.
func (u *UserDetails) GetEmail() string {
	if u == nil || u.Email == nil {
		return ""
	}
	return *u.Email
}

// GetExternalUserID safely returns the external user ID or an empty string if nil.
func (u *UserDetails) GetExternalUserID() string {
	if u == nil || u.ExternalUserID == nil {
		return ""
	}
	return *u.ExternalUserID
}

// GetAvatarURL safely returns the avatar URL or an empty string if nil.
func (u *UserDetails) GetAvatarURL() string {
	if u == nil || u.AvatarURL == nil {
		return ""
	}
	return *u.AvatarURL
}

// GetDisplayName returns the display name, or falls back to the local-part of the email address.
func (u *UserDetails) GetDisplayName() string {
	if u == nil {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	email := u.GetEmail()
	if idx := strings.Index(email, "@"); idx > 0 {
		return email[:idx]
	}
	return email
}

// HasPermission checks whether the user has been granted the specified permission.
func (u *UserDetails) HasPermission(permission string) bool {
	if u == nil {
		return false
	}
	for _, p := range u.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission returns true if the user has at least one of the specified permissions.
func (u *UserDetails) HasAnyPermission(permissions ...string) bool {
	if u == nil || len(permissions) == 0 {
		return false
	}
	for _, p := range permissions {
		if u.HasPermission(p) {
			return true
		}
	}
	return false
}

// HasAllPermissions returns true if the user has all of the specified permissions.
func (u *UserDetails) HasAllPermissions(permissions ...string) bool {
	if u == nil || len(permissions) == 0 {
		return false
	}
	for _, p := range permissions {
		if !u.HasPermission(p) {
			return false
		}
	}
	return true
}

// UserList represents a paginated list of users.
type UserList struct {
	Data       []*UserDetails `json:"data"`
	Pagination Pagination     `json:"pagination"`
}

// userOptions holds query options when fetching user details.
type userOptions struct {
	includePermissions bool
	requestOptions     []RequestOption
}

// UserOption configures user query options.
type UserOption func(*userOptions)

// WithIncludePermissions specifies whether to include assigned permissions in user details.
func WithIncludePermissions(include bool) UserOption {
	return func(opts *userOptions) {
		opts.includePermissions = include
	}
}

// WithUserRequestOption attaches standard request options to a user query.
func WithUserRequestOption(opt RequestOption) UserOption {
	return func(opts *userOptions) {
		opts.requestOptions = append(opts.requestOptions, opt)
	}
}

// ListUsersParams contains parameters for listing users within a project.
type ListUsersParams struct {
	ListParams
	IsActive *bool
	RoleID   *string
}

// ToValues converts ListUsersParams to url.Values.
func (p ListUsersParams) ToValues() url.Values {
	v := p.ListParams.ToValues()
	if p.IsActive != nil {
		v.Set("is_active", strconv.FormatBool(*p.IsActive))
	}
	if p.RoleID != nil && *p.RoleID != "" {
		v.Set("role_id", *p.RoleID)
	}
	return v
}

// CreateUserParams contains fields to create a user in a project.
type CreateUserParams struct {
	DisplayName    string  `json:"display_name"`
	AvatarURL      *string `json:"avatar_url,omitempty"`
	ExternalUserID *string `json:"external_user_id,omitempty"`
	Email          *string `json:"email,omitempty"`
	Password       *string `json:"password,omitempty"`
	RoleID         *string `json:"role_id,omitempty"`
}

// UpdateUserParams contains fields to update a user in a project.
type UpdateUserParams struct {
	DisplayName    string  `json:"display_name"`
	AvatarURL      *string `json:"avatar_url"`
	ExternalUserID *string `json:"external_user_id,omitempty"`
	Email          *string `json:"email,omitempty"`
	Password       *string `json:"password,omitempty"`
	IsActive       *bool   `json:"is_active"`
	RoleID         *string `json:"role_id,omitempty"`
}

// UpdateCurrentUserParams contains fields to update the authenticated user's own profile.
type UpdateCurrentUserParams struct {
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Email       string  `json:"email"`
	Password    *string `json:"password,omitempty"`
}

// InviteUserParams contains fields for inviting a new user to a project.
type InviteUserParams struct {
	Email       string  `json:"email"`
	RoleID      *string `json:"role_id,omitempty"`
	RedirectURI *string `json:"redirect_uri,omitempty"`
}

// GetCurrent retrieves the profile of the currently authenticated user using the given access token.
func (s *UserService) GetCurrent(
	ctx context.Context,
	accessToken string,
	opts ...UserOption,
) (*UserDetails, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("roled: access token is required")
	}

	uOpts := &userOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(uOpts)
		}
	}

	q := url.Values{}
	if uOpts.includePermissions {
		q.Set("include_permissions", "true")
	}

	reqOpts := append([]RequestOption{WithRequestToken(accessToken)}, uOpts.requestOptions...)

	var user UserDetails
	_, err := s.client.execute(ctx, http.MethodGet, "/api/v1/users/current", q, nil, &user, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateCurrent updates the profile of the currently authenticated user.
func (s *UserService) UpdateCurrent(
	ctx context.Context,
	accessToken string,
	params UpdateCurrentUserParams,
	reqOpts ...RequestOption,
) (*UserDetails, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("roled: access token is required")
	}

	combinedOpts := append([]RequestOption{WithRequestToken(accessToken)}, reqOpts...)

	var user UserDetails
	_, err := s.client.execute(ctx, http.MethodPut, "/api/v1/users/current", nil, params, &user, combinedOpts...)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// List returns a paginated list of users in a project.
func (s *UserService) List(
	ctx context.Context,
	projectID string,
	params ListUsersParams,
	reqOpts ...RequestOption,
) (*UserList, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users", url.PathEscape(projectID))

	var users []*UserDetails
	pagination, err := s.client.execute(ctx, http.MethodGet, path, params.ToValues(), nil, &users, reqOpts...)
	if err != nil {
		return nil, err
	}

	list := &UserList{
		Data: users,
	}
	if pagination != nil {
		list.Pagination = *pagination
	}

	return list, nil
}

// Get retrieves a specific user in a project by user ID.
func (s *UserService) Get(
	ctx context.Context,
	projectID, userID string,
	opts ...UserOption,
) (*UserDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if userID == "" {
		return nil, fmt.Errorf("roled: user_id is required")
	}

	uOpts := &userOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(uOpts)
		}
	}

	q := url.Values{}
	if uOpts.includePermissions {
		q.Set("include_permissions", "true")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users/%s", url.PathEscape(projectID), url.PathEscape(userID))

	var user UserDetails
	_, err := s.client.execute(ctx, http.MethodGet, path, q, nil, &user, uOpts.requestOptions...)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetByExternalID retrieves a user by their external user ID (BYOU).
func (s *UserService) GetByExternalID(
	ctx context.Context,
	projectID, externalUserID string,
	opts ...UserOption,
) (*UserDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if externalUserID == "" {
		return nil, fmt.Errorf("roled: external_user_id is required")
	}

	uOpts := &userOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(uOpts)
		}
	}

	q := url.Values{}
	if uOpts.includePermissions {
		q.Set("include_permissions", "true")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users/external/%s", url.PathEscape(projectID), url.PathEscape(externalUserID))

	var user UserDetails
	_, err := s.client.execute(ctx, http.MethodGet, path, q, nil, &user, uOpts.requestOptions...)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Create registers a new user in a project.
func (s *UserService) Create(
	ctx context.Context,
	projectID string,
	params CreateUserParams,
	reqOpts ...RequestOption,
) (*UserDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if params.DisplayName == "" {
		return nil, fmt.Errorf("roled: display_name is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users", url.PathEscape(projectID))

	var user UserDetails
	_, err := s.client.execute(ctx, http.MethodPost, path, nil, params, &user, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Update updates an existing user in a project.
func (s *UserService) Update(
	ctx context.Context,
	projectID, userID string,
	params UpdateUserParams,
	reqOpts ...RequestOption,
) (*UserDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if userID == "" {
		return nil, fmt.Errorf("roled: user_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users/%s", url.PathEscape(projectID), url.PathEscape(userID))

	var user UserDetails
	_, err := s.client.execute(ctx, http.MethodPut, path, nil, params, &user, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Delete permanently removes a user from a project.
func (s *UserService) Delete(
	ctx context.Context,
	projectID, userID string,
	reqOpts ...RequestOption,
) error {
	if projectID == "" {
		return fmt.Errorf("roled: project_id is required")
	}
	if userID == "" {
		return fmt.Errorf("roled: user_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users/%s", url.PathEscape(projectID), url.PathEscape(userID))
	_, err := s.client.execute(ctx, http.MethodDelete, path, nil, nil, nil, reqOpts...)
	return err
}

// ResendVerificationEmail triggers a verification email for the user.
func (s *UserService) ResendVerificationEmail(
	ctx context.Context,
	projectID, userID string,
	redirectURI string,
	reqOpts ...RequestOption,
) error {
	if projectID == "" {
		return fmt.Errorf("roled: project_id is required")
	}
	if userID == "" {
		return fmt.Errorf("roled: user_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users/%s/verification-email", url.PathEscape(projectID), url.PathEscape(userID))

	var body any
	if redirectURI != "" {
		body = map[string]string{"redirect_uri": redirectURI}
	}

	_, err := s.client.execute(ctx, http.MethodPost, path, nil, body, nil, reqOpts...)
	return err
}

// RequestPasswordReset triggers a password reset email for the user.
func (s *UserService) RequestPasswordReset(
	ctx context.Context,
	projectID, userID string,
	redirectURI string,
	reqOpts ...RequestOption,
) error {
	if projectID == "" {
		return fmt.Errorf("roled: project_id is required")
	}
	if userID == "" {
		return fmt.Errorf("roled: user_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users/%s/password-reset", url.PathEscape(projectID), url.PathEscape(userID))

	var body any
	if redirectURI != "" {
		body = map[string]string{"redirect_uri": redirectURI}
	}

	_, err := s.client.execute(ctx, http.MethodPost, path, nil, body, nil, reqOpts...)
	return err
}

// Invite invites a user to the specified project.
func (s *UserService) Invite(
	ctx context.Context,
	projectID string,
	params InviteUserParams,
	reqOpts ...RequestOption,
) (*UserDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if params.Email == "" {
		return nil, fmt.Errorf("roled: email is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/users/invitation", url.PathEscape(projectID))

	var user UserDetails
	_, err := s.client.execute(ctx, http.MethodPost, path, nil, params, &user, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
