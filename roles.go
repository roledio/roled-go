package roled

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// RoleService provides methods for managing roles and permissions within projects.
type RoleService struct {
	client *Client
}

// RoleDetails represents the details of a role in a Roled project.
type RoleDetails struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Code            string    `json:"code"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	IsDefaultSignup *bool     `json:"is_default_signup,omitempty"`
	PermissionIDs   []string  `json:"permission_ids,omitempty"`
}

// RolePermission represents permission metadata attached to a role.
type RolePermission struct {
	ID             string `json:"id"`
	ResourceName   string `json:"resource_name"`
	PermissionName string `json:"permission_name"`
}

// RoleDetailsAndPermissions represents a role along with detailed assigned permissions.
type RoleDetailsAndPermissions struct {
	RoleDetails
	Permissions []RolePermission `json:"permissions"`
}

// RoleList represents a paginated list of roles.
type RoleList struct {
	Data       []*RoleDetails `json:"data"`
	Pagination Pagination     `json:"pagination"`
}

// ListRolesParams contains query parameters for listing roles.
type ListRolesParams struct {
	ListParams
}

// CreateRoleParams contains fields for creating a role in a project.
type CreateRoleParams struct {
	Code          string   `json:"code"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	PermissionIDs []string `json:"permission_ids,omitempty"`
}

// UpdateRoleParams contains fields for updating a role in a project.
type UpdateRoleParams struct {
	Code          string   `json:"code"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	PermissionIDs []string `json:"permission_ids,omitempty"`
}

// List returns a paginated list of roles in a project.
func (s *RoleService) List(
	ctx context.Context,
	projectID string,
	params ListRolesParams,
	reqOpts ...RequestOption,
) (*RoleList, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/roles", url.PathEscape(projectID))

	var roles []*RoleDetails
	pagination, err := s.client.execute(ctx, http.MethodGet, path, params.ToValues(), nil, &roles, reqOpts...)
	if err != nil {
		return nil, err
	}

	list := &RoleList{
		Data: roles,
	}
	if pagination != nil {
		list.Pagination = *pagination
	}

	return list, nil
}

// Get returns details of a specific role, including assigned permission IDs.
func (s *RoleService) Get(
	ctx context.Context,
	projectID, roleID string,
	reqOpts ...RequestOption,
) (*RoleDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if roleID == "" {
		return nil, fmt.Errorf("roled: role_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/roles/%s", url.PathEscape(projectID), url.PathEscape(roleID))

	var role RoleDetails
	_, err := s.client.execute(ctx, http.MethodGet, path, nil, nil, &role, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// Create creates a new role in a project.
func (s *RoleService) Create(
	ctx context.Context,
	projectID string,
	params CreateRoleParams,
	reqOpts ...RequestOption,
) (*RoleDetailsAndPermissions, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if params.Code == "" {
		return nil, fmt.Errorf("roled: role code is required")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("roled: role name is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/roles", url.PathEscape(projectID))

	var role RoleDetailsAndPermissions
	_, err := s.client.execute(ctx, http.MethodPost, path, nil, params, &role, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// Update updates an existing role in a project.
func (s *RoleService) Update(
	ctx context.Context,
	projectID, roleID string,
	params UpdateRoleParams,
	reqOpts ...RequestOption,
) (*RoleDetailsAndPermissions, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if roleID == "" {
		return nil, fmt.Errorf("roled: role_id is required")
	}
	if params.Code == "" {
		return nil, fmt.Errorf("roled: role code is required")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("roled: role name is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/roles/%s", url.PathEscape(projectID), url.PathEscape(roleID))

	var role RoleDetailsAndPermissions
	_, err := s.client.execute(ctx, http.MethodPut, path, nil, params, &role, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// Delete permanently removes a role from a project.
func (s *RoleService) Delete(
	ctx context.Context,
	projectID, roleID string,
	reqOpts ...RequestOption,
) error {
	if projectID == "" {
		return fmt.Errorf("roled: project_id is required")
	}
	if roleID == "" {
		return fmt.Errorf("roled: role_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/roles/%s", url.PathEscape(projectID), url.PathEscape(roleID))
	_, err := s.client.execute(ctx, http.MethodDelete, path, nil, nil, nil, reqOpts...)
	return err
}
