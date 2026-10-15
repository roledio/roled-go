package roled

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ResourceService provides methods for managing resources and permission domains.
type ResourceService struct {
	client *Client
}

// Permission represents an individual action permission belonging to a resource.
type Permission struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Code        string  `json:"code"`
	Description *string `json:"description"`
	IsDefault   bool    `json:"is_default"`
}

// ResourceDetails represents full details of a resource and its defined permissions.
type ResourceDetails struct {
	ID          string       `json:"id"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Name        string       `json:"name"`
	Code        string       `json:"code"`
	Description *string      `json:"description"`
	IsDefault   bool         `json:"is_default"`
	Permissions []Permission `json:"permissions"`
}

// PermissionDetails represents permission info with associated resource details.
type PermissionDetails struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Name         string    `json:"name"`
	Code         string    `json:"code"`
	Description  *string   `json:"description"`
	IsDefault    bool      `json:"is_default"`
	ResourceID   string    `json:"resource_id"`
	ResourceName string    `json:"resource_name"`
	ResourceCode string    `json:"resource_code"`
}

// ResourceList represents a paginated list of resources.
type ResourceList struct {
	Data       []*ResourceDetails `json:"data"`
	Pagination Pagination         `json:"pagination"`
}

// PermissionList represents a paginated list of permissions.
type PermissionList struct {
	Data       []*PermissionDetails `json:"data"`
	Pagination Pagination           `json:"pagination"`
}

// ListResourcesParams contains query parameters for listing resources.
type ListResourcesParams struct {
	ListParams
	IsDefault *bool
}

// ToValues converts ListResourcesParams to url.Values.
func (p ListResourcesParams) ToValues() url.Values {
	v := p.ListParams.ToValues()
	if p.IsDefault != nil {
		v.Set("is_default", strconv.FormatBool(*p.IsDefault))
	}
	return v
}

// ListPermissionsParams contains query parameters for listing permissions.
type ListPermissionsParams struct {
	ListParams
	IsDefault *bool
}

// ToValues converts ListPermissionsParams to url.Values.
func (p ListPermissionsParams) ToValues() url.Values {
	v := p.ListParams.ToValues()
	if p.IsDefault != nil {
		v.Set("is_default", strconv.FormatBool(*p.IsDefault))
	}
	return v
}

// CreatePermissionParams specifies a permission definition when creating or updating a resource.
type CreatePermissionParams struct {
	Name        string  `json:"name"`
	Code        string  `json:"code"`
	Description *string `json:"description,omitempty"`
}

// CreateResourceParams contains fields for creating a resource domain.
type CreateResourceParams struct {
	Name        string                   `json:"name"`
	Code        string                   `json:"code"`
	Description *string                  `json:"description,omitempty"`
	Permissions []CreatePermissionParams `json:"permissions,omitempty"`
}

// UpdateResourceParams contains fields for updating a resource domain.
type UpdateResourceParams struct {
	Name        string                   `json:"name"`
	Code        string                   `json:"code"`
	Description *string                  `json:"description,omitempty"`
	Permissions []CreatePermissionParams `json:"permissions,omitempty"`
}

// List returns a paginated list of resources in a project.
func (s *ResourceService) List(
	ctx context.Context,
	projectID string,
	params ListResourcesParams,
	reqOpts ...RequestOption,
) (*ResourceList, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/resources", url.PathEscape(projectID))

	var resources []*ResourceDetails
	pagination, err := s.client.execute(ctx, http.MethodGet, path, params.ToValues(), nil, &resources, reqOpts...)
	if err != nil {
		return nil, err
	}

	list := &ResourceList{
		Data: resources,
	}
	if pagination != nil {
		list.Pagination = *pagination
	}

	return list, nil
}

// Get returns full details of a specific resource.
func (s *ResourceService) Get(
	ctx context.Context,
	projectID, resourceID string,
	reqOpts ...RequestOption,
) (*ResourceDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if resourceID == "" {
		return nil, fmt.Errorf("roled: resource_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/resources/%s", url.PathEscape(projectID), url.PathEscape(resourceID))

	var resource ResourceDetails
	_, err := s.client.execute(ctx, http.MethodGet, path, nil, nil, &resource, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &resource, nil
}

// Create creates a new resource domain and its permissions in a project.
func (s *ResourceService) Create(
	ctx context.Context,
	projectID string,
	params CreateResourceParams,
	reqOpts ...RequestOption,
) (*ResourceDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("roled: resource name is required")
	}
	if params.Code == "" {
		return nil, fmt.Errorf("roled: resource code is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/resources", url.PathEscape(projectID))

	var resource ResourceDetails
	_, err := s.client.execute(ctx, http.MethodPost, path, nil, params, &resource, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &resource, nil
}

// Update updates an existing resource domain.
func (s *ResourceService) Update(
	ctx context.Context,
	projectID, resourceID string,
	params UpdateResourceParams,
	reqOpts ...RequestOption,
) (*ResourceDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if resourceID == "" {
		return nil, fmt.Errorf("roled: resource_id is required")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("roled: resource name is required")
	}
	if params.Code == "" {
		return nil, fmt.Errorf("roled: resource code is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/resources/%s", url.PathEscape(projectID), url.PathEscape(resourceID))

	var resource ResourceDetails
	_, err := s.client.execute(ctx, http.MethodPut, path, nil, params, &resource, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &resource, nil
}

// Delete permanently removes a resource domain.
func (s *ResourceService) Delete(
	ctx context.Context,
	projectID, resourceID string,
	reqOpts ...RequestOption,
) error {
	if projectID == "" {
		return fmt.Errorf("roled: project_id is required")
	}
	if resourceID == "" {
		return fmt.Errorf("roled: resource_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/resources/%s", url.PathEscape(projectID), url.PathEscape(resourceID))
	_, err := s.client.execute(ctx, http.MethodDelete, path, nil, nil, nil, reqOpts...)
	return err
}

// ListPermissions returns a paginated list of all permissions defined in a project.
func (s *ResourceService) ListPermissions(
	ctx context.Context,
	projectID string,
	params ListPermissionsParams,
	reqOpts ...RequestOption,
) (*PermissionList, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/permissions", url.PathEscape(projectID))

	var permissions []*PermissionDetails
	pagination, err := s.client.execute(ctx, http.MethodGet, path, params.ToValues(), nil, &permissions, reqOpts...)
	if err != nil {
		return nil, err
	}

	list := &PermissionList{
		Data: permissions,
	}
	if pagination != nil {
		list.Pagination = *pagination
	}

	return list, nil
}
