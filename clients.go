package roled

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ClientService provides methods for managing OAuth 2.0 clients within projects.
type ClientService struct {
	client *Client
}

// ClientDetails represents details of an OAuth 2.0 client registered in a project.
type ClientDetails struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Name          string    `json:"name"`
	Description   *string   `json:"description"`
	IsDefault     bool      `json:"is_default"`
	IsActive      bool      `json:"is_active"`
	Secret        string    `json:"secret,omitempty"`
	PermissionIDs []string  `json:"permission_ids,omitempty"`
}

// ClientPermission represents permission information attached to a client.
type ClientPermission struct {
	ID             string `json:"id"`
	ResourceName   string `json:"resource_name"`
	PermissionName string `json:"permission_name"`
}

// ClientDetailsAndPermissions represents a client with detailed permissions.
type ClientDetailsAndPermissions struct {
	ClientDetails
	Permissions []ClientPermission `json:"permissions"`
}

// ClientList represents a paginated list of clients.
type ClientList struct {
	Data       []*ClientDetails `json:"data"`
	Pagination Pagination       `json:"pagination"`
}

// ListClientsParams contains query parameters for listing clients.
type ListClientsParams struct {
	ListParams
	IsActive       *bool
	CreatedAtSince *time.Time
	CreatedAtUntil *time.Time
}

// ToValues converts ListClientsParams to url.Values.
func (p ListClientsParams) ToValues() url.Values {
	v := p.ListParams.ToValues()
	if p.IsActive != nil {
		v.Set("is_active", strconv.FormatBool(*p.IsActive))
	}
	if p.CreatedAtSince != nil {
		v.Set("created_at_since", p.CreatedAtSince.Format(time.RFC3339))
	}
	if p.CreatedAtUntil != nil {
		v.Set("created_at_until", p.CreatedAtUntil.Format(time.RFC3339))
	}
	return v
}

// CreateClientParams contains fields for creating an OAuth 2.0 client.
type CreateClientParams struct {
	Name          string   `json:"name"`
	Description   *string  `json:"description,omitempty"`
	PermissionIDs []string `json:"permission_ids,omitempty"`
}

// UpdateClientParams contains fields for updating an OAuth 2.0 client.
type UpdateClientParams struct {
	Name          string   `json:"name"`
	Description   *string  `json:"description,omitempty"`
	IsActive      *bool    `json:"is_active,omitempty"`
	PermissionIDs []string `json:"permission_ids,omitempty"`
}

// List returns a paginated list of clients in a project.
func (s *ClientService) List(
	ctx context.Context,
	projectID string,
	params ListClientsParams,
	reqOpts ...RequestOption,
) (*ClientList, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/clients", url.PathEscape(projectID))

	var clients []*ClientDetails
	pagination, err := s.client.execute(ctx, http.MethodGet, path, params.ToValues(), nil, &clients, reqOpts...)
	if err != nil {
		return nil, err
	}

	list := &ClientList{
		Data: clients,
	}
	if pagination != nil {
		list.Pagination = *pagination
	}

	return list, nil
}

// Get returns full details of a specific client in a project.
func (s *ClientService) Get(
	ctx context.Context,
	projectID, clientID string,
	reqOpts ...RequestOption,
) (*ClientDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("roled: client_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/clients/%s", url.PathEscape(projectID), url.PathEscape(clientID))

	var client ClientDetails
	_, err := s.client.execute(ctx, http.MethodGet, path, nil, nil, &client, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &client, nil
}

// Create creates a new OAuth 2.0 client application in a project.
func (s *ClientService) Create(
	ctx context.Context,
	projectID string,
	params CreateClientParams,
	reqOpts ...RequestOption,
) (*ClientDetailsAndPermissions, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("roled: client name is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/clients", url.PathEscape(projectID))

	var client ClientDetailsAndPermissions
	_, err := s.client.execute(ctx, http.MethodPost, path, nil, params, &client, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &client, nil
}

// Update updates an existing OAuth 2.0 client application.
func (s *ClientService) Update(
	ctx context.Context,
	projectID, clientID string,
	params UpdateClientParams,
	reqOpts ...RequestOption,
) (*ClientDetailsAndPermissions, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("roled: client_id is required")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("roled: client name is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/clients/%s", url.PathEscape(projectID), url.PathEscape(clientID))

	var client ClientDetailsAndPermissions
	_, err := s.client.execute(ctx, http.MethodPut, path, nil, params, &client, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &client, nil
}

// Delete permanently removes a client from a project.
func (s *ClientService) Delete(
	ctx context.Context,
	projectID, clientID string,
	reqOpts ...RequestOption,
) error {
	if projectID == "" {
		return fmt.Errorf("roled: project_id is required")
	}
	if clientID == "" {
		return fmt.Errorf("roled: client_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/clients/%s", url.PathEscape(projectID), url.PathEscape(clientID))
	_, err := s.client.execute(ctx, http.MethodDelete, path, nil, nil, nil, reqOpts...)
	return err
}
