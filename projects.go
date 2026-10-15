package roled

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ProjectService provides methods for managing Roled projects.
type ProjectService struct {
	client *Client
}

// RedirectURI represents an OAuth 2.0 redirect URI and its corresponding login URL.
type RedirectURI struct {
	RedirectURI string `json:"redirect_uri"`
	LoginURL    string `json:"login_url,omitempty"`
}

// ProjectSummary represents summary information of a project.
type ProjectSummary struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	LogoURL     *string   `json:"logo_url"`
	IsActive    bool      `json:"is_active"`
}

// ProjectDetails represents complete details of a project, including redirect URIs.
type ProjectDetails struct {
	ID           string        `json:"id"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	Name         string        `json:"name"`
	Description  *string       `json:"description"`
	LogoURL      *string       `json:"logo_url"`
	RedirectURIs []RedirectURI `json:"redirect_uris"`
	IsActive     bool          `json:"is_active"`
}

// ProjectList represents a paginated list of projects.
type ProjectList struct {
	Data       []*ProjectSummary `json:"data"`
	Pagination Pagination        `json:"pagination"`
}

// ListProjectsParams contains query parameters for listing projects.
type ListProjectsParams struct {
	ListParams
	IsActive       *bool
	CreatedAtSince *time.Time
	CreatedAtUntil *time.Time
}

// ToValues converts ListProjectsParams to url.Values.
func (p ListProjectsParams) ToValues() url.Values {
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

// CreateProjectParams contains fields for creating a new project.
type CreateProjectParams struct {
	Name         string        `json:"name"`
	Description  *string       `json:"description,omitempty"`
	LogoURL      *string       `json:"logo_url,omitempty"`
	RedirectURIs []RedirectURI `json:"redirect_uris,omitempty"`
}

// UpdateProjectParams contains fields for updating an existing project.
type UpdateProjectParams struct {
	Name         string        `json:"name"`
	Description  *string       `json:"description,omitempty"`
	LogoURL      *string       `json:"logo_url,omitempty"`
	RedirectURIs []RedirectURI `json:"redirect_uris,omitempty"`
	IsActive     *bool         `json:"is_active,omitempty"`
}

// List returns a paginated list of projects.
func (s *ProjectService) List(
	ctx context.Context,
	params ListProjectsParams,
	reqOpts ...RequestOption,
) (*ProjectList, error) {
	var projects []*ProjectSummary
	pagination, err := s.client.execute(ctx, http.MethodGet, "/api/v1/projects", params.ToValues(), nil, &projects, reqOpts...)
	if err != nil {
		return nil, err
	}

	list := &ProjectList{
		Data: projects,
	}
	if pagination != nil {
		list.Pagination = *pagination
	}

	return list, nil
}

// Get returns full details of a specific project.
func (s *ProjectService) Get(
	ctx context.Context,
	projectID string,
	reqOpts ...RequestOption,
) (*ProjectDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s", url.PathEscape(projectID))

	var project ProjectDetails
	_, err := s.client.execute(ctx, http.MethodGet, path, nil, nil, &project, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

// Create creates a new project.
func (s *ProjectService) Create(
	ctx context.Context,
	params CreateProjectParams,
	reqOpts ...RequestOption,
) (*ProjectDetails, error) {
	if params.Name == "" {
		return nil, fmt.Errorf("roled: project name is required")
	}

	var project ProjectDetails
	_, err := s.client.execute(ctx, http.MethodPost, "/api/v1/projects", nil, params, &project, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

// Update updates an existing project.
func (s *ProjectService) Update(
	ctx context.Context,
	projectID string,
	params UpdateProjectParams,
	reqOpts ...RequestOption,
) (*ProjectDetails, error) {
	if projectID == "" {
		return nil, fmt.Errorf("roled: project_id is required")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("roled: project name is required")
	}

	path := fmt.Sprintf("/api/v1/projects/%s", url.PathEscape(projectID))

	var project ProjectDetails
	_, err := s.client.execute(ctx, http.MethodPut, path, nil, params, &project, reqOpts...)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

// Delete permanently removes a project by verifying the project name.
func (s *ProjectService) Delete(
	ctx context.Context,
	projectID string,
	projectName string,
	reqOpts ...RequestOption,
) error {
	if projectID == "" {
		return fmt.Errorf("roled: project_id is required")
	}
	if projectName == "" {
		return fmt.Errorf("roled: project name is required to confirm deletion")
	}

	path := fmt.Sprintf("/api/v1/projects/%s/delete", url.PathEscape(projectID))
	payload := map[string]string{
		"name": projectName,
	}

	_, err := s.client.execute(ctx, http.MethodPost, path, nil, payload, nil, reqOpts...)
	return err
}
