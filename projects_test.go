package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProjectService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// List projects: GET /api/v1/projects
		if r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[[]*ProjectSummary]{
				Success: true,
				Data: []*ProjectSummary{
					{ID: "p1", Name: "Business App", IsActive: true},
					{ID: "p2", Name: "Mobile App", IsActive: true},
				},
				Pagination: &Pagination{
					PageNum:   1,
					PageSize:  10,
					TotalData: 2,
				},
			})
			return
		}

		// Get project: GET /api/v1/projects/p1
		if r.URL.Path == "/api/v1/projects/p1" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[ProjectDetails]{
				Success: true,
				Data: ProjectDetails{
					ID:       "p1",
					Name:     "Business App",
					IsActive: true,
					RedirectURIs: []RedirectURI{
						{RedirectURI: "https://example.com/callback"},
					},
				},
			})
			return
		}

		// Create project: POST /api/v1/projects
		if r.URL.Path == "/api/v1/projects" && r.Method == http.MethodPost {
			var body CreateProjectParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[ProjectDetails]{
				Success: true,
				Data: ProjectDetails{
					ID:       "p_new",
					Name:     body.Name,
					IsActive: true,
				},
			})
			return
		}

		// Update project: PUT /api/v1/projects/p1
		if r.URL.Path == "/api/v1/projects/p1" && r.Method == http.MethodPut {
			var body UpdateProjectParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[ProjectDetails]{
				Success: true,
				Data: ProjectDetails{
					ID:       "p1",
					Name:     body.Name,
					IsActive: true,
				},
			})
			return
		}

		// Delete project: POST /api/v1/projects/p1/delete
		if r.URL.Path == "/api/v1/projects/p1/delete" && r.Method == http.MethodPost {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["name"] != "Business App" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{Success: true})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithToken("master_token"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()

	// List
	list, err := client.Projects.List(ctx, ListProjectsParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Data) != 2 {
		t.Errorf("expected 2 projects, got %d", len(list.Data))
	}

	// Get
	p, err := client.Projects.Get(ctx, "p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "Business App" || len(p.RedirectURIs) != 1 {
		t.Errorf("unexpected project details: %+v", p)
	}

	// Create
	created, err := client.Projects.Create(ctx, CreateProjectParams{
		Name: "New Proj",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.Name != "New Proj" {
		t.Errorf("expected 'New Proj', got %s", created.Name)
	}

	// Update
	updated, err := client.Projects.Update(ctx, "p1", UpdateProjectParams{
		Name: "Updated Proj",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "Updated Proj" {
		t.Errorf("expected 'Updated Proj', got %s", updated.Name)
	}

	// Delete
	err = client.Projects.Delete(ctx, "p1", "Business App")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
