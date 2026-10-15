package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// List clients: GET /api/v1/projects/p1/clients
		if r.URL.Path == "/api/v1/projects/p1/clients" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[[]*ClientDetails]{
				Success: true,
				Data: []*ClientDetails{
					{ID: "c1", Name: "Read Only Client", IsActive: true},
					{ID: "c2", Name: "Backend Service", IsActive: true},
				},
				Pagination: &Pagination{
					PageNum:   1,
					PageSize:  10,
					TotalData: 2,
				},
			})
			return
		}

		// Get client: GET /api/v1/projects/p1/clients/c1
		if r.URL.Path == "/api/v1/projects/p1/clients/c1" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[ClientDetails]{
				Success: true,
				Data: ClientDetails{
					ID:            "c1",
					Name:          "Read Only Client",
					IsActive:      true,
					PermissionIDs: []string{"perm1"},
				},
			})
			return
		}

		// Create client: POST /api/v1/projects/p1/clients
		if r.URL.Path == "/api/v1/projects/p1/clients" && r.Method == http.MethodPost {
			var body CreateClientParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[ClientDetailsAndPermissions]{
				Success: true,
				Data: ClientDetailsAndPermissions{
					ClientDetails: ClientDetails{
						ID:       "c_new",
						Name:     body.Name,
						IsActive: true,
						Secret:   "sec_12345",
					},
					Permissions: []ClientPermission{
						{ID: "perm1", ResourceName: "Products", PermissionName: "Read"},
					},
				},
			})
			return
		}

		// Update client: PUT /api/v1/projects/p1/clients/c1
		if r.URL.Path == "/api/v1/projects/p1/clients/c1" && r.Method == http.MethodPut {
			var body UpdateClientParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[ClientDetailsAndPermissions]{
				Success: true,
				Data: ClientDetailsAndPermissions{
					ClientDetails: ClientDetails{
						ID:       "c1",
						Name:     body.Name,
						IsActive: true,
					},
				},
			})
			return
		}

		// Delete client: DELETE /api/v1/projects/p1/clients/c1
		if r.URL.Path == "/api/v1/projects/p1/clients/c1" && r.Method == http.MethodDelete {
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
	list, err := client.Clients.List(ctx, "p1", ListClientsParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Data) != 2 {
		t.Errorf("expected 2 clients, got %d", len(list.Data))
	}

	// Get
	c, err := client.Clients.Get(ctx, "p1", "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Name != "Read Only Client" {
		t.Errorf("expected Read Only Client, got %s", c.Name)
	}

	// Create
	created, err := client.Clients.Create(ctx, "p1", CreateClientParams{
		Name: "New Backend Client",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.Secret != "sec_12345" || len(created.Permissions) != 1 {
		t.Errorf("unexpected created client: %+v", created)
	}

	// Update
	updated, err := client.Clients.Update(ctx, "p1", "c1", UpdateClientParams{
		Name:     "Updated Client",
		IsActive: BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "Updated Client" {
		t.Errorf("expected Updated Client, got %s", updated.Name)
	}

	// Delete
	err = client.Clients.Delete(ctx, "p1", "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
