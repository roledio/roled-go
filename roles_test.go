package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoleService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// List roles: GET /api/v1/projects/p1/roles
		if r.URL.Path == "/api/v1/projects/p1/roles" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[[]*RoleDetails]{
				Success: true,
				Data: []*RoleDetails{
					{ID: "r1", Code: "store-manager", Name: "Store Manager"},
					{ID: "r2", Code: "inventory-staff", Name: "Inventory Staff"},
				},
				Pagination: &Pagination{
					PageNum:   1,
					PageSize:  10,
					TotalData: 2,
				},
			})
			return
		}

		// Get role: GET /api/v1/projects/p1/roles/r1
		if r.URL.Path == "/api/v1/projects/p1/roles/r1" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[RoleDetails]{
				Success: true,
				Data: RoleDetails{
					ID:            "r1",
					Code:          "store-manager",
					Name:          "Store Manager",
					PermissionIDs: []string{"perm1", "perm2"},
				},
			})
			return
		}

		// Create role: POST /api/v1/projects/p1/roles
		if r.URL.Path == "/api/v1/projects/p1/roles" && r.Method == http.MethodPost {
			var body CreateRoleParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[RoleDetailsAndPermissions]{
				Success: true,
				Data: RoleDetailsAndPermissions{
					RoleDetails: RoleDetails{
						ID:   "r_new",
						Code: body.Code,
						Name: body.Name,
					},
					Permissions: []RolePermission{
						{ID: "perm1", ResourceName: "Products", PermissionName: "Read"},
					},
				},
			})
			return
		}

		// Update role: PUT /api/v1/projects/p1/roles/r1
		if r.URL.Path == "/api/v1/projects/p1/roles/r1" && r.Method == http.MethodPut {
			var body UpdateRoleParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[RoleDetailsAndPermissions]{
				Success: true,
				Data: RoleDetailsAndPermissions{
					RoleDetails: RoleDetails{
						ID:   "r1",
						Code: body.Code,
						Name: body.Name,
					},
				},
			})
			return
		}

		// Delete role: DELETE /api/v1/projects/p1/roles/r1
		if r.URL.Path == "/api/v1/projects/p1/roles/r1" && r.Method == http.MethodDelete {
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
	list, err := client.Roles.List(ctx, "p1", ListRolesParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Data) != 2 {
		t.Errorf("expected 2 roles, got %d", len(list.Data))
	}

	// Get
	r1, err := client.Roles.Get(ctx, "p1", "r1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r1.Code != "store-manager" || len(r1.PermissionIDs) != 2 {
		t.Errorf("unexpected role: %+v", r1)
	}

	// Create
	created, err := client.Roles.Create(ctx, "p1", CreateRoleParams{
		Code: "admin",
		Name: "Administrator",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.Code != "admin" || len(created.Permissions) != 1 {
		t.Errorf("unexpected created role: %+v", created)
	}

	// Update
	updated, err := client.Roles.Update(ctx, "p1", "r1", UpdateRoleParams{
		Code: "super-manager",
		Name: "Super Manager",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Code != "super-manager" {
		t.Errorf("expected super-manager, got %s", updated.Code)
	}

	// Delete
	err = client.Roles.Delete(ctx, "p1", "r1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
