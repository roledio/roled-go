package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResourceService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// List resources: GET /api/v1/projects/p1/resources
		if r.URL.Path == "/api/v1/projects/p1/resources" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[[]*ResourceDetails]{
				Success: true,
				Data: []*ResourceDetails{
					{ID: "res1", Name: "Products", Code: "products"},
					{ID: "res2", Name: "Orders", Code: "orders"},
				},
				Pagination: &Pagination{
					PageNum:   1,
					PageSize:  10,
					TotalData: 2,
				},
			})
			return
		}

		// Get resource: GET /api/v1/projects/p1/resources/res1
		if r.URL.Path == "/api/v1/projects/p1/resources/res1" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[ResourceDetails]{
				Success: true,
				Data: ResourceDetails{
					ID:   "res1",
					Name: "Products",
					Code: "products",
					Permissions: []Permission{
						{ID: "perm1", Name: "Create", Code: "create"},
					},
				},
			})
			return
		}

		// Create resource: POST /api/v1/projects/p1/resources
		if r.URL.Path == "/api/v1/projects/p1/resources" && r.Method == http.MethodPost {
			var body CreateResourceParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[ResourceDetails]{
				Success: true,
				Data: ResourceDetails{
					ID:   "res_new",
					Name: body.Name,
					Code: body.Code,
				},
			})
			return
		}

		// Update resource: PUT /api/v1/projects/p1/resources/res1
		if r.URL.Path == "/api/v1/projects/p1/resources/res1" && r.Method == http.MethodPut {
			var body UpdateResourceParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[ResourceDetails]{
				Success: true,
				Data: ResourceDetails{
					ID:   "res1",
					Name: body.Name,
					Code: body.Code,
				},
			})
			return
		}

		// Delete resource: DELETE /api/v1/projects/p1/resources/res1
		if r.URL.Path == "/api/v1/projects/p1/resources/res1" && r.Method == http.MethodDelete {
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{Success: true})
			return
		}

		// List permissions: GET /api/v1/projects/p1/permissions
		if r.URL.Path == "/api/v1/projects/p1/permissions" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[[]*PermissionDetails]{
				Success: true,
				Data: []*PermissionDetails{
					{ID: "perm1", Name: "Create", Code: "create", ResourceCode: "products"},
				},
				Pagination: &Pagination{
					PageNum:   1,
					PageSize:  10,
					TotalData: 1,
				},
			})
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
	list, err := client.Resources.List(ctx, "p1", ListResourcesParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Data) != 2 {
		t.Errorf("expected 2 resources, got %d", len(list.Data))
	}

	// Get
	res, err := client.Resources.Get(ctx, "p1", "res1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Code != "products" || len(res.Permissions) != 1 {
		t.Errorf("unexpected resource details: %+v", res)
	}

	// Create
	created, err := client.Resources.Create(ctx, "p1", CreateResourceParams{
		Name: "Invoices",
		Code: "invoices",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.Code != "invoices" {
		t.Errorf("expected invoices, got %s", created.Code)
	}

	// Update
	updated, err := client.Resources.Update(ctx, "p1", "res1", UpdateResourceParams{
		Name: "Products Catalog",
		Code: "products",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "Products Catalog" {
		t.Errorf("expected Products Catalog, got %s", updated.Name)
	}

	// Delete
	err = client.Resources.Delete(ctx, "p1", "res1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// List permissions
	perms, err := client.Resources.ListPermissions(ctx, "p1", ListPermissionsParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(perms.Data) != 1 {
		t.Errorf("expected 1 permission, got %d", len(perms.Data))
	}
}
