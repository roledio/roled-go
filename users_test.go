package roled

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserDetails_Helpers(t *testing.T) {
	var nilUser *UserDetails
	if nilUser.GetEmail() != "" {
		t.Errorf("expected empty string for nil user email")
	}
	if nilUser.GetDisplayName() != "" {
		t.Errorf("expected empty string for nil user display name")
	}
	if nilUser.GetExternalUserID() != "" {
		t.Errorf("expected empty string for nil user external user id")
	}
	if nilUser.GetAvatarURL() != "" {
		t.Errorf("expected empty string for nil user avatar url")
	}
	if nilUser.HasPermission("read") {
		t.Errorf("expected false for nil user permission")
	}

	user := &UserDetails{
		ID:          "user_1",
		Email:       StringPtr("alice.smith@example.com"),
		DisplayName: "Alice Smith",
		Permissions: []string{"products:read", "products:create"},
	}

	if user.GetEmail() != "alice.smith@example.com" {
		t.Errorf("expected 'alice.smith@example.com', got %s", user.GetEmail())
	}
	if user.GetDisplayName() != "Alice Smith" {
		t.Errorf("expected 'Alice Smith', got %s", user.GetDisplayName())
	}
	if !user.HasPermission("products:read") {
		t.Errorf("expected user to have 'products:read'")
	}
	if user.HasPermission("orders:delete") {
		t.Errorf("expected user to not have 'orders:delete'")
	}
	if !user.HasAnyPermission("orders:delete", "products:read") {
		t.Errorf("expected user to have at least one permission")
	}
	if user.HasAnyPermission("orders:delete", "orders:create") {
		t.Errorf("expected false for non-matching permissions")
	}
	if !user.HasAllPermissions("products:read", "products:create") {
		t.Errorf("expected true for HasAllPermissions")
	}
	if user.HasAllPermissions("products:read", "orders:delete") {
		t.Errorf("expected false for HasAllPermissions when one is missing")
	}

	// Fallback display name to email prefix
	userNoDisplay := &UserDetails{
		Email: StringPtr("bob@example.com"),
	}
	if userNoDisplay.GetDisplayName() != "bob" {
		t.Errorf("expected 'bob', got %s", userNoDisplay.GetDisplayName())
	}
}

func TestUserService_CRUD(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// List users: GET /api/v1/projects/p1/users
		if r.URL.Path == "/api/v1/projects/p1/users" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[[]*UserDetails]{
				Success: true,
				Data: []*UserDetails{
					{ID: "u1", DisplayName: "Alice"},
					{ID: "u2", DisplayName: "Bob"},
				},
				Pagination: &Pagination{
					PageNum:   1,
					PageSize:  10,
					TotalData: 2,
				},
			})
			return
		}

		// Get user: GET /api/v1/projects/p1/users/u1
		if r.URL.Path == "/api/v1/projects/p1/users/u1" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
				Success: true,
				Data: UserDetails{
					ID:          "u1",
					DisplayName: "Alice",
				},
			})
			return
		}

		// Get external user: GET /api/v1/projects/p1/users/external/ext_1
		if r.URL.Path == "/api/v1/projects/p1/users/external/ext_1" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
				Success: true,
				Data: UserDetails{
					ID:             "u1",
					ExternalUserID: StringPtr("ext_1"),
					DisplayName:    "Alice",
				},
			})
			return
		}

		// Create user: POST /api/v1/projects/p1/users
		if r.URL.Path == "/api/v1/projects/p1/users" && r.Method == http.MethodPost {
			var body CreateUserParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
				Success: true,
				Data: UserDetails{
					ID:          "u_new",
					DisplayName: body.DisplayName,
				},
			})
			return
		}

		// Update user: PUT /api/v1/projects/p1/users/u1
		if r.URL.Path == "/api/v1/projects/p1/users/u1" && r.Method == http.MethodPut {
			var body UpdateUserParams
			_ = json.NewDecoder(r.Body).Decode(&body)

			_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
				Success: true,
				Data: UserDetails{
					ID:          "u1",
					DisplayName: body.DisplayName,
				},
			})
			return
		}

		// Delete user: DELETE /api/v1/projects/p1/users/u1
		if r.URL.Path == "/api/v1/projects/p1/users/u1" && r.Method == http.MethodDelete {
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{
				Success: true,
				Data:    nil,
			})
			return
		}

		// Resend verification email
		if r.URL.Path == "/api/v1/projects/p1/users/u1/verification-email" && r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{Success: true})
			return
		}

		// Password reset
		if r.URL.Path == "/api/v1/projects/p1/users/u1/password-reset" && r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(responseEnvelope[any]{Success: true})
			return
		}

		// Invite
		if r.URL.Path == "/api/v1/projects/p1/users/invitation" && r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(responseEnvelope[UserDetails]{
				Success: true,
				Data: UserDetails{
					ID:    "u_invited",
					Email: StringPtr("new@example.com"),
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
	list, err := client.Users.List(ctx, "p1", ListUsersParams{
		ListParams: ListParams{PageNum: 1, PageSize: 10},
	})
	if err != nil {
		t.Fatalf("unexpected error listing users: %v", err)
	}
	if len(list.Data) != 2 {
		t.Errorf("expected 2 users, got %d", len(list.Data))
	}
	if list.Pagination.TotalData != 2 {
		t.Errorf("expected total data 2, got %d", list.Pagination.TotalData)
	}

	// Get
	u1, err := client.Users.Get(ctx, "p1", "u1", WithIncludePermissions(true))
	if err != nil {
		t.Fatalf("unexpected error getting user: %v", err)
	}
	if u1.DisplayName != "Alice" {
		t.Errorf("expected Alice, got %s", u1.DisplayName)
	}

	// Get by external ID
	uExt, err := client.Users.GetByExternalID(ctx, "p1", "ext_1")
	if err != nil {
		t.Fatalf("unexpected error getting user by external ID: %v", err)
	}
	if uExt.GetExternalUserID() != "ext_1" {
		t.Errorf("expected ext_1, got %s", uExt.GetExternalUserID())
	}

	// Create
	created, err := client.Users.Create(ctx, "p1", CreateUserParams{
		DisplayName: "Charlie",
		Email:       StringPtr("charlie@example.com"),
	})
	if err != nil {
		t.Fatalf("unexpected error creating user: %v", err)
	}
	if created.DisplayName != "Charlie" {
		t.Errorf("expected Charlie, got %s", created.DisplayName)
	}

	// Update
	updated, err := client.Users.Update(ctx, "p1", "u1", UpdateUserParams{
		DisplayName: "Alice Updated",
		IsActive:    BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("unexpected error updating user: %v", err)
	}
	if updated.DisplayName != "Alice Updated" {
		t.Errorf("expected Alice Updated, got %s", updated.DisplayName)
	}

	// Delete
	err = client.Users.Delete(ctx, "p1", "u1")
	if err != nil {
		t.Fatalf("unexpected error deleting user: %v", err)
	}

	// Resend verification email
	err = client.Users.ResendVerificationEmail(ctx, "p1", "u1", "https://app.com/login")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Request password reset
	err = client.Users.RequestPasswordReset(ctx, "p1", "u1", "https://app.com/login")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invite
	invited, err := client.Users.Invite(ctx, "p1", InviteUserParams{Email: "new@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if invited.GetEmail() != "new@example.com" {
		t.Errorf("expected new@example.com, got %s", invited.GetEmail())
	}
}
