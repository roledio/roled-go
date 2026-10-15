<img src="https://roled.io/images/roled-logo-text-dark.png" alt="Roled" style="height: 48px;" /><br/>

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=roledio_roled-go&metric=coverage)](https://sonarcloud.io/summary/new_code?id=roledio_roled-go)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=roledio_roled-go&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=roledio_roled-go)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=roledio_roled-go&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=roledio_roled-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/roledio/roled-go.svg)](https://pkg.go.dev/github.com/roledio/roled-go)
[![License](https://img.shields.io/github/license/roledio/roled-go)](https://github.com/roledio/roled-go/blob/main/LICENSE)

# Go SDK

The official Go SDK for accessing [Roled](https://roled.io/) APIs.

## Installation

Requires Go 1.22 or later.

```bash
go get github.com/roledio/roled-go
```

## Usage Guide

### 1. User Authentication (OAuth 2.0 PKCE Flow)

#### Step 1: Generate PKCE & Redirect to Authorization URL

```go
package main

import (
	"net/http"
	"github.com/roledio/roled-go"
)

func handleLogin(client *roled.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Generate PKCE code verifier and challenge
		verifier, err := roled.GenerateCodeVerifier()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		challenge := roled.ComputeCodeChallenge(verifier)

		// 2. Generate random state parameter (anti-CSRF)
		state, err := roled.GenerateState()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Store verifier and state in session / secure cookie
		saveSession(r, w, "code_verifier", verifier)
		saveSession(r, w, "oauth_state", state)

		// 3. Build Roled authorization URL
		authURL, err := client.Auth.BuildAuthorizeURL(roled.AuthorizeURLParams{
			CodeChallenge: challenge,
			State:         state,
			IsSignup:      false, // Set to true to open sign-up view by default
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 4. Redirect user to Roled login screen
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
```

#### Step 2: Handle OAuth Callback & Exchange Code for Tokens

```go
func handleCallback(client *roled.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Verify state parameter
		if r.URL.Query().Get("state") != getSession(r, "oauth_state") {
			http.Error(w, "invalid state parameter", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		verifier := getSession(r, "code_verifier")

		// Exchange authorization code for access and refresh tokens
		tokens, err := client.Auth.ExchangeAuthorizationCode(ctx, roled.ExchangeAuthorizationCodeParams{
			Code:         code,
			CodeVerifier: verifier,
		})
		if err != nil {
			http.Error(w, "token exchange failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Persist tokens in user session
		saveUserSession(w, tokens.AccessToken, tokens.RefreshToken)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}
```


### 2. Stateful User Sessions with Automatic Token Refresh (`client.ForUser`)

Wrap user tokens in `client.ForUser(accessToken, refreshToken)`. When user-scoped endpoints receive `401 Unauthorized`, the client automatically calls `RefreshToken`, updates its internal state, and retries the request once:

```go
func handleDashboard(client *roled.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		accessToken, refreshToken := getUserTokens(r)

		// Create user session client
		userClient := client.ForUser(accessToken, refreshToken)

		// Retrieve authenticated user profile with permissions
		user, err := userClient.GetCurrentUser(ctx, roled.WithIncludePermissions(true))
		if err != nil {
			if roled.IsUnauthorized(err) {
				// Refresh token expired; redirect to login
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "failed to get profile", http.StatusInternalServerError)
			return
		}

		// Check if tokens were refreshed during the request
		if userClient.IsRefreshed() {
			newAccess, newRefresh := userClient.Tokens()
			saveUserSession(w, newAccess, newRefresh)
		}

		// Check permissions
		if user.HasPermission("products:create") {
			// User can create products
		}

		fmt.Fprintf(w, "Hello %s! Role: %s", user.GetDisplayName(), user.RoleName)
	}
}
```

#### Updating User Profile & Logout

```go
// Update current authenticated user profile
err := userClient.UpdateCurrentUser(ctx, roled.UpdateCurrentUserParams{
	DisplayName: "Alice Smith",
	Email:       "alice@example.com",
	AvatarURL:   roled.StringPtr("https://example.com/avatar.png"),
})

// Revoke current session (Logout)
err = userClient.Revoke(ctx)
```


### 3. Backend Service Authentication (`client_credentials`)

Backend services use `client_id` and `client_secret` to obtain an OAuth 2.0 access token:

```go
client, err := roled.NewClient(
	roled.WithClientID("backend_client_id"),
	roled.WithClientSecret("backend_client_secret"),
)

// Authenticate via client_credentials flow
tokenResp, err := client.Authenticate(ctx)
if err != nil {
	log.Fatalf("failed to authenticate: %v", err)
}

// All subsequent calls on client now use the obtained Bearer token
```

Alternatively, if you already have a Bearer token:

```go
client, err := roled.NewClient(
	roled.WithToken("YOUR_OAUTH2_ACCESS_TOKEN"),
)
```


### 4. User Management (Project Scoped)

```go
projectID := "2JUSLUee46xG6iEwG8JwPc"

// 1. List users with pagination and search
userList, err := client.Users.List(ctx, projectID, roled.ListUsersParams{
	ListParams: roled.ListParams{
		PageNum:  1,
		PageSize: 20,
		SortBy:   "created_at",
		SortDir:  "desc",
		Search:   "alice",
	},
	IsActive: roled.BoolPtr(true),
})

// 2. Create Fully Managed user (Email + Password)
newUser, err := client.Users.Create(ctx, projectID, roled.CreateUserParams{
	DisplayName: "Alice Smith",
	Email:       roled.StringPtr("alice@example.com"),
	Password:    roled.StringPtr("SecurePassword123!"),
	RoleID:      roled.StringPtr("role_store_manager"),
})

// 3. Create BYOU user (Bring-Your-Own-User)
byouUser, err := client.Users.Create(ctx, projectID, roled.CreateUserParams{
	DisplayName:    "Bob Johnson",
	ExternalUserID: roled.StringPtr("custom-crm-user-987"),
	RoleID:         roled.StringPtr("role_inventory_staff"),
})

// 4. Get user by ID or by External ID
user, err := client.Users.Get(ctx, projectID, newUser.ID, roled.WithIncludePermissions(true))
byou, err := client.Users.GetByExternalID(ctx, projectID, "custom-crm-user-987")

// 5. Update user
updated, err := client.Users.Update(ctx, projectID, newUser.ID, roled.UpdateUserParams{
	DisplayName: "Alice S.",
	IsActive:    roled.BoolPtr(true),
	RoleID:      roled.StringPtr("role_admin"),
})

// 6. Delete user
err = client.Users.Delete(ctx, projectID, newUser.ID)

// 7. Invite user via email
invited, err := client.Users.Invite(ctx, projectID, roled.InviteUserParams{
	Email:  "partner@example.com",
	RoleID: roled.StringPtr("role_guest"),
})
```


### 5. Role-Based Access Control (RBAC)

#### Roles

```go
// Create role with assigned permission IDs
newRole, err := client.Roles.Create(ctx, projectID, roled.CreateRoleParams{
	Code:        "store-manager",
	Name:        "Store Manager",
	Description: "Manages store products and inventory",
	PermissionIDs: []string{
		"perm_products_read",
		"perm_products_create",
		"perm_products_update",
	},
})

// List roles
roles, err := client.Roles.List(ctx, projectID, roled.ListRolesParams{})
```

#### Resources & Permissions

```go
// Define custom resource domain with CRUD action permissions
resource, err := client.Resources.Create(ctx, projectID, roled.CreateResourceParams{
	Name: "Products",
	Code: "products",
	Permissions: []roled.CreatePermissionParams{
		{Name: "Create Product", Code: "create"},
		{Name: "Read Product", Code: "read"},
		{Name: "Update Product", Code: "update"},
		{Name: "Delete Product", Code: "delete"},
	},
})

// List all permissions across the project
permissions, err := client.Resources.ListPermissions(ctx, projectID, roled.ListPermissionsParams{})
```


### 6. Error Handling

All API errors return a structured `*roled.APIError`. Sentinel helpers let you inspect errors without string matching:

```go
user, err := client.Users.Get(ctx, projectID, userID)
if err != nil {
	if roled.IsUnauthorized(err) {
		// 401: Token missing, invalid, or expired
	} else if roled.IsForbidden(err) {
		// 403: Insufficient permission
	} else if roled.IsNotFound(err) {
		// 404: User or project not found
	} else if roled.IsConflict(err) {
		// 409: Duplicate email or external user ID
	} else {
		var apiErr *roled.APIError
		if errors.As(err, &apiErr) {
			fmt.Printf("Roled Error Code: %s, HTTP Status: %d, Message: %s\n",
				apiErr.Code, apiErr.StatusCode, apiErr.Message)
		}
	}
}
```


### 7. Client Configuration Options

```go
client, err := roled.NewClient(
	// Base URL (defaults to https://auth.roled.io)
	roled.WithBaseURL("https://roled.app.com"),

	// OAuth 2.0 Credentials
	roled.WithClientID("YOUR_CLIENT_ID"),
	roled.WithClientSecret("YOUR_CLIENT_SECRET"),
	roled.WithRedirectURI("https://app.com/callback"),

	// Pre-configured OAuth 2.0 Bearer token
	roled.WithToken("YOUR_OAUTH2_BEARER_TOKEN"),

	// Custom HTTP client
	roled.WithHTTPClient(&http.Client{
		Timeout: 20 * time.Second,
	}),

	// Custom User-Agent header
	roled.WithUserAgent("my-app/1.0"),
)
```
