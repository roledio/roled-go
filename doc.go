// Package roled provides the official Go SDK for the Roled API.
//
// Roled provides a centralized platform for managing users, roles, and permissions across multiple applications.
//
// Key features of this SDK:
//   - Complete OAuth 2.0 PKCE flow support (verifier, challenge, authorize URL, code exchange)
//   - Stateful User Session client (ForUser) with automatic token refresh and retry on 401 Unauthorized
//   - Full RBAC management (Projects, Roles, Resources, Permissions, Clients, Users)
//   - Support for both Fully Managed and Bring-Your-Own-User (BYOU) models
//   - Rich error handling with HTTP status codes and typed API error codes
//   - Idiomatic Go with context.Context, functional options, zero external dependencies
package roled
