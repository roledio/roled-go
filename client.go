package roled

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBaseURL is the default production Roled API endpoint.
	DefaultBaseURL = "https://auth.roled.io"

	// DefaultUserAgent is the default User-Agent header sent by the SDK.
	DefaultUserAgent = "roled-go/0.1.0"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 15 * time.Second
)

// Client is the primary client for interacting with the Roled API.
type Client struct {
	baseURL      *url.URL
	clientID     string
	clientSecret string
	redirectURI  string
	httpClient   *http.Client
	userAgent    string

	tokenMu sync.RWMutex
	token   string

	// Auth provides methods for OAuth 2.0 PKCE, tokens, and verification.
	Auth *AuthService

	// Users provides methods for user management and self-service user operations.
	Users *UserService

	// Projects provides methods for managing Roled projects.
	Projects *ProjectService

	// Roles provides methods for managing roles and assigned permissions.
	Roles *RoleService

	// Resources provides methods for managing resources and permission domains.
	Resources *ResourceService

	// Clients provides methods for managing OAuth 2.0 clients and permissions.
	Clients *ClientService
}

// New creates and configures a new Roled Client.
func New(opts ...Option) (*Client, error) {
	return NewClient(opts...)
}

// NewClient creates and configures a new Roled Client.
func NewClient(opts ...Option) (*Client, error) {
	cfg := &clientConfig{
		baseURL:   DefaultBaseURL,
		userAgent: DefaultUserAgent,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	rawURL := strings.TrimRight(cfg.baseURL, "/")
	if rawURL == "" {
		rawURL = DefaultBaseURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("roled: invalid base URL: %w", err)
	}

	c := &Client{
		baseURL:      parsedURL,
		clientID:     cfg.clientID,
		clientSecret: cfg.clientSecret,
		redirectURI:  cfg.redirectURI,
		token:        cfg.token,
		httpClient:   cfg.httpClient,
		userAgent:    cfg.userAgent,
	}

	// Initialize services
	c.Auth = &AuthService{client: c}
	c.Users = &UserService{client: c}
	c.Projects = &ProjectService{client: c}
	c.Roles = &RoleService{client: c}
	c.Resources = &ResourceService{client: c}
	c.Clients = &ClientService{client: c}

	return c, nil
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string {
	return c.baseURL.String()
}

// ClientID returns the configured Client ID.
func (c *Client) ClientID() string {
	return c.clientID
}

// RedirectURI returns the configured Redirect URI.
func (c *Client) RedirectURI() string {
	return c.redirectURI
}

// Token returns the current default Bearer access token configured on the client.
func (c *Client) Token() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

// SetToken sets the default Bearer access token used for subsequent requests.
func (c *Client) SetToken(token string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.token = token
}

// Authenticate exchanges the client's configured client_id and client_secret
// for an OAuth 2.0 access token via client_credentials grant, and stores it
// as the client's default Bearer token.
func (c *Client) Authenticate(ctx context.Context) (*TokenResponse, error) {
	tokenResp, err := c.Auth.ExchangeClientCredentials(ctx)
	if err != nil {
		return nil, err
	}
	c.SetToken(tokenResp.AccessToken)
	return tokenResp, nil
}

// ForUser returns a stateful user session client bound to the given access and refresh tokens.
// Calls on the user session client will automatically refresh the token and retry on 401 Unauthorized.
func (c *Client) ForUser(accessToken, refreshToken string) *UserSessionClient {
	return NewUserSession(c, accessToken, refreshToken)
}

// UserSession is an alias for ForUser.
func (c *Client) UserSession(accessToken, refreshToken string) *UserSessionClient {
	return c.ForUser(accessToken, refreshToken)
}

// execute performs an HTTP request and decodes the response into dst.
func (c *Client) execute(
	ctx context.Context,
	method, path string,
	query url.Values,
	body any,
	dst any,
	reqOpts ...RequestOption,
) (*Pagination, error) {
	opts := &requestOptions{}
	for _, opt := range reqOpts {
		if opt != nil {
			opt(opts)
		}
	}

	// Build URL
	relPath := strings.TrimLeft(path, "/")
	reqURL := c.baseURL.ResolveReference(&url.URL{Path: relPath})
	if len(query) > 0 {
		reqURL.RawQuery = query.Encode()
	}

	// Build body & determine content type
	var bodyReader io.Reader
	var contentType string

	if body != nil {
		switch v := body.(type) {
		case url.Values:
			encoded := v.Encode()
			bodyReader = strings.NewReader(encoded)
			contentType = "application/x-www-form-urlencoded"
		case []byte:
			bodyReader = bytes.NewReader(v)
			contentType = "application/json"
		case string:
			bodyReader = strings.NewReader(v)
			contentType = "application/json"
		case io.Reader:
			bodyReader = v
		default:
			jsonBytes, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("roled: failed to marshal request body: %w", err)
			}
			bodyReader = bytes.NewReader(jsonBytes)
			contentType = "application/json"
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("roled: failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	// Determine Authorization
	token := opts.token
	if token == "" {
		token = c.Token()
	}
	if token != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Apply custom headers from options
	if opts.header != nil {
		for k, values := range opts.header {
			for _, v := range values {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("roled: request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("roled: failed to read response body: %w", err)
	}

	// Decode response envelope
	var envelope responseEnvelope[json.RawMessage]
	unmarshalErr := json.Unmarshal(bodyBytes, &envelope)

	// Check HTTP status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			RawBody:    string(bodyBytes),
		}

		if unmarshalErr == nil && envelope.Error != nil {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		} else {
			apiErr.Message = fmt.Sprintf("HTTP %d error", resp.StatusCode)
		}

		return nil, apiErr
	}

	// Even if status is 2xx, check if envelope indicated failure
	if unmarshalErr == nil && !envelope.Success && envelope.Error != nil {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Code:       envelope.Error.Code,
			Message:    envelope.Error.Message,
			RawBody:    string(bodyBytes),
		}
	}

	// If destination provided, unmarshal data
	if dst != nil && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		if err := json.Unmarshal(envelope.Data, dst); err != nil {
			return nil, fmt.Errorf("roled: failed to unmarshal response data: %w", err)
		}
	}

	return envelope.Pagination, nil
}
