package roled

import "net/http"

type clientConfig struct {
	baseURL      string
	clientID     string
	clientSecret string
	redirectURI  string
	token        string
	httpClient   *http.Client
	userAgent    string
}

// Option represents a configuration option for NewClient.
type Option func(*clientConfig)

// WithBaseURL sets a custom base URL for the Roled API (default: https://auth.roled.io).
func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) {
		c.baseURL = baseURL
	}
}

// WithClientID sets the OAuth 2.0 client ID.
func WithClientID(clientID string) Option {
	return func(c *clientConfig) {
		c.clientID = clientID
	}
}

// WithClientSecret sets the OAuth 2.0 client secret.
func WithClientSecret(clientSecret string) Option {
	return func(c *clientConfig) {
		c.clientSecret = clientSecret
	}
}

// WithRedirectURI sets the default OAuth 2.0 redirect URI.
func WithRedirectURI(redirectURI string) Option {
	return func(c *clientConfig) {
		c.redirectURI = redirectURI
	}
}

// WithToken sets an OAuth 2.0 Bearer access token for authenticating requests.
func WithToken(token string) Option {
	return func(c *clientConfig) {
		c.token = token
	}
}

// WithBearerToken is an alias for WithToken.
func WithBearerToken(token string) Option {
	return WithToken(token)
}

// WithHTTPClient specifies a custom http.Client to use for requests.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *clientConfig) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithUserAgent specifies a custom User-Agent string.
func WithUserAgent(userAgent string) Option {
	return func(c *clientConfig) {
		c.userAgent = userAgent
	}
}

// requestOptions holds options for a single API request.
type requestOptions struct {
	token  string
	header http.Header
}

// RequestOption represents a functional option applied to an individual API request.
type RequestOption func(*requestOptions)

// WithRequestToken overrides the Bearer token for a single API call.
func WithRequestToken(token string) RequestOption {
	return func(opts *requestOptions) {
		opts.token = token
	}
}

// WithHeader adds a custom HTTP header to a single API call.
func WithHeader(key, value string) RequestOption {
	return func(opts *requestOptions) {
		if opts.header == nil {
			opts.header = make(http.Header)
		}
		opts.header.Set(key, value)
	}
}
