// Package jwkssource loads and periodically refreshes keys from a remote JSON
// Web Key Set endpoint.
package jwkssource

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/veles-security/vcrypt/jwks"
)

const defaultHTTPTimeout = 30 * time.Second

// Option configures a JWKS source.
type Option func(*Source) error

// WithInsecureHTTP permits loading a JWKS over unauthenticated HTTP. HTTPS is
// required by default because an attacker who can modify a JWKS response can
// replace the keys trusted by its consumers.
func WithInsecureHTTP() Option {
	return func(source *Source) error {
		source.allowHTTP = true
		return nil
	}
}

// WithHTTPClient configures the client used to request the JWKS endpoint. The
// caller retains ownership of the client and its transport. Supplying a client
// also makes the caller responsible for configuring its timeout policy.
func WithHTTPClient(client *http.Client) Option {
	return func(source *Source) error {
		if client == nil {
			return fmt.Errorf("JWKS source HTTP client is nil")
		}
		source.client = client
		source.ownsClient = false
		return nil
	}
}

// New creates a source which reloads url at the provided frequency.
func New(id, rawURL string, frequency time.Duration, options ...Option) (*Source, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("JWKS source ID is empty")
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return nil, fmt.Errorf("JWKS source URL %q is invalid", rawURL)
	}
	if frequency <= 0 {
		return nil, fmt.Errorf("JWKS source frequency must be positive")
	}

	lifecycleContext, cancel := context.WithCancel(context.Background())
	decoder, err := jwks.NewDecoder()
	if err != nil {
		return nil, fmt.Errorf("JWKS source: decoder init failed: %w", err)
	}
	source := &Source{
		id:         id,
		url:        parsedURL.String(),
		frequency:  frequency,
		client:     &http.Client{Timeout: defaultHTTPTimeout},
		ownsClient: true,
		decoder:    decoder,
		ctx:        lifecycleContext,
		cancel:     cancel,
	}
	for _, option := range options {
		if option != nil {
			if err := option(source); err != nil {
				cancel()
				return nil, err
			}
		}
	}
	if parsedURL.Scheme == "http" && !source.allowHTTP {
		cancel()
		return nil, fmt.Errorf("JWKS source URL %q uses insecure HTTP; use WithInsecureHTTP to permit it", rawURL)
	}
	return source, nil
}
