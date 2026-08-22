// Package jwkssource loads and periodically refreshes keys from a remote JSON
// Web Key Set endpoint.
package jwkssource

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/veles-security/vcrypt/descriptor"
)

// Option configures a JWKS source.
type Option func(*Source) error

// WithHTTPClient configures the client used to request the JWKS endpoint. The
// caller retains ownership of the client and its transport.
func WithHTTPClient(client *http.Client) Option {
	return func(source *Source) error {
		if client == nil {
			return fmt.Errorf("JWKS source HTTP client is nil")
		}
		source.client = client
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

	source := &Source{
		id:        id,
		url:       parsedURL.String(),
		frequency: frequency,
		client:    http.DefaultClient,
		decoder:   descriptor.NewJWKSDecoder(),
	}
	for _, option := range options {
		if option != nil {
			if err := option(source); err != nil {
				return nil, err
			}
		}
	}
	return source, nil
}
