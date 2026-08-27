package jwksendpoint

import (
	"slices"

	"github.com/veles-security/vcrypt/jwks"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keystore"
)

func WithKeystore(keystore keystore.Keystore) JwksEndpointConfigOption {
	return func(endpoint *JwksEndpoint) error {
		endpoint.keystore = keystore
		return nil
	}
}

func WithKeySelector(selector key.Selector) JwksEndpointConfigOption {
	return func(endpoint *JwksEndpoint) error {
		endpoint.selector = selector
		return nil
	}
}

// WithJwksWriterOption forwards configuration options to the JWKS writer
// constructed by the endpoint.
func WithJwksWriterOption(options ...jwks.WriterConfigOption) JwksEndpointConfigOption {
	return func(endpoint *JwksEndpoint) error {
		endpoint.writerOptions = append(endpoint.writerOptions, slices.Clone(options)...)
		return nil
	}
}
