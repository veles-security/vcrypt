package jws

import (
	"context"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keystore"
)

// WithVerifierAlg configures the signature algorithm accepted by the verifier.
func WithVerifierAlg(algorithm key.KeyAlg) VerifierOption {
	return func(next VerifyFunc) VerifyFunc {
		return func(ctx context.Context, message []byte, signature []byte, options ...keystore.VerifyOption) error {
			algorithmOption := keystore.VerifyOption(keystore.WithAlgorithms(algorithm))
			return next(ctx, message, signature, append(options, algorithmOption)...)
		}
	}
}
