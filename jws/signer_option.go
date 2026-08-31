package jws

import (
	"context"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keystore"
)

// WithAlgorithm configures the signature algorithm used by the signer.
func WithAlgorithm(algorithm key.KeyAlg) SignerOption {
	return func(next SignFunc) SignFunc {
		return func(ctx context.Context, claims []byte, headerFunc HeaderFunc, options ...keystore.SignOption) (JWS, error) {
			algorithmOption := keystore.SignOption(keystore.WithAlgorithms(algorithm))
			return next(ctx, claims, headerFunc, append(options, algorithmOption)...)
		}
	}
}
