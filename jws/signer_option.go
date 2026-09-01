package jws

import (
	"context"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keystore"
)

// WithSignerAlg configures the signature algorithm used by the signer.
func WithSignerAlg(algorithm key.KeyAlg) SignerOption {
	return func(next SignFunc) SignFunc {
		return func(ctx context.Context, claims []byte, headerFunc HeaderFunc, options ...keystore.SignOption) (JWS, error) {
			algorithmOption := keystore.SignOption(keystore.WithAlgorithms(algorithm))
			return next(ctx, claims, headerFunc, append(options, algorithmOption)...)
		}
	}
}

// WithSignerKeys restricts verification to keys matching selector.
func WithSignerKeys(selector key.Selector) SignerOption {
	return func(next SignFunc) SignFunc {
		return func(ctx context.Context, claims []byte, headerFunc HeaderFunc, options ...keystore.SignOption) (JWS, error) {
			keyOption := keystore.SignOption(keystore.WithKeys(selector))
			return next(ctx, claims, headerFunc, append(options, keyOption)...)
		}
	}
}
