package jws

import (
	"fmt"

	"github.com/veles-security/vcrypt/keystore"
)

// WithVerifierRuntimeOptions configures verifier options that are applied to
// every Verify call before its per-call options.
func WithVerifierRuntimeOptions(options ...VerifierOption) VerifierConfigOption {
	return func(verifier *Verifier) error {
		if verifier == nil {
			return fmt.Errorf("JWS: nil verifier")
		}
		verifier.runtimeOptions = append([]VerifierOption(nil), options...)
		return nil
	}
}

// WithVerifierKeystore configures the keystore used to verify signatures.
func WithVerifierKeystore(store *keystore.Keystore) VerifierConfigOption {
	return func(verifier *Verifier) error {
		if verifier == nil {
			return fmt.Errorf("JWS: nil verifier")
		}
		if store == nil || *store == nil {
			return fmt.Errorf("JWS: nil keystore")
		}
		verifier.keystore = *store
		return nil
	}
}
