package jws

import (
	"fmt"

	"github.com/veles-security/vcrypt/keystore"
)

// WithSignerRuntimeOptions configures signer options that are applied to every
// Sign call before its per-call options.
func WithSignerRuntimeOptions(options ...SignerOption) SignerConfigOption {
	return func(signer *Signer) error {
		signer.runtimeOptions = append([]SignerOption(nil), options...)
		return nil
	}
}

func WithSignerKeystore(keystore *keystore.Keystore) SignerConfigOption {
	return func(s *Signer) error {
		if keystore == nil {
			return fmt.Errorf("JWS: nil keystore")
		}
		s.keystore = *keystore
		return nil
	}
}
