package jws

import (
	"fmt"

	"github.com/veles-security/vcrypt/keystore"
)

func WithSignerKeystore(keystore *keystore.Keystore) SignerConfigOption {
	return func(s *Signer) error {
		if keystore == nil {
			return fmt.Errorf("JWS: nil keystore")
		}
		s.keystore = *keystore
		return nil
	}
}
