//go:build !with_unsafe_crypto

package symetric

import (
	"fmt"

	"github.com/veles-security/vcrypt/key"
)

const unsafeCryptoEnabled = false

var unsafeCryptoCapabilities []key.Capability

func unsafeEncrypt(_ []byte, algorithm key.KeyAlg, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("symetric backend: encryption algorithm %q requires the with_unsafe_crypto build tag", algorithm)
}

func unsafeDecrypt(_ []byte, algorithm key.KeyAlg, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("symetric backend: encryption algorithm %q requires the with_unsafe_crypto build tag", algorithm)
}
