//go:build !with_unsafe_crypto

package rsa

import (
	stdrsa "crypto/rsa"
	"fmt"
	"hash"

	"github.com/veles-security/vcrypt/key"
)

const unsafeCryptoEnabled = false

var unsafeCryptoCapabilities = map[MaterialType][]key.Capability{}

func unsafeEncryptionHash() (hash.Hash, error) {
	return nil, fmt.Errorf("RSA backend: encryption algorithm %q requires the with_unsafe_crypto build tag", RSAOAEP)
}

func unsafeEncryptPKCS1v15(_ *stdrsa.PublicKey, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("RSA backend: encryption algorithm %q requires the with_unsafe_crypto build tag", RSA1_5)
}

func unsafeDecryptPKCS1v15(_ *stdrsa.PrivateKey, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("RSA backend: encryption algorithm %q requires the with_unsafe_crypto build tag", RSA1_5)
}
