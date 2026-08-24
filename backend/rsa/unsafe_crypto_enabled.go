//go:build with_unsafe_crypto

package rsa

import (
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha1" // #nosec G505 -- explicitly enabled for legacy RSA-OAEP interoperability
	"hash"

	"github.com/veles-security/vcrypt/key"
)

const unsafeCryptoEnabled = true

var unsafeCryptoCapabilities = map[MaterialType][]key.Capability{
	PUBLIC_MATERIAL: {
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSA1_5},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP},
	},
	PRIVATE_MATERIAL: {
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSA1_5},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSA1_5},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP},
	},
}

func unsafeEncryptionHash() (hash.Hash, error) {
	return sha1.New(), nil // nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
}

func unsafeEncryptPKCS1v15(publicKey *stdrsa.PublicKey, plaintext []byte) ([]byte, error) {
	return stdrsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
}

func unsafeDecryptPKCS1v15(privateKey *stdrsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return stdrsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}
