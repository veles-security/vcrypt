package rsa

import (
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/veles-security/vcrypt/key"
)

func encryptionHash(algorithm key.KeyAlg) (hash.Hash, error) {
	switch algorithm {
	case RSAOAEP:
		return unsafeEncryptionHash()
	case RSAOAEP256:
		return sha256.New(), nil
	case RSAOAEP384:
		return sha512.New384(), nil
	case RSAOAEP512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("RSA backend: unsupported encryption algorithm %q", algorithm)
	}
}

func encrypt(publicKey *stdrsa.PublicKey, algorithm key.KeyAlg, plaintext []byte) ([]byte, error) {
	if algorithm == RSA1_5 {
		return unsafeEncryptPKCS1v15(publicKey, plaintext)
	}
	hash, err := encryptionHash(algorithm)
	if err != nil {
		return nil, err
	}
	return stdrsa.EncryptOAEP(hash, rand.Reader, publicKey, plaintext, nil)
}

func decrypt(privateKey *stdrsa.PrivateKey, algorithm key.KeyAlg, ciphertext []byte) ([]byte, error) {
	if algorithm == RSA1_5 {
		return unsafeDecryptPKCS1v15(privateKey, ciphertext)
	}
	hash, err := encryptionHash(algorithm)
	if err != nil {
		return nil, err
	}
	return stdrsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
}
