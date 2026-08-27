package rsa

import (
	"context"
	"crypto"
	"fmt"

	"crypto/rand"
	stdrsa "crypto/rsa"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type privateBackend struct {
	material material.PrivateMaterial
}

// Capabilities implements [key.Backend].
func (b *privateBackend) Capabilities() []key.Capability {
	return append([]key.Capability(nil), capabilities[PRIVATE_MATERIAL]...)
}

func (b *privateBackend) signatureOptions(alg key.KeyAlg) (crypto.Hash, bool, error) {
	switch alg {
	case RS256:
		return crypto.SHA256, false, nil
	case RS384:
		return crypto.SHA384, false, nil
	case RS512:
		return crypto.SHA512, false, nil
	case PS256:
		return crypto.SHA256, true, nil
	case PS384:
		return crypto.SHA384, true, nil
	case PS512:
		return crypto.SHA512, true, nil
	default:
		return 0, false, fmt.Errorf("RSA backend: unsupported signature algorithm %q", alg)
	}
}

// Sign implements [key.Signer].
func (b *privateBackend) Sign(ctx context.Context, algorithm key.KeyAlg, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, ok := b.material.Key.(*stdrsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA backend: key material is not an RSA private key")
	}
	hash, isPss, err := b.signatureOptions(algorithm)
	if err != nil {
		return nil, err
	}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return nil, err
	}
	if isPss {
		return stdrsa.SignPSS(rand.Reader, key, hash, digest, &stdrsa.PSSOptions{
			SaltLength: stdrsa.PSSSaltLengthEqualsHash,
		})
	}
	return stdrsa.SignPKCS1v15(rand.Reader, key, hash, digest)
}

// Supports implements [key.Backend].
func (b *privateBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range capabilities[PRIVATE_MATERIAL] {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}

	return false
}

// Verify implements [key.Verifier].
func (b *privateBackend) Verify(ctx context.Context, algorithm key.KeyAlg, signature []byte, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	privateKey, ok := b.material.Key.(*stdrsa.PrivateKey)
	if !ok {
		return fmt.Errorf("RSA backend: key material is not an RSA private key")
	}
	hash, isPss, err := b.signatureOptions(algorithm)
	if err != nil {
		return err
	}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return err
	}
	if isPss {
		return stdrsa.VerifyPSS(&privateKey.PublicKey, hash, digest, signature, &stdrsa.PSSOptions{
			SaltLength: stdrsa.PSSSaltLengthEqualsHash,
		})
	}
	return stdrsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature)
}

// Encrypt implements [key.Encrypter].
func (b *privateBackend) Encrypt(ctx context.Context, algorithm key.KeyAlg, plaintext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privateKey, ok := b.material.Key.(*stdrsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA backend: key material is not an RSA private key")
	}
	return encrypt(&privateKey.PublicKey, algorithm, plaintext)
}

// Decrypt implements [key.Decrypter].
func (b *privateBackend) Decrypt(ctx context.Context, algorithm key.KeyAlg, ciphertext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privateKey, ok := b.material.Key.(*stdrsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA backend: key material is not an RSA private key")
	}
	return decrypt(privateKey, algorithm, ciphertext)
}

var _ key.Backend = &privateBackend{}
var _ key.Signer = &privateBackend{}
var _ key.Verifier = &privateBackend{}
var _ key.Encrypter = &privateBackend{}
var _ key.Decrypter = &privateBackend{}
