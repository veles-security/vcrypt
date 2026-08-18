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
	return capabilities[PRIVATE_MATERIAL]
}

func (b *privateBackend) signatureOptions(options ...key.SignOption) (crypto.Hash, bool, error) {
	if len(options) != 1 {
		return 0, false, fmt.Errorf("RSA backend: expected 1 signature algorith option, got %d", len(options))
	}
	alg := options[0]
	switch key.KeyAlg(alg) {
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

// Sign implements [key.Backend].
func (b *privateBackend) Sign(ctx context.Context, message []byte, options ...key.SignOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, ok := b.material.Key.(*stdrsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA backend: key material is not an RSA private key")
	}
	hash, isPss, err := b.signatureOptions(options...)
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

// VerifySignature implements [key.Backend].
func (b *privateBackend) VerifySignature(ctx context.Context, signature []byte, message []byte, options ...key.VerifyOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	privateKey, ok := b.material.Key.(*stdrsa.PrivateKey)
	if !ok {
		return fmt.Errorf("RSA backend: key material is not an RSA private key")
	}
	hash, isPss, err := b.signatureOptions(key.SignOption(options[0]))
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

var _ key.Backend = &privateBackend{}
