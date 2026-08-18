package rsa

import (
	"context"
	"crypto"
	stdrsa "crypto/rsa"
	"errors"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type publicBackend struct {
	material material.PublicMaterial
}

func (b *publicBackend) signatureOptions(options ...key.SignOption) (crypto.Hash, bool, error) {
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

// Capabilities implements [key.Backend].
func (p *publicBackend) Capabilities() []key.Capability {
	return capabilities[PUBLIC_MATERIAL]
}

// Sign implements [key.Backend].
func (p *publicBackend) Sign(ctx context.Context, message []byte, options ...key.SignOption) ([]byte, error) {
	return nil, errors.New("RSA backend: unsupported operation")
}

// Supports implements [key.Backend].
func (p *publicBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range capabilities[PUBLIC_MATERIAL] {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}

	return false
}

// VerifySignature implements [key.Backend].
func (p *publicBackend) VerifySignature(ctx context.Context, signature []byte, message []byte, options ...key.VerifyOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, ok := p.material.Key.(*stdrsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSA backend: key material is not an RSA public key")
	}
	if len(options) != 1 {
		return fmt.Errorf("RSA backend: expected 1 signature algorith option, got %d", len(options))
	}
	hash, isPss, err := p.signatureOptions(key.SignOption(options[0]))
	if err != nil {
		return err
	}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return err
	}
	if isPss {
		return stdrsa.VerifyPSS(publicKey, hash, digest, signature, &stdrsa.PSSOptions{
			SaltLength: stdrsa.PSSSaltLengthEqualsHash,
		})
	}
	return stdrsa.VerifyPKCS1v15(publicKey, hash, digest, signature)
}

var _ key.Backend = &publicBackend{}
