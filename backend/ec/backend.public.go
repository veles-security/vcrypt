package ec

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type publicBackend struct {
	material material.PublicMaterial
}

// Capabilities implements [key.Backend].
func (b *publicBackend) Capabilities() []key.Capability {
	return capabilities[PUBLIC_MATERIAL]
}

// Sign implements [key.Backend].
func (b *publicBackend) Sign(ctx context.Context, message []byte, options ...key.SignOption) ([]byte, error) {
	return nil, errors.New("EC backend: unsupported operation")
}

// Supports implements [key.Backend].
func (b *publicBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range capabilities[PUBLIC_MATERIAL] {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}
	return false
}

// VerifySignature implements [key.Backend].
func (b *publicBackend) VerifySignature(ctx context.Context, signature []byte, message []byte, options ...key.VerifyOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, ok := b.material.Key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("EC backend: key material is not an ECDSA public key")
	}
	signOptions := make([]key.SignOption, len(options))
	for i, option := range options {
		signOptions[i] = key.SignOption(option)
	}
	hash, err := signatureOptions(publicKey, signOptions...)
	if err != nil {
		return err
	}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(publicKey, digest, signature) {
		return fmt.Errorf("EC backend: invalid signature")
	}
	return nil
}

var _ key.Backend = &publicBackend{}
