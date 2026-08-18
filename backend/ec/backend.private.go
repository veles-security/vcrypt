package ec

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

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

// Sign implements [key.Backend].
func (b *privateBackend) Sign(ctx context.Context, message []byte, options ...key.SignOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privateKey, ok := b.material.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("EC backend: key material is not an ECDSA private key")
	}
	hash, err := signatureOptions(&privateKey.PublicKey, options...)
	if err != nil {
		return nil, err
	}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, privateKey, digest)
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
	privateKey, ok := b.material.Key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("EC backend: key material is not an ECDSA private key")
	}
	signOptions := make([]key.SignOption, len(options))
	for i, option := range options {
		signOptions[i] = key.SignOption(option)
	}
	hash, err := signatureOptions(&privateKey.PublicKey, signOptions...)
	if err != nil {
		return err
	}
	digest, err := hashMessage(hash, message)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature) {
		return fmt.Errorf("EC backend: invalid signature")
	}
	return nil
}

var _ key.Backend = &privateBackend{}
