package ec

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
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
func (b *privateBackend) Sign(ctx context.Context, algorithm key.KeyAlg, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privateKey, ok := b.material.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("EC backend: key material is not an ECDSA private key")
	}
	hash, err := signatureOptions(&privateKey.PublicKey, algorithm)
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
func (b *privateBackend) VerifySignature(ctx context.Context, algorithm key.KeyAlg, signature []byte, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	privateKey, ok := b.material.Key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("EC backend: key material is not an ECDSA private key")
	}
	hash, err := signatureOptions(&privateKey.PublicKey, algorithm)
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

// Encrypt implements [key.Backend].
func (b *privateBackend) Encrypt(context.Context, key.KeyAlg, []byte) ([]byte, error) {
	return nil, errors.New("EC backend: unsupported operation")
}

// Decrypt implements [key.Backend].
func (b *privateBackend) Decrypt(context.Context, key.KeyAlg, []byte) ([]byte, error) {
	return nil, errors.New("EC backend: unsupported operation")
}

var _ key.Backend = &privateBackend{}
