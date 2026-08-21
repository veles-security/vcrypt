package ec

import (
	"context"
	"crypto/ecdsa"
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

// Supports implements [key.Backend].
func (b *publicBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range capabilities[PUBLIC_MATERIAL] {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}
	return false
}

// VerifySignature implements [key.SignatureVerifier].
func (b *publicBackend) VerifySignature(ctx context.Context, algorithm key.KeyAlg, signature []byte, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, ok := b.material.Key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("EC backend: key material is not an ECDSA public key")
	}
	hash, err := signatureOptions(publicKey, algorithm)
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
var _ key.SignatureVerifier = &publicBackend{}
