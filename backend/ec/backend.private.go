package ec

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

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

// Sign implements [key.Signer].
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
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("EC backend: sign digest: %w", err)
	}
	return encodeSignature(&privateKey.PublicKey, r, s)
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

// VerifySignature implements [key.SignatureVerifier].
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
	if !verifySignature(&privateKey.PublicKey, digest, signature) {
		return fmt.Errorf("EC backend: invalid signature")
	}
	return nil
}

// encodeSignature encodes an ECDSA signature using the fixed-width R || S
// representation required by JOSE (RFC 7518, section 3.4).
func encodeSignature(publicKey *ecdsa.PublicKey, r, s *big.Int) ([]byte, error) {
	if publicKey == nil || publicKey.Curve == nil || publicKey.Curve.Params() == nil || r == nil || s == nil {
		return nil, fmt.Errorf("EC backend: invalid signature values")
	}
	size := (publicKey.Curve.Params().N.BitLen() + 7) / 8
	signature := make([]byte, 2*size)
	r.FillBytes(signature[:size])
	s.FillBytes(signature[size:])
	return signature, nil
}

func verifySignature(publicKey *ecdsa.PublicKey, digest, signature []byte) bool {
	if publicKey == nil || publicKey.Curve == nil || publicKey.Curve.Params() == nil {
		return false
	}
	size := (publicKey.Curve.Params().N.BitLen() + 7) / 8
	if len(signature) != 2*size {
		return false
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	return ecdsa.Verify(publicKey, digest, r, s)
}

var _ key.Backend = &privateBackend{}
var _ key.Signer = &privateBackend{}
var _ key.SignatureVerifier = &privateBackend{}
