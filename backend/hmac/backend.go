package hmac

import (
	"context"
	"crypto"
	stdhmac "crypto/hmac"
	"errors"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type symmetricBackend struct {
	material material.SymmetricMaterial
}

func (b *symmetricBackend) signatureOptions(algorithm key.KeyAlg) (crypto.Hash, error) {
	var hash crypto.Hash
	switch alg := algorithm; alg {
	case HS256:
		hash = crypto.SHA256
	case HS384:
		hash = crypto.SHA384
	case HS512:
		hash = crypto.SHA512
	default:
		return 0, fmt.Errorf("HMAC backend: unsupported signature algorithm %q", alg)
	}
	if !hash.Available() {
		return 0, fmt.Errorf("HMAC backend: hash %v is unavailable", hash)
	}
	if len(b.material.Key) < hash.Size() {
		return 0, fmt.Errorf("HMAC backend: key is too short: got %d bytes, require at least %d", len(b.material.Key), hash.Size())
	}
	return hash, nil
}

// Capabilities implements [key.Backend].
func (b *symmetricBackend) Capabilities() []key.Capability {
	return capabilities
}

// Sign implements [key.Backend].
func (b *symmetricBackend) Sign(ctx context.Context, algorithm key.KeyAlg, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hash, err := b.signatureOptions(algorithm)
	if err != nil {
		return nil, err
	}
	mac := stdhmac.New(hash.New, b.material.Key)
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}

// Supports implements [key.Backend].
func (b *symmetricBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range capabilities {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}
	return false
}

// VerifySignature implements [key.Backend].
func (b *symmetricBackend) VerifySignature(ctx context.Context, algorithm key.KeyAlg, signature []byte, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	hash, err := b.signatureOptions(algorithm)
	if err != nil {
		return err
	}
	mac := stdhmac.New(hash.New, b.material.Key)
	_, _ = mac.Write(message)
	if !stdhmac.Equal(signature, mac.Sum(nil)) {
		return fmt.Errorf("HMAC backend: invalid signature")
	}
	return nil
}

// Encrypt implements [key.Backend].
func (b *symmetricBackend) Encrypt(context.Context, key.KeyAlg, []byte) ([]byte, error) {
	return nil, errors.New("HMAC backend: unsupported operation")
}

// Decrypt implements [key.Backend].
func (b *symmetricBackend) Decrypt(context.Context, key.KeyAlg, []byte) ([]byte, error) {
	return nil, errors.New("HMAC backend: unsupported operation")
}

var _ key.Backend = &symmetricBackend{}
