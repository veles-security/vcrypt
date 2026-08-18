package hmac

import (
	"context"
	"crypto"
	stdhmac "crypto/hmac"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type symmetricBackend struct {
	material material.SymmetricMaterial
}

func (b *symmetricBackend) signatureOptions(options ...key.SignOption) (crypto.Hash, error) {
	if len(options) != 1 {
		return 0, fmt.Errorf("HMAC backend: expected 1 signature algorithm option, got %d", len(options))
	}

	var hash crypto.Hash
	switch alg := key.KeyAlg(options[0]); alg {
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
func (b *symmetricBackend) Sign(ctx context.Context, message []byte, options ...key.SignOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hash, err := b.signatureOptions(options...)
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
func (b *symmetricBackend) VerifySignature(ctx context.Context, signature []byte, message []byte, options ...key.VerifyOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	signOptions := make([]key.SignOption, len(options))
	for i, option := range options {
		signOptions[i] = key.SignOption(option)
	}
	hash, err := b.signatureOptions(signOptions...)
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

var _ key.Backend = &symmetricBackend{}
