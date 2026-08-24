package rsa

import (
	"context"
	"crypto"
	stdrsa "crypto/rsa"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type publicBackend struct {
	material material.PublicMaterial
}

func (b *publicBackend) signatureOptions(alg key.KeyAlg) (crypto.Hash, bool, error) {
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

// Capabilities implements [key.Backend].
func (p *publicBackend) Capabilities() []key.Capability {
	return append([]key.Capability(nil), capabilities[PUBLIC_MATERIAL]...)
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

// VerifySignature implements [key.SignatureVerifier].
func (p *publicBackend) VerifySignature(ctx context.Context, algorithm key.KeyAlg, signature []byte, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, ok := p.material.Key.(*stdrsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSA backend: key material is not an RSA public key")
	}
	hash, isPss, err := p.signatureOptions(algorithm)
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

// Encrypt implements [key.Encrypter].
func (p *publicBackend) Encrypt(ctx context.Context, algorithm key.KeyAlg, plaintext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	publicKey, ok := p.material.Key.(*stdrsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("RSA backend: key material is not an RSA public key")
	}
	return encrypt(publicKey, algorithm, plaintext)
}

var _ key.Backend = &publicBackend{}
var _ key.SignatureVerifier = &publicBackend{}
var _ key.Encrypter = &publicBackend{}
