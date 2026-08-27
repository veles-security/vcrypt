package material

import (
	"crypto"
	"crypto/x509"
)

type Material interface {
	IsMaterial() bool
	Public() *PublicMaterial
}

type PrivateMaterial struct {
	Key crypto.PrivateKey
}

// IsMaterial implements [Material].
func (p *PrivateMaterial) IsMaterial() bool {
	return true
}

// Public returns the public part of the private key when it implements
// [crypto.Signer].
func (p *PrivateMaterial) Public() *PublicMaterial {
	if p == nil {
		return nil
	}
	signer, ok := p.Key.(crypto.Signer)
	if !ok {
		return nil
	}
	return &PublicMaterial{Key: clonePublicKey(signer.Public())}
}

type PublicMaterial struct {
	Key crypto.PublicKey
}

// IsMaterial implements [Material].
func (p *PublicMaterial) IsMaterial() bool {
	return true
}

// Public returns a copy of the public material wrapper.
func (p *PublicMaterial) Public() *PublicMaterial {
	if p == nil {
		return nil
	}
	return &PublicMaterial{Key: clonePublicKey(p.Key)}
}

type CertificateMaterial struct {
	Cert *x509.Certificate
}

// IsMaterial implements [Material].
func (c *CertificateMaterial) IsMaterial() bool {
	return true
}

// Public returns the public key embedded in the certificate.
func (c *CertificateMaterial) Public() *PublicMaterial {
	if c == nil || c.Cert == nil {
		return nil
	}
	return &PublicMaterial{Key: clonePublicKey(c.Cert.PublicKey)}
}

type SymmetricMaterial struct {
	Key []byte
}

// IsMaterial implements [Material].
func (s *SymmetricMaterial) IsMaterial() bool {
	return true
}

// Public returns nil because symmetric key material has no public part.
func (s *SymmetricMaterial) Public() *PublicMaterial {
	return nil
}

var _ Material = &PrivateMaterial{}
var _ Material = &PublicMaterial{}
var _ Material = &CertificateMaterial{}
var _ Material = &SymmetricMaterial{}
