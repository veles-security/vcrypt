package material

import (
	"crypto"
	"crypto/x509"
)

type Material interface {
	IsMaterial() bool
}

type PrivateMaterial struct {
	Key crypto.PrivateKey
}

// IsMaterial implements [Material].
func (p *PrivateMaterial) IsMaterial() bool {
	return true
}

type PublicMaterial struct {
	Key crypto.PublicKey
}

// IsMaterial implements [Material].
func (p *PublicMaterial) IsMaterial() bool {
	return true
}

type CertificateMaterial struct {
	Cert *x509.Certificate
}

// IsMaterial implements [Material].
func (c *CertificateMaterial) IsMaterial() bool {
	return true
}

type SymmetricMaterial struct {
	Key []byte
}

// IsMaterial implements [Material].
func (s *SymmetricMaterial) IsMaterial() bool {
	return true
}

var _ Material = &PrivateMaterial{}
var _ Material = &PublicMaterial{}
var _ Material = &CertificateMaterial{}
var _ Material = &SymmetricMaterial{}
