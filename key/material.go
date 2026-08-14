package key

import (
	"crypto"
	"crypto/x509"
)

type KeyMaterial interface {
	Public() crypto.PublicKey
}

type PrivateKeyMaterial struct {
	Key crypto.PrivateKey
}

type PublicKeyMaterial struct {
	Key crypto.PublicKey
}

type CertificateMaterial struct {
	Cert *x509.Certificate
}

func (m PrivateKeyMaterial) Public() crypto.PublicKey {
	if signer, ok := m.Key.(crypto.Signer); ok {
		return signer.Public()
	}
	return nil
}

func (m PublicKeyMaterial) Public() crypto.PublicKey {
	return m.Key
}

func (m CertificateMaterial) Public() crypto.PublicKey {
	if m.Cert == nil {
		return nil
	}
	return m.Cert.PublicKey
}
