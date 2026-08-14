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
