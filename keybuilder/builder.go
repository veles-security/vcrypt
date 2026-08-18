package keybuilder

import (
	"github.com/veles-security/vcrypt/backend"
	_ "github.com/veles-security/vcrypt/backend/ec"
	_ "github.com/veles-security/vcrypt/backend/hmac"
	_ "github.com/veles-security/vcrypt/backend/rsa"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Build(candidate key.KeyCandidate) (*key.Key, error) {
	keyBackend, err := backend.BackendFor(candidate.Material)
	// Certificates retain their representation and metadata on Key, while the
	// cryptographic backend operates on the public key embedded in the cert.
	if certificate, ok := candidate.Material.(*material.CertificateMaterial); ok &&
		certificate != nil && certificate.Cert != nil {
		keyBackend, err = backend.BackendFor(&material.PublicMaterial{Key: certificate.Cert.PublicKey})
	}
	if err != nil {
		return nil, err
	}

	builtKey := key.New(candidate, keyBackend)
	return &builtKey, nil
}
