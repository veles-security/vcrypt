package rsa

import (
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

// certificateBackend retains the certificate representation while delegating
// cryptographic operations to the RSA public-key backend.
type certificateBackend struct {
	*publicBackend
	material material.CertificateMaterial
}

var _ key.Backend = &certificateBackend{}
var _ key.Verifier = &certificateBackend{}
var _ key.Encrypter = &certificateBackend{}
