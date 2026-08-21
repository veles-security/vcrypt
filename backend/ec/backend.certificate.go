package ec

import (
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

// certificateBackend retains the certificate representation while delegating
// signature verification to the EC public-key backend.
type certificateBackend struct {
	*publicBackend
	material material.CertificateMaterial
}

var _ key.Backend = &certificateBackend{}
var _ key.SignatureVerifier = &certificateBackend{}
