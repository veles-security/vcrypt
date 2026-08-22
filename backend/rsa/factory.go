package rsa

import (
	stdrsa "crypto/rsa"
	"errors"

	"github.com/veles-security/vcrypt/backend"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type factory struct {
}

// New implements [backend.Factory].
func (f factory) New(m material.Material) (key.Backend, error) {
	switch value := m.(type) {
	case *material.PublicMaterial:
		if _, ok := value.Key.(*stdrsa.PublicKey); ok {
			return &publicBackend{material: *value}, nil
		}
	case *material.PrivateMaterial:
		if _, ok := value.Key.(*stdrsa.PrivateKey); ok {
			return &privateBackend{material: *value}, nil
		}
	case *material.CertificateMaterial:
		if value.Cert != nil {
			if publicKey, ok := value.Cert.PublicKey.(*stdrsa.PublicKey); ok {
				return &certificateBackend{
					publicBackend: &publicBackend{material: material.PublicMaterial{Key: publicKey}},
					material:      *value,
				}, nil
			}
		}
	}

	return nil, errors.New("RSA backend: material is not supported")
}

// Supports implements [backend.Factory].
func (f factory) Supports(m material.Material) bool {
	switch value := m.(type) {
	case *material.PrivateMaterial:
		_, ok := value.Key.(*stdrsa.PrivateKey)
		return ok
	case *material.PublicMaterial:
		_, ok := value.Key.(*stdrsa.PublicKey)
		return ok
	case *material.CertificateMaterial:
		if value.Cert == nil {
			return false
		}
		_, ok := value.Cert.PublicKey.(*stdrsa.PublicKey)
		return ok
	default:
		return false
	}
}

var _ backend.Factory = factory{}

func init() {
	backend.Regsiter(&factory{})
	backend.RegisterJOSEEncoder(NewJOSEEncoder())
	backend.RegisterJOSEDecoder(NewJOSEDecoder())
}
