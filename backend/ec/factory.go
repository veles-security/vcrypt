package ec

import (
	"crypto/ecdsa"
	"errors"

	"github.com/veles-security/vcrypt/backend"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type factory struct{}

// New implements [backend.Factory].
func (f factory) New(m material.Material) (key.Backend, error) {
	switch value := material.Clone(m).(type) {
	case *material.PublicMaterial:
		if value != nil {
			if publicKey, ok := value.Key.(*ecdsa.PublicKey); ok && publicKey != nil {
				return &publicBackend{material: *value}, nil
			}
		}
	case *material.PrivateMaterial:
		if value != nil {
			if privateKey, ok := value.Key.(*ecdsa.PrivateKey); ok && privateKey != nil {
				return &privateBackend{material: *value}, nil
			}
		}
	case *material.CertificateMaterial:
		if value != nil && value.Cert != nil {
			if publicKey, ok := value.Cert.PublicKey.(*ecdsa.PublicKey); ok && publicKey != nil {
				return &certificateBackend{
					publicBackend: &publicBackend{material: material.PublicMaterial{Key: publicKey}},
					material:      *value,
				}, nil
			}
		}
	}

	return nil, errors.New("EC backend: material is not supported")
}

// Supports implements [backend.Factory].
func (f factory) Supports(m material.Material) bool {
	switch value := m.(type) {
	case *material.PrivateMaterial:
		if value == nil {
			return false
		}
		privateKey, ok := value.Key.(*ecdsa.PrivateKey)
		return ok && privateKey != nil
	case *material.PublicMaterial:
		if value == nil {
			return false
		}
		publicKey, ok := value.Key.(*ecdsa.PublicKey)
		return ok && publicKey != nil
	case *material.CertificateMaterial:
		if value == nil || value.Cert == nil {
			return false
		}
		publicKey, ok := value.Cert.PublicKey.(*ecdsa.PublicKey)
		return ok && publicKey != nil
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
