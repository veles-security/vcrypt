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
	switch material := m.(type) {
	case *material.PublicMaterial:
		if _, ok := material.Key.(*stdrsa.PublicKey); ok {
			return &publicBackend{material: *material}, nil
		}
	case *material.PrivateMaterial:
		if _, ok := material.Key.(*stdrsa.PrivateKey); ok {
			return &privateBackend{material: *material}, nil
		}
	}

	return nil, errors.New("RSA backend: material is not supported")
}

// Supports implements [backend.Factory].
func (f factory) Supports(m material.Material) bool {
	switch material := m.(type) {
	case *material.PrivateMaterial:
		_, ok := material.Key.(*stdrsa.PrivateKey)
		return ok
	case *material.PublicMaterial:
		_, ok := material.Key.(*stdrsa.PublicKey)
		return ok
	default:
		return false
	}
}

var _ backend.Factory = factory{}

func init() {
	backend.Regsiter(&factory{})
}
