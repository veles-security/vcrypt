package symetric

import (
	"errors"

	"github.com/veles-security/vcrypt/backend"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type factory struct{}

// New implements [backend.Factory].
func (f factory) New(m material.Material) (key.Backend, error) {
	if material, ok := m.(*material.SymmetricMaterial); ok {
		return &symmetricBackend{material: *material}, nil
	}
	return nil, errors.New("symetric backend: material is not supported")
}

// Supports implements [backend.Factory].
func (f factory) Supports(m material.Material) bool {
	_, ok := m.(*material.SymmetricMaterial)
	return ok
}

var _ backend.Factory = factory{}

func init() {
	backend.Regsiter(&factory{})
	backend.RegisterJOSEEncoder(NewJOSEEncoder())
	backend.RegisterJOSEDecoder(NewJOSEDecoder())
}
