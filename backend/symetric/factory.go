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
	if value, ok := material.Clone(m).(*material.SymmetricMaterial); ok && value != nil {
		return &symmetricBackend{material: *value}, nil
	}
	return nil, errors.New("symetric backend: material is not supported")
}

// Supports implements [backend.Factory].
func (f factory) Supports(m material.Material) bool {
	value, ok := m.(*material.SymmetricMaterial)
	return ok && value != nil
}

var _ backend.Factory = factory{}

func init() {
	backend.Regsiter(&factory{})
	backend.RegisterJOSEEncoder(NewJOSEEncoder())
	backend.RegisterJOSEDecoder(NewJOSEDecoder())
}
