package backend

import (
	"errors"
	"sync"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

var regsitry = struct {
	sync.RWMutex
	factories []Factory
}{
	factories: []Factory{},
}

func Regsiter(factory Factory) {
	if factory == nil {
		return
	}
	regsitry.Lock()
	regsitry.factories = append(regsitry.factories, factory)
	regsitry.Unlock()
}

func BackendFor(material material.Material) (key.Backend, error) {
	if material == nil {
		return nil, errors.New("nil material")
	}
	regsitry.RLock()
	defer regsitry.RUnlock()

	for i := len(regsitry.factories) - 1; i >= 0; i-- {
		backendFactory := regsitry.factories[i]
		if backendFactory.Supports(material) {
			return backendFactory.New(material)
		}
	}

	return nil, errors.New("material is not supported")
}
