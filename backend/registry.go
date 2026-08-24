package backend

import (
	"errors"
	"reflect"
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
	if material == nil || isNil(material) {
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

func isNil(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
