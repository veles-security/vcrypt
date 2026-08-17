package scheme

import (
	"reflect"
	"sync"

	"github.com/veles-security/vcrypt"
	"github.com/veles-security/vcrypt/alg"
	"github.com/veles-security/vcrypt/key"
)

type Scheme interface {
	DiscoverCapabilities(*key.Key) error
	Signer(*key.Key, alg.Alg) vcrypt.Signer
}

var registry = struct {
	sync.RWMutex
	schemes map[reflect.Type]Scheme
}{
	schemes: make(map[reflect.Type]Scheme),
}

// Register associates a key type with a Scheme implementation. The type may be
// either a concrete [key.KeyMaterial] type or the cryptographic key type returned
// by [key.KeyMaterial.Public].
func Register(t reflect.Type, s Scheme) {
	if t == nil || s == nil {
		return
	}

	registry.Lock()
	registry.schemes[t] = s
	registry.Unlock()
}

// Lookup returns the Scheme registered for k's cryptographic material. It first
// checks the material's concrete type, allowing symmetric key material with no
// public representation, and then checks the public key type.
func Lookup(k *key.Key) Scheme {
	if k == nil || k.Material == nil {
		return nil
	}

	registry.RLock()
	s := registry.schemes[reflect.TypeOf(k.Material)]
	registry.RUnlock()
	if s != nil {
		return s
	}

	publicKey := k.Material.Public()
	if publicKey == nil {
		return nil
	}

	registry.RLock()
	s = registry.schemes[reflect.TypeOf(publicKey)]
	registry.RUnlock()
	return s
}
