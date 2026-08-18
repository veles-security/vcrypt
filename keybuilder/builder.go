package keybuilder

import (
	"github.com/veles-security/vcrypt/backend"
	_ "github.com/veles-security/vcrypt/backend/ec"
	_ "github.com/veles-security/vcrypt/backend/hmac"
	_ "github.com/veles-security/vcrypt/backend/rsa"
	"github.com/veles-security/vcrypt/key"
)

func Build(candidate key.KeyCandidate) (*key.Key, error) {
	keyBackend, err := backend.BackendFor(candidate.Material)
	if err != nil {
		return nil, err
	}

	builtKey := key.New(candidate, keyBackend)
	return &builtKey, nil
}
