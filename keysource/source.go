package keysource

import "github.com/veles-security/vcrypt/key"

type Source interface {
	ID() string
	Load() ([]key.Key, error)
}
