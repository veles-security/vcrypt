package keysource

import "github.com/veles-security/vcrypt/key"

type Source interface {
	ID() string
	Load() ([]key.KeyCandidate, error)
}

// SelfRefreshingSource keeps its keys up to date after the initial Load. The
// manager provides a callback that replaces this source's keys in its store.
type SelfRefreshingSource interface {
	Source
	SetRefreshCallback(func([]key.KeyCandidate) error)
}
