package keysource

import (
	"context"

	"github.com/veles-security/vcrypt/key"
)

type Source interface {
	ID() string
	// Load returns the source's current key candidates. Implementations must
	// honor context cancellation.
	Load(context.Context) ([]key.KeyCandidate, error)
	// Close stops background work and releases resources. It must be safe to
	// call more than once.
	Close() error
}

// SelfRefreshingSource keeps its keys up to date after the initial Load. The
// manager provides a callback that replaces this source's keys in its store.
type SelfRefreshingSource interface {
	Source
	SetRefreshCallback(func([]key.KeyCandidate) error)
}
