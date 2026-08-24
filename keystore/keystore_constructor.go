package keystore

import (
	"errors"
	"fmt"
	"strings"

	"github.com/veles-security/vcrypt/keysource"
)

// Option configures a Store during construction.
type Option func(*store) error

// WithSource adds a key source to the store. The optional error allows the
// result of a source constructor to be passed directly, for example:
//
//	keystore.New(keystore.WithSource(randomsource.New(...)))
func WithSource(source keysource.Source, sourceErrors ...error) Option {
	return func(store *store) error {
		if len(sourceErrors) > 1 {
			return fmt.Errorf("source returned %d errors, want at most one", len(sourceErrors))
		}
		if len(sourceErrors) == 1 && sourceErrors[0] != nil {
			return fmt.Errorf("failed to initialize source: %w", sourceErrors[0])
		}
		if source == nil {
			return fmt.Errorf("source is nil")
		}
		id := source.ID()
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("source ID is empty")
		}
		if _, ok := store.sources[id]; ok {
			return fmt.Errorf("source %s already bound", id)
		}
		store.sources[id] = source
		return nil
	}
}

func New(options ...Option) (Store, error) {
	m := &store{
		repository: NewRepository(),
		sources:    map[string]keysource.Source{},
		loading:    map[string]struct{}{},
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(m); err != nil {
			return nil, errors.Join(err, m.Close())
		}
	}
	sources := make([]keysource.Source, 0, len(m.sources))
	for _, source := range m.sources {
		sources = append(sources, source)
	}
	// Load every source before activating automatic refresh. If construction
	// fails, no source retains a callback to the store being discarded.
	err := m.loadSources(sources)
	if err != nil {
		return nil, errors.Join(err, m.Close())
	}
	for _, source := range sources {
		m.bindSelfRefreshing(source)
	}
	return m, nil
}
