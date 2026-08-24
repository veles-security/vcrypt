package keystore

import (
	"errors"

	"github.com/veles-security/vcrypt/keysource"
)

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
