package keystore

import (
	"fmt"
	"strings"

	"github.com/veles-security/vcrypt/keysource"
)

func New(sources ...keysource.Source) (Store, error) {
	m := &store{
		repository: NewRepository(),
		sources:    map[string]keysource.Source{},
		loading:    map[string]struct{}{},
	}
	for _, source := range sources {
		if source == nil {
			return nil, fmt.Errorf("source is nil")
		}
		id := source.ID()
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("source ID is empty")
		}
		if _, ok := m.sources[id]; ok {
			return nil, fmt.Errorf("source %s already bound", id)
		}
		m.sources[id] = source
	}
	// Load every source before activating automatic refresh. If construction
	// fails, no source retains a callback to the store being discarded.
	err := m.loadSources(sources)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		m.bindSelfRefreshing(source)
	}
	return m, nil
}
