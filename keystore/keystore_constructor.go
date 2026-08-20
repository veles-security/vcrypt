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
		m.bindSelfRefreshing(source)
		m.sources[id] = source
	}
	// Self-refreshing sources still receive one initial load. Later updates are
	// delivered through the callback installed above.
	err := m.loadSources(sources)
	if err != nil {
		return nil, err
	}
	return m, nil
}
