package keystore

import (
	"context"
	"fmt"
	"sync"

	"github.com/veles-security/vcrypt/keysource"
)

type Manager interface {
	Bind(source keysource.Source) error
	RefreshAll() error
}

type manager struct {
	store     Store
	sources   map[string]keysource.Source
	sourcesMU sync.RWMutex
}

// Bind implements [Manager].
func (m *manager) Bind(source keysource.Source) error {
	m.sourcesMU.Lock()
	defer m.sourcesMU.Unlock()
	if _, ok := m.sources[source.ID()]; ok {
		return fmt.Errorf("source %s already binded", source.ID())
	}
	m.sources[source.ID()] = source
	return nil
}

func (m *manager) RefreshAll() error {
	m.sourcesMU.RLock()
	defer m.sourcesMU.RUnlock()
	return m.refreshAll()
}

func (m *manager) refreshAll() error {
	for _, source := range m.sources {
		keys, err := source.Load()
		if err != nil {
			return fmt.Errorf("failed to load keys from source %s: %w", source.ID(), err)
		}
		err = m.store.Replace(context.Background(), keys, WithSource(source.ID()))
		if err != nil {
			return fmt.Errorf("failed to store keys from source %s in keystore: %w", source.ID(), err)
		}
	}
	return nil
}

func NewManager(store Store, sources ...keysource.Source) (Manager, error) {
	m := &manager{
		store:   store,
		sources: map[string]keysource.Source{},
	}
	for _, source := range sources {
		if _, ok := m.sources[source.ID()]; ok {
			return nil, fmt.Errorf("source #%s already binded", source.ID())
		}
		m.sources[source.ID()] = source
	}
	err := m.refreshAll()
	if err != nil {
		return nil, err
	}
	return m, nil
}

var _ Manager = &manager{}
