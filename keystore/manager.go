package keystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource"
)

type Manager interface {
	Bind(source keysource.Source) error
	RefreshAll() error
}

type manager struct {
	store     Store
	sources   map[string]keysource.Source
	loading   map[string]struct{}
	sourcesMU sync.RWMutex
}

func (m *manager) isSelfRefreshingResource(source keysource.Source) bool {
	if _, ok := source.(keysource.SelfRefreshingSource); ok {
		return true
	}
	return false
}

func (m *manager) bindSelfRefreshing(source keysource.Source) {
	id := source.ID()
	if selfRefreshing, ok := source.(keysource.SelfRefreshingSource); ok {
		selfRefreshing.SetRefreshCallback(func(keys []key.Key) error {
			if err := m.store.Replace(context.Background(), keys, WithSource(id)); err != nil {
				return fmt.Errorf("failed to store keys from source %s in keystore: %w", id, err)
			}
			return nil
		})
	}
}

// Bind implements [Manager].
func (m *manager) Bind(source keysource.Source) error {
	if source == nil {
		return fmt.Errorf("source is nil")
	}
	id := source.ID()
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("source ID is empty")
	}

	m.sourcesMU.Lock()
	_, bound := m.sources[id]
	_, loading := m.loading[id]
	if bound || loading {
		m.sourcesMU.Unlock()
		return fmt.Errorf("source %s already bound", id)
	}
	// Reserve the ID before doing I/O, but do not expose the source to refreshes
	// until its initial load has completed.
	m.loading[id] = struct{}{}
	m.sourcesMU.Unlock()

	m.bindSelfRefreshing(source)

	keys, err := source.Load()
	if err == nil {
		err = m.store.Replace(context.Background(), keys, WithSource(id))
		if err != nil {
			err = fmt.Errorf("failed to store keys from source %s in keystore: %w", id, err)
		}
	} else {
		err = fmt.Errorf("failed to load keys from source %s: %w", id, err)
	}
	m.sourcesMU.Lock()
	delete(m.loading, id)
	if err == nil {
		m.sources[id] = source
	}
	m.sourcesMU.Unlock()
	if err != nil {
		return err
	}
	return nil
}

// RefreshAll implements [Manager].
func (m *manager) RefreshAll() error {
	m.sourcesMU.RLock()
	sources := make([]keysource.Source, 0, len(m.sources))
	for _, source := range m.sources {
		if _, ok := source.(keysource.SelfRefreshingSource); !ok {
			sources = append(sources, source)
		}
	}
	m.sourcesMU.RUnlock()
	return m.loadSources(sources)
}

func (m *manager) loadSources(sources []keysource.Source) error {
	errs := make(chan error, len(sources))
	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys, err := source.Load()
			if err != nil {
				errs <- fmt.Errorf("failed to load keys from source %s: %w", source.ID(), err)
				return
			}
			if err := m.store.Replace(context.Background(), keys, WithSource(source.ID())); err != nil {
				errs <- fmt.Errorf("failed to store keys from source %s in keystore: %w", source.ID(), err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	var result error
	for err := range errs {
		result = errors.Join(result, err)
	}
	return result
}

func NewManager(store Store, sources ...keysource.Source) (Manager, error) {
	m := &manager{
		store:   store,
		sources: map[string]keysource.Source{},
		loading: map[string]struct{}{},
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

var _ Manager = &manager{}
