package keystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/veles-security/vcrypt/backend"
	_ "github.com/veles-security/vcrypt/backend/ec"
	_ "github.com/veles-security/vcrypt/backend/rsa"
	_ "github.com/veles-security/vcrypt/backend/symetric"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource"
)

type Keystore interface {
	Repository
	Close() error
	Sign(ctx context.Context, message []byte, options ...SignOption) (SignResult, error)
	VerifySignature(ctx context.Context, message, signature []byte, options ...VerifyOption) error
	Encrypt(ctx context.Context, plaintext []byte, options ...EncryptOption) (EncryptResult, error)
	Decrypt(ctx context.Context, ciphertext []byte, options ...DecryptOption) ([]byte, error)
	Bind(source keysource.Source) error
	RefreshAll() error
}

type store struct {
	repository     Repository
	sources        map[string]keysource.Source
	loading        map[string]struct{}
	sourcesMU      sync.RWMutex
	runtimeOptions []KeystoreRuntimeOption
}

// Close stops all sources owned by the store and releases their resources.
func (m *store) Close() error {
	m.sourcesMU.RLock()
	sources := make([]keysource.Source, 0, len(m.sources))
	for _, source := range m.sources {
		sources = append(sources, source)
	}
	m.sourcesMU.RUnlock()

	var result error
	for _, source := range sources {
		result = errors.Join(result, source.Close())
	}
	return result
}

func (m *store) Find(ctx context.Context, selector KeySelector) ([]key.Key, error) {
	return m.repository.Find(ctx, selector)
}

func (m *store) Replace(ctx context.Context, keys []key.Key, selector KeySelector) error {
	return m.repository.Replace(ctx, keys, selector)
}

// Bind implements [Manager].
func (m *store) Bind(source keysource.Source) error {
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

	candidates, err := source.Load(context.Background())
	var keys []key.Key
	if err != nil {
		err = fmt.Errorf("failed to load keys from source %s: %w", id, err)
	} else {
		keys, err = m.buildCandidates(candidates)
		if err != nil {
			err = fmt.Errorf("failed to build keys from source %s: %w", id, err)
		}
	}
	if err == nil {
		err = m.repository.Replace(context.Background(), keys, WithKeySelector(WithKeySource(id)))
		if err != nil {
			err = fmt.Errorf("failed to store keys from source %s in keystore: %w", id, err)
		}
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
	// Activate refresh only after the initial keys and source registration have
	// both been committed successfully.
	m.bindSelfRefreshing(source)
	return nil
}

// RefreshAll implements [Manager].
func (m *store) RefreshAll() error {
	m.sourcesMU.RLock()
	defer m.sourcesMU.RUnlock()
	sources := make([]keysource.Source, 0, len(m.sources))
	for _, source := range m.sources {
		if _, ok := source.(keysource.SelfRefreshingSource); !ok {
			sources = append(sources, source)
		}
	}
	return m.loadSources(sources)
}

func (m *store) bindSelfRefreshing(source keysource.Source) {
	id := source.ID()
	if selfRefreshing, ok := source.(keysource.SelfRefreshingSource); ok {
		selfRefreshing.SetRefreshCallback(func(candidates []key.KeyCandidate) error {
			keys, err := m.buildCandidates(candidates)
			if err != nil {
				return fmt.Errorf("failed to build keys from source %s: %w", id, err)
			}
			if err := m.repository.Replace(context.Background(), keys, WithKeySelector(WithKeySource(id))); err != nil {
				return fmt.Errorf("failed to store keys from source %s in keystore: %w", id, err)
			}
			return nil
		})
	}
}

func (m *store) loadSources(sources []keysource.Source) error {
	errs := make(chan error, len(sources))
	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidates, err := source.Load(context.Background())
			if err != nil {
				errs <- fmt.Errorf("failed to load keys from source %s: %w", source.ID(), err)
				return
			}
			keys, err := m.buildCandidates(candidates)
			if err != nil {
				errs <- fmt.Errorf("failed to build keys from source %s: %w", source.ID(), err)
				return
			}
			if err := m.repository.Replace(context.Background(), keys, WithKeySelector(WithKeySource(source.ID()))); err != nil {
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

func (m *store) buildCandidates(candidates []key.KeyCandidate) ([]key.Key, error) {
	keys := make([]key.Key, 0, len(candidates))
	for i, candidate := range candidates {
		keyBackend, err := backend.BackendFor(candidate.Material)
		if err != nil {
			return nil, fmt.Errorf("candidate %d: %w", i+1, err)
		}

		keys = append(keys, key.New(candidate, keyBackend))
	}
	return keys, nil
}

var _ Keystore = &store{}
