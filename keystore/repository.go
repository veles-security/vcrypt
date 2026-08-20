package keystore

import (
	"context"
	"sync"

	"github.com/veles-security/vcrypt/key"
)

type Repository interface {
	Find(ctx context.Context, selector KeySelector) ([]key.Key, error)
	Replace(ctx context.Context, keys []key.Key, selector KeySelector) error
}

type repository struct {
	mu   sync.RWMutex
	keys []key.Key
}

func NewRepository() Repository {
	return &repository{
		keys: []key.Key(nil),
	}
}

// Find implements [Repository].
func (k *repository) Find(ctx context.Context, selector KeySelector) ([]key.Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	result := make([]key.Key, 0, len(k.keys))
	for i := range k.keys {
		candidate := &k.keys[i]
		if selector.matches(candidate) {
			result = append(result, *candidate)
		}
	}
	return result, nil
}

// Replace implements [Repository].
func (k *repository) Replace(ctx context.Context, keys []key.Key, selector KeySelector) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	kept := k.keys[:0]
	for i := range k.keys {
		candidate := &k.keys[i]
		if !selector.matches(candidate) {
			kept = append(kept, *candidate)
		}
	}
	kept = append(kept, keys...)
	k.keys = kept
	return nil
}

var _ Repository = &repository{}
