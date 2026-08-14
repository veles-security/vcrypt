package keystore

import (
	"context"
	"sync"

	"github.com/veles-security/vcrypt/key"
)

type Repository interface {
	Find(ctx context.Context, conditions ...KeyQueryPredicate) ([]key.Key, error)
	Replace(ctx context.Context, keys []key.Key, conditions ...KeyQueryPredicate) error
}

type repository struct {
	mu   sync.RWMutex
	keys []key.Key
}

// Find implements [Repository].
func (k *repository) Find(ctx context.Context, conditions ...KeyQueryPredicate) ([]key.Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	result := make([]key.Key, 0, len(k.keys))
	for i := range k.keys {
		candidate := &k.keys[i]
		matches := true
		for _, condition := range conditions {
			if condition != nil && !condition(candidate) {
				matches = false
				break
			}
		}
		if matches {
			result = append(result, *candidate)
		}
	}
	return result, nil
}

// Replace implements [Repository].
func (k *repository) Replace(ctx context.Context, keys []key.Key, conditions ...KeyQueryPredicate) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	kept := k.keys[:0]
	for i := range k.keys {
		candidate := &k.keys[i]
		matches := true
		for _, condition := range conditions {
			if condition != nil && !condition(candidate) {
				matches = false
				break
			}
		}
		if !matches {
			kept = append(kept, *candidate)
		}
	}
	kept = append(kept, keys...)
	k.keys = kept
	return nil
}

var _ Repository = &repository{}
