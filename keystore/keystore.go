package keystore

import (
	"context"
	"sync"

	"github.com/veles-security/vcrypt/key"
)

type KeyStorer interface {
	Find(ctx context.Context, conditions ...KeyQueryPredicate) ([]key.Key, error)
	Replace(ctx context.Context, source string, keys []key.Key) error
}

type KeyStore struct {
	mu   sync.RWMutex
	keys []key.Key
}

// Find implements [KeyStorer].
func (k *KeyStore) Find(ctx context.Context, conditions ...KeyQueryPredicate) ([]key.Key, error) {
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

// Replace implements [KeyStorer].
func (k *KeyStore) Replace(ctx context.Context, source string, keys []key.Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	kept := k.keys[:0]
	for _, candidate := range k.keys {
		if candidate.Source != source {
			kept = append(kept, candidate)
		}
	}
	for _, replacement := range keys {
		replacement.Source = source
		kept = append(kept, replacement)
	}
	k.keys = kept
	return nil
}

var _ KeyStorer = &KeyStore{}
