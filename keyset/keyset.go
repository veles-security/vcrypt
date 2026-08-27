package keyset

import (
	"context"
	"sync"

	"github.com/veles-security/vcrypt/key"
)

type KeySet interface {
	Find(ctx context.Context, selector key.Selector) ([]key.Key, error)
	Replace(ctx context.Context, keys []key.Key, selector key.Selector) error
}

type keySet struct {
	mu   sync.RWMutex
	keys []key.Key
}

func New() KeySet {
	return &keySet{
		keys: []key.Key(nil),
	}
}

// Find implements [KeySet].
func (r *keySet) Find(ctx context.Context, selector key.Selector) ([]key.Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]key.Key, 0, len(r.keys))
	for i := range r.keys {
		candidate := r.keys[i]
		if selector.Matches(candidate) {
			result = append(result, candidate)
		}
	}
	return result, nil
}

// Replace implements [KeySet].
func (r *keySet) Replace(ctx context.Context, keys []key.Key, selector key.Selector) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	kept := r.keys[:0]
	for i := range r.keys {
		candidate := r.keys[i]
		if !selector.Matches(candidate) {
			kept = append(kept, candidate)
		}
	}
	kept = append(kept, keys...)
	r.keys = kept
	return nil
}

var _ KeySet = &keySet{}
