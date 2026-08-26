package keystore

import (
	"github.com/veles-security/vcrypt/key"
)

// KeySelector identifies keys using a set of predicates. A zero-value selector
// matches every key.
type KeySelector struct {
	options []KeySelectorOption
}

// KeySelectorOption reports whether a key matches a selection criterion.
type KeySelectorOption func(*key.Key) bool

// WithKeySelector builds a key selector that can be reused by repository queries and
// cryptographic operations.
func WithKeySelector(options ...KeySelectorOption) KeySelector {
	selector := KeySelector{options: make([]KeySelectorOption, 0, len(options))}
	for _, option := range options {
		if option != nil {
			selector.options = append(selector.options, option)
		}
	}
	return selector
}

// WithKeyID restricts selection to the key with id.
func WithKeyID(id string) KeySelectorOption {
	return func(candidate *key.Key) bool {
		return candidate.ID() == id
	}
}

// WithKeyOwner restricts selection to keys owned by owner.
func WithKeyOwner(owner string) KeySelectorOption {
	return func(candidate *key.Key) bool {
		return candidate.Owner() == owner
	}
}

// WithKeySource restricts selection to keys from source.
func WithKeySource(source string) KeySelectorOption {
	return func(candidate *key.Key) bool {
		return candidate.Source() == source
	}
}

// WithKeyCapability restricts selection to keys that support capability.
func WithKeyCapability(capability key.Capability) KeySelectorOption {
	return func(candidate *key.Key) bool {
		backend := candidate.Backend()
		if backend == nil || !backend.Supports(capability.Use, capability.Operation, capability.Algorithm) {
			return false
		}

		restrictions := candidate.Restrictions()
		if len(restrictions) == 0 {
			return true
		}
		for _, restriction := range restrictions {
			if restriction == capability {
				return true
			}
		}
		return false
	}
}

func (selector KeySelector) matches(candidate *key.Key) bool {
	for _, option := range selector.options {
		if !option(candidate) {
			return false
		}
	}
	return true
}
