package keystore

import "github.com/veles-security/vcrypt/key"

// KeySelector identifies keys by their stable metadata. A zero-value selector
// matches every key.
type KeySelector struct {
	ID     string
	Owner  string
	Source string
}

// KeySelectorOption configures a [KeySelector].
type KeySelectorOption func(*KeySelector)

// Select builds a key selector that can be reused by repository queries and
// cryptographic operations.
func Select(options ...KeySelectorOption) KeySelector {
	var selector KeySelector
	for _, option := range options {
		if option != nil {
			option(&selector)
		}
	}
	return selector
}

// WithKeyID restricts selection to the key with id.
func WithKeyID(id string) KeySelectorOption {
	return func(selector *KeySelector) {
		selector.ID = id
	}
}

// WithKeyOwner restricts selection to keys owned by owner.
func WithKeyOwner(owner string) KeySelectorOption {
	return func(selector *KeySelector) {
		selector.Owner = owner
	}
}

// WithKeySource restricts selection to keys from source.
func WithKeySource(source string) KeySelectorOption {
	return func(selector *KeySelector) {
		selector.Source = source
	}
}

func (selector KeySelector) matches(candidate *key.Key) bool {
	return (selector.ID == "" || candidate.ID() == selector.ID) &&
		(selector.Owner == "" || candidate.Owner() == selector.Owner) &&
		(selector.Source == "" || candidate.Source() == selector.Source)
}
