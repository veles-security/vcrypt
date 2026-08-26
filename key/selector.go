package key

// Selector identifies keys using a set of predicates. A zero-value selector
// matches every key.
type Selector struct {
	options []SelectorOption
}

// SelectorOption reports whether a key matches a selection criterion.
type SelectorOption func(Key) bool

// Select builds a selector that can be reused by key consumers.
func Select(options ...SelectorOption) Selector {
	selector := Selector{options: make([]SelectorOption, 0, len(options))}
	for _, option := range options {
		if option != nil {
			selector.options = append(selector.options, option)
		}
	}
	return selector
}

// WithID restricts selection to the key with id.
func WithID(id string) SelectorOption {
	return func(candidate Key) bool {
		return candidate.ID() == id
	}
}

// WithOwner restricts selection to keys owned by owner.
func WithOwner(owner string) SelectorOption {
	return func(candidate Key) bool {
		return candidate.Owner() == owner
	}
}

// WithSource restricts selection to keys from source.
func WithSource(source string) SelectorOption {
	return func(candidate Key) bool {
		return candidate.Source() == source
	}
}

// WithCapability restricts selection to keys that support capability.
func WithCapability(capability Capability) SelectorOption {
	return func(candidate Key) bool {
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

// Matches reports whether candidate satisfies every selection criterion.
func (selector Selector) Matches(candidate Key) bool {
	for _, option := range selector.options {
		if !option(candidate) {
			return false
		}
	}
	return true
}
