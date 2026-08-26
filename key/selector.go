package key

import "time"

// Selector identifies keys using a set of predicates. A zero-value selector
// matches every key.
type Selector struct {
	options []SelectorOption
}

// SelectorOption reports whether a key matches a selection criterion.
type SelectorOption func(Key) bool

// Select builds a selector that can be reused by key consumers.
func Select(options ...SelectorOption) Selector {
	return Selector{}.And(options...)
}

// And returns a selector containing the receiver's criteria followed by the
// additional criteria. It does not modify the receiver.
func (selector Selector) And(options ...SelectorOption) Selector {
	combined := Selector{options: make([]SelectorOption, 0, len(selector.options)+len(options))}
	combined.options = append(combined.options, selector.options...)
	for _, option := range options {
		if option != nil {
			combined.options = append(combined.options, option)
		}
	}
	return combined
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

// WithStatus restricts selection to keys with one of the supplied statuses.
// It matches no keys when statuses is empty.
func WithStatus(statuses ...KeyStatus) SelectorOption {
	allowed := append([]KeyStatus(nil), statuses...)
	return func(candidate Key) bool {
		for _, status := range allowed {
			if candidate.Status() == status {
				return true
			}
		}
		return false
	}
}

// WithValidityAt restricts selection to keys valid at the supplied instant.
// A zero key validity bound is treated as unspecified.
func WithValidityAt(at time.Time) SelectorOption {
	return func(candidate Key) bool {
		return (candidate.NotBefore().IsZero() || !at.Before(candidate.NotBefore())) &&
			(candidate.NotAfter().IsZero() || !at.After(candidate.NotAfter()))
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
