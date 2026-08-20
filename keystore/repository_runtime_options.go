package keystore

import "github.com/veles-security/vcrypt/key"

type KeyQueryPredicate func(*key.Key) bool

func WithID(kid string) KeyQueryPredicate {
	return func(candidate *key.Key) bool {
		return candidate.ID() == kid
	}
}

func WithOwner(owner string) KeyQueryPredicate {
	return func(candidate *key.Key) bool {
		return candidate.Owner() == owner
	}
}

func WithSource(source string) KeyQueryPredicate {
	return func(candidate *key.Key) bool {
		return candidate.Source() == source
	}
}
