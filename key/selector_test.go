package key

import "testing"

type selectorBackend struct {
	capabilities []Capability
}

func (b selectorBackend) Capabilities() []Capability {
	return append([]Capability(nil), b.capabilities...)
}

func (b selectorBackend) Supports(use KeyUse, operation KeyOperation, algorithm KeyAlg) bool {
	for _, capability := range b.capabilities {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}
	return false
}

func Test_Select(t *testing.T) {
	// keys
	candidate := New(KeyCandidate{ID: "selected"}, nil)

	// assertions
	assertMatch := func(t *testing.T, selector Selector) {
		if !selector.Matches(candidate) {
			t.Error("Select().Matches() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, selector Selector) {
		if selector.Matches(candidate) {
			t.Error("Select().Matches() = true, want false")
		}
	}
	tests := []struct {
		name      string
		options   []SelectorOption
		assertion func(*testing.T, Selector)
	}{
		{name: "No Options", assertion: assertMatch},
		{name: "Nil Option", options: []SelectorOption{nil}, assertion: assertMatch},
		{name: "Matching Options", options: []SelectorOption{WithID("selected"), WithOwner("")}, assertion: assertMatch},
		{name: "Mismatched Option", options: []SelectorOption{WithID("other")}, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := Select(tt.options...)
			tt.assertion(t, selector)
		})
	}
}

func Test_WithID(t *testing.T) {
	// keys
	selected := New(KeyCandidate{ID: "selected"}, nil)
	other := New(KeyCandidate{ID: "other"}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithID() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithID() = true, want false")
		}
	}
	tests := []struct {
		name      string
		id        string
		candidate Key
		assertion func(*testing.T, bool)
	}{
		{name: "Matching ID", id: "selected", candidate: selected, assertion: assertMatch},
		{name: "Mismatched ID", id: "selected", candidate: other, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := WithID(tt.id)(tt.candidate)
			tt.assertion(t, matched)
		})
	}
}

func Test_WithOwner(t *testing.T) {
	// keys
	selected := New(KeyCandidate{Owner: "selected"}, nil)
	other := New(KeyCandidate{Owner: "other"}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithOwner() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithOwner() = true, want false")
		}
	}
	tests := []struct {
		name      string
		owner     string
		candidate Key
		assertion func(*testing.T, bool)
	}{
		{name: "Matching Owner", owner: "selected", candidate: selected, assertion: assertMatch},
		{name: "Mismatched Owner", owner: "selected", candidate: other, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := WithOwner(tt.owner)(tt.candidate)
			tt.assertion(t, matched)
		})
	}
}

func Test_WithSource(t *testing.T) {
	// keys
	selected := New(KeyCandidate{Source: "selected"}, nil)
	other := New(KeyCandidate{Source: "other"}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithSource() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithSource() = true, want false")
		}
	}
	tests := []struct {
		name      string
		source    string
		candidate Key
		assertion func(*testing.T, bool)
	}{
		{name: "Matching Source", source: "selected", candidate: selected, assertion: assertMatch},
		{name: "Mismatched Source", source: "selected", candidate: other, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := WithSource(tt.source)(tt.candidate)
			tt.assertion(t, matched)
		})
	}
}

func Test_WithCapability(t *testing.T) {
	// capabilities
	signing := Capability{Use: KeyUseSigning, Operation: KeyOpSign, Algorithm: "RS256"}
	verification := Capability{Use: KeyUseSigning, Operation: KeyOpVerify, Algorithm: "RS256"}
	// backends
	signingBackend := selectorBackend{capabilities: []Capability{signing}}
	// keys
	unrestricted := New(KeyCandidate{}, signingBackend)
	restrictedToSigning := New(KeyCandidate{Restrictions: []Capability{signing}}, signingBackend)
	restrictedToVerification := New(KeyCandidate{Restrictions: []Capability{verification}}, signingBackend)
	withoutBackend := New(KeyCandidate{}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithCapability() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithCapability() = true, want false")
		}
	}
	tests := []struct {
		name       string
		capability Capability
		candidate  Key
		assertion  func(*testing.T, bool)
	}{
		{name: "Unrestricted Key", capability: signing, candidate: unrestricted, assertion: assertMatch},
		{name: "Matching Restriction", capability: signing, candidate: restrictedToSigning, assertion: assertMatch},
		{name: "Unsupported Capability", capability: verification, candidate: unrestricted, assertion: assertNoMatch},
		{name: "Mismatched Restriction", capability: signing, candidate: restrictedToVerification, assertion: assertNoMatch},
		{name: "Missing Backend", capability: signing, candidate: withoutBackend, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := WithCapability(tt.capability)(tt.candidate)
			tt.assertion(t, matched)
		})
	}
}

func Test_Selector_Matches(t *testing.T) {
	// keys
	selected := New(KeyCandidate{ID: "selected", Owner: "owner"}, nil)
	other := New(KeyCandidate{ID: "other", Owner: "owner"}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("Matches() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("Matches() = true, want false")
		}
	}
	tests := []struct {
		name      string
		selector  Selector
		candidate Key
		assertion func(*testing.T, bool)
	}{
		{name: "Zero Value", candidate: selected, assertion: assertMatch},
		{name: "All Predicates Match", selector: Select(WithID("selected"), WithOwner("owner")), candidate: selected, assertion: assertMatch},
		{name: "One Predicate Mismatches", selector: Select(WithID("selected"), WithOwner("owner")), candidate: other, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := tt.selector.Matches(tt.candidate)
			tt.assertion(t, matched)
		})
	}
}
