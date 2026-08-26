package key

import (
	"testing"
	"time"
)

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

func Test_Selector_And(t *testing.T) {
	// keys
	selected := New(KeyCandidate{ID: "selected", Owner: "owner"}, nil)
	differentOwner := New(KeyCandidate{ID: "selected", Owner: "other"}, nil)
	// selectors
	base := Select(WithID("selected"))

	// assertions
	assertMatch := func(t *testing.T, selector Selector) {
		if !selector.Matches(selected) {
			t.Error("And().Matches() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, selector Selector) {
		if selector.Matches(differentOwner) {
			t.Error("And().Matches() = true, want false")
		}
	}
	assertReceiverUnchanged := func(t *testing.T, _ Selector) {
		if !base.Matches(selected) {
			t.Error("And() modified the receiver")
		}
	}
	tests := []struct {
		name      string
		selector  Selector
		options   []SelectorOption
		assertion func(*testing.T, Selector)
	}{
		{name: "Add Matching Condition", selector: base, options: []SelectorOption{WithOwner("owner")}, assertion: assertMatch},
		{name: "Add Mismatched Condition", selector: base, options: []SelectorOption{WithOwner("owner")}, assertion: assertNoMatch},
		{name: "Ignore Nil Condition", selector: base, options: []SelectorOption{nil}, assertion: assertMatch},
		{name: "Zero Value Receiver", options: []SelectorOption{WithID("selected")}, assertion: assertMatch},
		{name: "Does Not Modify Receiver", selector: base, options: []SelectorOption{WithOwner("other")}, assertion: assertReceiverUnchanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			combined := tt.selector.And(tt.options...)
			tt.assertion(t, combined)
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

func Test_WithStatus(t *testing.T) {
	// keys
	active := New(KeyCandidate{Status: KeyStatusActive}, nil)
	passive := New(KeyCandidate{Status: KeyStatusPassive}, nil)
	disabled := New(KeyCandidate{Status: KeyStatusDisabled}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithStatus() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithStatus() = true, want false")
		}
	}
	tests := []struct {
		name      string
		statuses  []KeyStatus
		candidate Key
		assertion func(*testing.T, bool)
	}{
		{name: "Single Matching Status", statuses: []KeyStatus{KeyStatusActive}, candidate: active, assertion: assertMatch},
		{name: "One Of Multiple Statuses", statuses: []KeyStatus{KeyStatusActive, KeyStatusPassive}, candidate: passive, assertion: assertMatch},
		{name: "Mismatched Status", statuses: []KeyStatus{KeyStatusActive, KeyStatusPassive}, candidate: disabled, assertion: assertNoMatch},
		{name: "No Statuses", candidate: active, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := WithStatus(tt.statuses...)(tt.candidate)
			tt.assertion(t, matched)
		})
	}
}

func Test_WithoutStatus(t *testing.T) {
	// keys
	unset := New(KeyCandidate{}, nil)
	active := New(KeyCandidate{Status: KeyStatusActive}, nil)
	disabled := New(KeyCandidate{Status: KeyStatusDisabled}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithoutStatus() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithoutStatus() = true, want false")
		}
	}
	tests := []struct {
		name      string
		status    KeyStatus
		candidate Key
		assertion func(*testing.T, bool)
	}{
		{name: "Unset Status", status: KeyStatusDisabled, candidate: unset, assertion: assertMatch},
		{name: "Different Status", status: KeyStatusDisabled, candidate: active, assertion: assertMatch},
		{name: "Matching Status", status: KeyStatusDisabled, candidate: disabled, assertion: assertNoMatch},
		{name: "Exclude Unset Status", candidate: unset, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := WithoutStatus(tt.status)(tt.candidate)
			tt.assertion(t, matched)
		})
	}
}

func Test_WithValidityAt(t *testing.T) {
	// times
	now := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	// keys
	unbounded := New(KeyCandidate{}, nil)
	valid := New(KeyCandidate{NotBefore: past, NotAfter: future}, nil)
	notYetValid := New(KeyCandidate{NotBefore: future}, nil)
	expired := New(KeyCandidate{NotAfter: past}, nil)
	validFromBoundary := New(KeyCandidate{NotBefore: now}, nil)
	validThroughBoundary := New(KeyCandidate{NotAfter: now}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithValidityAt() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithValidityAt() = true, want false")
		}
	}
	tests := []struct {
		name      string
		at        time.Time
		candidate Key
		assertion func(*testing.T, bool)
	}{
		{name: "Unbounded", at: now, candidate: unbounded, assertion: assertMatch},
		{name: "Inside Range", at: now, candidate: valid, assertion: assertMatch},
		{name: "Not Before Boundary", at: now, candidate: validFromBoundary, assertion: assertMatch},
		{name: "Not After Boundary", at: now, candidate: validThroughBoundary, assertion: assertMatch},
		{name: "Before Range", at: now, candidate: notYetValid, assertion: assertNoMatch},
		{name: "After Range", at: now, candidate: expired, assertion: assertNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := WithValidityAt(tt.at)(tt.candidate)
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
