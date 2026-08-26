package keystore

import (
	"testing"

	"github.com/veles-security/vcrypt/key"
)

type capabilityBackend struct {
	capabilities []key.Capability
}

func (b capabilityBackend) Capabilities() []key.Capability {
	return append([]key.Capability(nil), b.capabilities...)
}

func (b capabilityBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range b.capabilities {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}
	return false
}

func Test_WithKeyCapability(t *testing.T) {
	// capabilities
	signing := key.Capability{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: "RS256"}
	verification := key.Capability{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: "RS256"}
	// backends
	signingBackend := capabilityBackend{capabilities: []key.Capability{signing}}
	// keys
	unrestricted := key.New(key.KeyCandidate{}, signingBackend)
	restrictedToSigning := key.New(key.KeyCandidate{Restrictions: []key.Capability{signing}}, signingBackend)
	restrictedToVerification := key.New(key.KeyCandidate{Restrictions: []key.Capability{verification}}, signingBackend)
	withoutBackend := key.New(key.KeyCandidate{}, nil)

	// assertions
	assertMatch := func(t *testing.T, matched bool) {
		if !matched {
			t.Error("WithKeyCapability() = false, want true")
		}
	}
	assertNoMatch := func(t *testing.T, matched bool) {
		if matched {
			t.Error("WithKeyCapability() = true, want false")
		}
	}
	tests := []struct {
		name       string
		capability key.Capability
		candidate  key.Key
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
			matched := WithKeyCapability(tt.capability)(&tt.candidate)
			tt.assertion(t, matched)
		})
	}
}
