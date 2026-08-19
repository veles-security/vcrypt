package vcrypt

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/veles-security/vcrypt/key"
)

const (
	testAlgA key.KeyAlg = "TEST-A"
	testAlgB key.KeyAlg = "TEST-B"
)

type testBackend struct {
	capabilities    []key.Capability
	signature       []byte
	verified        bool
	calledAlgorithm key.KeyAlg
}

func (b *testBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range b.capabilities {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}
	return false
}

func (b *testBackend) Capabilities() []key.Capability {
	return append([]key.Capability(nil), b.capabilities...)
}

func (b *testBackend) Sign(_ context.Context, algorithm key.KeyAlg, _ []byte) ([]byte, error) {
	b.calledAlgorithm = algorithm
	return append([]byte(nil), b.signature...), nil
}

func (b *testBackend) VerifySignature(_ context.Context, algorithm key.KeyAlg, signature []byte, _ []byte) error {
	b.calledAlgorithm = algorithm
	if !bytes.Equal(signature, b.signature) {
		return errors.New("invalid signature")
	}
	b.verified = true
	return nil
}

func (b *testBackend) Encrypt(_ context.Context, algorithm key.KeyAlg, plaintext []byte) ([]byte, error) {
	b.calledAlgorithm = algorithm
	return append([]byte(nil), plaintext...), nil
}

func (b *testBackend) Decrypt(_ context.Context, algorithm key.KeyAlg, ciphertext []byte) ([]byte, error) {
	b.calledAlgorithm = algorithm
	return append([]byte(nil), ciphertext...), nil
}

func TestServiceSignReturnsSelectedKeyDescriptor(t *testing.T) {
	service, err := New()
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{
		capabilities: []key.Capability{
			{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: testAlgB},
		},
		signature: []byte("signature"),
	}
	keys := []key.Key{
		key.New(key.KeyCandidate{ID: "passive", Status: key.KeyStatusPassive, Priority: 20}, backend),
		key.New(key.KeyCandidate{ID: "active", Status: key.KeyStatusActive, Priority: 10}, backend),
	}
	if err := service.keystore.Replace(context.Background(), keys); err != nil {
		t.Fatal(err)
	}

	result, err := service.Sign(context.Background(), []byte("message"), WithAlgorithms(testAlgA, testAlgB))
	if err != nil {
		t.Fatal(err)
	}
	if result.Key.ID != "active" || result.Key.Algorithm != testAlgB {
		t.Fatalf("unexpected descriptor: %+v", result.Key)
	}
	if !bytes.Equal(result.Signature, backend.signature) {
		t.Fatalf("unexpected signature: %q", result.Signature)
	}
	if backend.calledAlgorithm != testAlgB {
		t.Fatalf("backend called with algorithm %q", backend.calledAlgorithm)
	}
}

func TestServiceVerifySignatureUsesDescriptorAndAllowsPassiveKey(t *testing.T) {
	service, err := New()
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{
		capabilities: []key.Capability{
			{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: testAlgA},
		},
		signature: []byte("signature"),
	}
	candidate := key.KeyCandidate{
		ID:     "key-id",
		Owner:  "issuer",
		Source: "jwks",
		Status: key.KeyStatusPassive,
	}
	if err := service.keystore.Replace(context.Background(), []key.Key{key.New(candidate, backend)}); err != nil {
		t.Fatal(err)
	}

	err = service.VerifySignature(
		context.Background(),
		[]byte("message"),
		[]byte("signature"),
		WithKid("key-id"),
		WithOwner("issuer"),
		WithSource("jwks"),
		WithAlgorithms(testAlgA),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !backend.verified || backend.calledAlgorithm != testAlgA {
		t.Fatal("verification was not delegated with the descriptor algorithm")
	}
}

func TestServiceHonorsKeyRestrictions(t *testing.T) {
	service, err := New()
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{
		capabilities: []key.Capability{
			{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: testAlgA},
		},
	}
	candidate := key.KeyCandidate{
		ID:     "restricted",
		Status: key.KeyStatusActive,
		Restrictions: []key.Capability{
			{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: testAlgB},
		},
	}
	if err := service.keystore.Replace(context.Background(), []key.Key{key.New(candidate, backend)}); err != nil {
		t.Fatal(err)
	}

	_, err = service.Sign(context.Background(), []byte("message"), WithAlgorithms(testAlgA))
	if err == nil {
		t.Fatal("expected restricted key not to be selected")
	}
}
