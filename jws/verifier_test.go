package jws

import (
	"context"
	"errors"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource"
	"github.com/veles-security/vcrypt/keystore"
)

type verifierKeystore struct {
	message     []byte
	signature   []byte
	optionCount int
	err         error
}

func (s *verifierKeystore) Verify(_ context.Context, message []byte, signature []byte, options ...keystore.VerifyOption) error {
	s.message = append([]byte(nil), message...)
	s.signature = append([]byte(nil), signature...)
	s.optionCount = len(options)
	return s.err
}

func (*verifierKeystore) Keys(context.Context, key.Selector) ([]key.Key, error) { return nil, nil }
func (*verifierKeystore) Signer(context.Context, ...keystore.SignOption) (key.KeyDescriptor, keystore.SignFunc, error) {
	return key.KeyDescriptor{}, nil, nil
}
func (*verifierKeystore) Encrypt(context.Context, []byte, ...keystore.EncryptOption) (keystore.EncryptResult, error) {
	return keystore.EncryptResult{}, nil
}
func (*verifierKeystore) Decrypt(context.Context, []byte, ...keystore.DecryptOption) ([]byte, error) {
	return nil, nil
}
func (*verifierKeystore) Bind(keysource.Source) error { return nil }
func (*verifierKeystore) RefreshAll() error           { return nil }
func (*verifierKeystore) Close() error                { return nil }

func Test_NewVerifier(t *testing.T) {
	// keystores
	store := &verifierKeystore{}
	var storeInterface keystore.Keystore = store
	var nilStore keystore.Keystore
	// errors
	configError := errors.New("config error")

	// assertions
	assertConfigured := func(t *testing.T, got vapi.Verifier[VerifierOption], err error) {
		if err != nil {
			t.Fatalf("NewVerifier() error = %v", err)
		}
		if got == nil {
			t.Error("NewVerifier() = nil, want verifier")
		}
	}
	assertMisconfigured := func(t *testing.T, got vapi.Verifier[VerifierOption], err error) {
		if !errors.Is(err, vapi.ErrMisconfigured) {
			t.Errorf("NewVerifier() error = %v, want ErrMisconfigured", err)
		}
		if got != nil {
			t.Errorf("NewVerifier() = %#v, want nil", got)
		}
	}
	tests := []struct {
		name      string
		options   []VerifierConfigOption
		assertion func(*testing.T, vapi.Verifier[VerifierOption], error)
	}{
		{name: "Configured", options: []VerifierConfigOption{WithVerifierKeystore(&storeInterface)}, assertion: assertConfigured},
		{name: "No Keystore", assertion: assertMisconfigured},
		{name: "Nil Keystore Pointer", options: []VerifierConfigOption{WithVerifierKeystore(nil)}, assertion: assertMisconfigured},
		{name: "Nil Keystore Interface", options: []VerifierConfigOption{WithVerifierKeystore(&nilStore)}, assertion: assertMisconfigured},
		{name: "Nil Config Option", options: []VerifierConfigOption{nil}, assertion: assertMisconfigured},
		{name: "Config Option Error", options: []VerifierConfigOption{func(*Verifier) error { return configError }}, assertion: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewVerifier(tt.options...)
			tt.assertion(t, got, err)
		})
	}
}

func Test_Verifier_Verify(t *testing.T) {
	// payloads
	message := []byte("message")
	signature := []byte("signature")
	// errors
	verifyError := errors.New("invalid signature")
	// options
	keystoreOption := keystore.VerifyOption(keystore.WithAlgorithms("RS256"))
	runtimeOption := func(next VerifyFunc) VerifyFunc {
		return func(ctx context.Context, message []byte, signature []byte, options ...keystore.VerifyOption) error {
			return next(ctx, message, signature, append([]keystore.VerifyOption{keystoreOption}, options...)...)
		}
	}
	callOption := func(next VerifyFunc) VerifyFunc {
		return func(ctx context.Context, message []byte, signature []byte, options ...keystore.VerifyOption) error {
			return next(ctx, message, signature, append(options, keystoreOption)...)
		}
	}
	nilVerifyFuncOption := func(VerifyFunc) VerifyFunc { return nil }
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertVerified := func(wantOptionCount int) func(*testing.T, *verifierKeystore, error) {
		return func(t *testing.T, store *verifierKeystore, err error) {
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if string(store.message) != string(message) || string(store.signature) != string(signature) {
				t.Errorf("Verify() passed message %q and signature %q, want %q and %q", store.message, store.signature, message, signature)
			}
			if store.optionCount != wantOptionCount {
				t.Errorf("keystore option count = %d, want %d", store.optionCount, wantOptionCount)
			}
		}
	}
	assertMisconfigured := func(t *testing.T, _ *verifierKeystore, err error) {
		if !errors.Is(err, vapi.ErrMisconfigured) {
			t.Errorf("Verify() error = %v, want ErrMisconfigured", err)
		}
	}
	assertCanceled := func(t *testing.T, _ *verifierKeystore, err error) {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Verify() error = %v, want context.Canceled", err)
		}
	}
	assertVerifyError := func(t *testing.T, _ *verifierKeystore, err error) {
		if !errors.Is(err, verifyError) {
			t.Errorf("Verify() error = %v, want %v", err, verifyError)
		}
	}
	tests := []struct {
		name           string
		ctx            context.Context
		runtimeOptions []VerifierOption
		options        []VerifierOption
		storeError     error
		nilReceiver    bool
		assertion      func(*testing.T, *verifierKeystore, error)
	}{
		{name: "Default", ctx: context.Background(), assertion: assertVerified(0)},
		{name: "Signature Algorithm", ctx: context.Background(), options: []VerifierOption{WithVerifierAlg("RS256")}, assertion: assertVerified(1)},
		{name: "Runtime And Per-Call Options", ctx: context.Background(), runtimeOptions: []VerifierOption{runtimeOption}, options: []VerifierOption{callOption}, assertion: assertVerified(2)},
		{name: "Keystore Error", ctx: context.Background(), storeError: verifyError, assertion: assertVerifyError},
		{name: "Nil Context", assertion: assertMisconfigured},
		{name: "Canceled Context", ctx: canceledContext, assertion: assertCanceled},
		{name: "Nil Runtime Option", ctx: context.Background(), runtimeOptions: []VerifierOption{nil}, assertion: assertMisconfigured},
		{name: "Nil Per-Call Option", ctx: context.Background(), options: []VerifierOption{nil}, assertion: assertMisconfigured},
		{name: "Option Returns Nil VerifyFunc", ctx: context.Background(), options: []VerifierOption{nilVerifyFuncOption}, assertion: assertMisconfigured},
		{name: "Nil Receiver", ctx: context.Background(), nilReceiver: true, assertion: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &verifierKeystore{err: tt.storeError}
			var storeInterface keystore.Keystore = store
			verifier := &Verifier{keystore: storeInterface, runtimeOptions: tt.runtimeOptions}
			if tt.nilReceiver {
				verifier = nil
			}
			err := verifier.Verify(tt.ctx, message, signature, tt.options...)
			tt.assertion(t, store, err)
		})
	}
}
