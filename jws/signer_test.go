package jws

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource"
	"github.com/veles-security/vcrypt/keystore"
)

type signerKeystore struct {
	descriptor  key.KeyDescriptor
	signature   []byte
	optionCount *int
}

func (s signerKeystore) SignPrepared(_ context.Context, prepare keystore.PrepareSignFunc, options ...keystore.SignOption) (keystore.SignResult, error) {
	if s.optionCount != nil {
		*s.optionCount = len(options)
	}
	if _, err := prepare(s.descriptor); err != nil {
		return keystore.SignResult{}, err
	}
	return keystore.SignResult{Signature: append([]byte(nil), s.signature...), Key: s.descriptor}, nil
}

func (signerKeystore) Keys(context.Context, key.Selector) ([]key.Key, error) { return nil, nil }
func (signerKeystore) Verify(context.Context, []byte, []byte, ...keystore.VerifyOption) error {
	return nil
}
func (signerKeystore) Encrypt(context.Context, []byte, ...keystore.EncryptOption) (keystore.EncryptResult, error) {
	return keystore.EncryptResult{}, nil
}
func (signerKeystore) Decrypt(context.Context, []byte, ...keystore.DecryptOption) ([]byte, error) {
	return nil, nil
}
func (signerKeystore) Bind(keysource.Source) error { return nil }
func (signerKeystore) RefreshAll() error           { return nil }
func (signerKeystore) Close() error                { return nil }

func Test_Signer_Sign(t *testing.T) {
	// keys
	descriptor := key.KeyDescriptor{ID: "signing-key", Algorithm: "RS256"}
	// payloads
	claims := []byte(`{"sub":"alice"}`)
	defaultEncoded := []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6InNpZ25pbmcta2V5In0.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl`)
	customHeader := []byte(`{"alg":"RS256","kid":"signing-key","typ":"JWT"}`)
	customEncoded := []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6InNpZ25pbmcta2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl`)
	// keystores
	var optionCount int
	store := signerKeystore{descriptor: descriptor, signature: []byte("signature"), optionCount: &optionCount}
	var keystoreInterface keystore.Keystore = store
	// options
	keystoreOption := keystore.SignOption(keystore.WithAlgorithms("RS256"))
	runtimeOption := func(next SignFunc) SignFunc {
		return func(ctx context.Context, claims []byte, header HeaderFunc, options ...keystore.SignOption) (JWS, error) {
			return next(ctx, claims, header, append([]keystore.SignOption{keystoreOption}, options...)...)
		}
	}
	callOption := func(next SignFunc) SignFunc {
		return func(ctx context.Context, claims []byte, _ HeaderFunc, options ...keystore.SignOption) (JWS, error) {
			buildHeader := func(key.KeyDescriptor) ([]byte, error) { return customHeader, nil }
			return next(ctx, claims, buildHeader, append(options, keystoreOption)...)
		}
	}
	nilSignFuncOption := func(SignFunc) SignFunc { return nil }

	// assertions
	assertSigned := func(wantHeader, wantEncoded []byte, wantOptionCount int) func(*testing.T, JWS, error) {
		return func(t *testing.T, got JWS, err error) {
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			if !bytes.Equal(got.Header, wantHeader) || !bytes.Equal(got.Claims, claims) || !bytes.Equal(got.Signature, store.signature) || !reflect.DeepEqual(got.Key, descriptor) || !bytes.Equal(got.Encoded, wantEncoded) {
				t.Errorf("Sign() = %#v, want header %s, original claims, signature, key, and encoded %s", got, wantHeader, wantEncoded)
			}
			if optionCount != wantOptionCount {
				t.Errorf("keystore option count = %d, want %d", optionCount, wantOptionCount)
			}
		}
	}
	assertMisconfigured := func(t *testing.T, got JWS, err error) {
		if !errors.Is(err, vapi.ErrMisconfigured) {
			t.Errorf("Sign() error = %v, want ErrMisconfigured", err)
		}
		if !reflect.DeepEqual(got, JWS{}) {
			t.Errorf("Sign() = %#v, want zero JWS", got)
		}
	}
	tests := []struct {
		name           string
		runtimeOptions []SignerOption
		options        []SignerOption
		assertion      func(*testing.T, JWS, error)
	}{
		{name: "Default Header", assertion: assertSigned([]byte(`{"alg":"RS256","kid":"signing-key"}`), defaultEncoded, 0)},
		{name: "Decorated Header And Keystore Options", runtimeOptions: []SignerOption{runtimeOption}, options: []SignerOption{callOption}, assertion: assertSigned(customHeader, customEncoded, 2)},
		{name: "Nil Runtime Option", runtimeOptions: []SignerOption{nil}, assertion: assertMisconfigured},
		{name: "Nil Per-Call Option", options: []SignerOption{nil}, assertion: assertMisconfigured},
		{name: "Option Returns Nil SignFunc", options: []SignerOption{nilSignFuncOption}, assertion: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optionCount = 0
			signer, err := New(WithSignerKeystore(&keystoreInterface), WithSignerRuntimeOptions(tt.runtimeOptions...))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			got, gotErr := signer.Sign(context.Background(), claims, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
