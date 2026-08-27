package jwks_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/veles-security/vapi"
	_ "github.com/veles-security/vcrypt/backend/symetric"
	"github.com/veles-security/vcrypt/jwks"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func TestDecoder_Decode(t *testing.T) {
	// JSON Web Key Sets
	validJWKS := []byte(`{"keys":[
		{"kty":"oct","kid":"signing-key","use":"sig","key_ops":["sign","verify"],"alg":"HS256","k":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"},
		{"kty":"oct","kid":"encryption-key","use":"enc","key_ops":["encrypt"],"alg":"A256GCM","k":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"}
	]}`)
	emptyJWKS := []byte(`{"keys":[]}`)
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	// decoders
	newDecoder := func(options ...jwks.DecoderConfigOption) vapi.Decoder[jwks.JWKS[key.KeyCandidate], jwks.DecoderOption] {
		decoder, err := jwks.NewDecoder(options...)
		if err != nil {
			t.Fatalf("NewDecoder() error = %v", err)
		}
		return decoder
	}
	defaultDecoder := newDecoder()
	optionOrder := []string{}
	option := func(name string) jwks.DecoderOption {
		return func(next jwks.DecodeFunc) jwks.DecodeFunc {
			return func(ctx context.Context, payload []byte, options ...key.JOSEDecodeOption) (jwks.JWKS[key.KeyCandidate], error) {
				optionOrder = append(optionOrder, name+" before")
				decoded, err := next(ctx, payload, options...)
				optionOrder = append(optionOrder, name+" after")
				return decoded, err
			}
		}
	}
	optionDecoder := newDecoder(jwks.WithDecoderRuntimeOptions(option("runtime")))

	// assertions
	assertDecoded := func(t *testing.T, decoded jwks.JWKS[key.KeyCandidate], err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if len(decoded.Keys) != 2 {
			t.Fatalf("Decode() key count = %d, want 2", len(decoded.Keys))
		}
		wantIDs := []string{"signing-key", "encryption-key"}
		wantRestrictions := [][]key.Capability{
			{
				{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: key.KeyAlg("HS256")},
				{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: key.KeyAlg("HS256")},
			},
			{{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: key.KeyAlg("A256GCM")}},
		}
		wantKey := []byte("0123456789abcdef0123456789abcdef")
		for i, candidate := range decoded.Keys {
			if candidate.ID != wantIDs[i] {
				t.Errorf("Decode() key %d ID = %q, want %q", i+1, candidate.ID, wantIDs[i])
			}
			if !reflect.DeepEqual(candidate.Restrictions, wantRestrictions[i]) {
				t.Errorf("Decode() key %d restrictions = %#v, want %#v", i+1, candidate.Restrictions, wantRestrictions[i])
			}
			value, ok := candidate.Material.(*material.SymmetricMaterial)
			if !ok || !reflect.DeepEqual(value.Key, wantKey) {
				t.Errorf("Decode() key %d material = %#v, want fixture symmetric key", i+1, candidate.Material)
			}
		}
	}
	assertEmpty := func(t *testing.T, decoded jwks.JWKS[key.KeyCandidate], err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if decoded.Keys == nil || len(decoded.Keys) != 0 {
			t.Errorf("Decode() keys = %#v, want non-nil empty slice", decoded.Keys)
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, jwks.JWKS[key.KeyCandidate], error) {
		return func(t *testing.T, decoded jwks.JWKS[key.KeyCandidate], err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Decode() error = %v, want error containing %q", err, want)
			}
			if !reflect.DeepEqual(decoded, jwks.JWKS[key.KeyCandidate]{}) {
				t.Errorf("Decode() result = %#v, want zero value", decoded)
			}
		}
	}
	assertCategory := func(category error) func(*testing.T, jwks.JWKS[key.KeyCandidate], error) {
		return func(t *testing.T, decoded jwks.JWKS[key.KeyCandidate], err error) {
			if !errors.Is(err, category) {
				t.Errorf("Decode() error = %v, want category %v", err, category)
			}
			if !reflect.DeepEqual(decoded, jwks.JWKS[key.KeyCandidate]{}) {
				t.Errorf("Decode() result = %#v, want zero value", decoded)
			}
		}
	}
	assertCanceled := func(t *testing.T, decoded jwks.JWKS[key.KeyCandidate], err error) {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Decode() error = %v, want context.Canceled", err)
		}
		if !reflect.DeepEqual(decoded, jwks.JWKS[key.KeyCandidate]{}) {
			t.Errorf("Decode() result = %#v, want zero value", decoded)
		}
	}
	assertOptions := func(t *testing.T, decoded jwks.JWKS[key.KeyCandidate], err error) {
		assertDecoded(t, decoded, err)
		want := []string{"runtime before", "call before", "call after", "runtime after"}
		if !reflect.DeepEqual(optionOrder, want) {
			t.Errorf("Decode() option order = %v, want %v", optionOrder, want)
		}
	}
	tests := []struct {
		name      string
		decoder   vapi.Decoder[jwks.JWKS[key.KeyCandidate], jwks.DecoderOption]
		ctx       context.Context
		encoded   []byte
		options   []jwks.DecoderOption
		assertion func(*testing.T, jwks.JWKS[key.KeyCandidate], error)
	}{
		{name: "JWKS", decoder: defaultDecoder, ctx: context.Background(), encoded: validJWKS, assertion: assertDecoded},
		{name: "Empty JWKS", decoder: defaultDecoder, ctx: context.Background(), encoded: emptyJWKS, assertion: assertEmpty},
		{name: "Canceled Context", decoder: defaultDecoder, ctx: canceledContext, encoded: validJWKS, assertion: assertCanceled},
		{name: "Nil Decoder", decoder: (*jwks.Decoder)(nil), ctx: context.Background(), encoded: validJWKS, assertion: assertCategory(vapi.ErrMisconfigured)},
		{name: "Nil Payload", decoder: defaultDecoder, ctx: context.Background(), assertion: assertCategory(vapi.ErrMalformed)},
		{name: "Malformed JWKS", decoder: defaultDecoder, ctx: context.Background(), encoded: []byte(`{"keys":[`), assertion: assertErrorContaining("unmarshal key set")},
		{name: "Missing Keys", decoder: defaultDecoder, ctx: context.Background(), encoded: []byte(`{}`), assertion: assertErrorContaining("keys member is required")},
		{name: "Malformed Key", decoder: defaultDecoder, ctx: context.Background(), encoded: []byte(`{"keys":[1]}`), assertion: assertErrorContaining("unmarshal header")},
		{name: "Missing Key Type", decoder: defaultDecoder, ctx: context.Background(), encoded: []byte(`{"keys":[{}]}`), assertion: assertErrorContaining("kty member is required")},
		{name: "Unsupported Key Type", decoder: defaultDecoder, ctx: context.Background(), encoded: []byte(`{"keys":[{"kty":"unsupported"}]}`), assertion: assertErrorContaining("key type is not supported")},
		{name: "Key Decode Failure", decoder: defaultDecoder, ctx: context.Background(), encoded: []byte(`{"keys":[{"kty":"oct"}]}`), assertion: assertErrorContaining(`parameter "k" is missing`)},
		{name: "Nil Option", decoder: defaultDecoder, ctx: context.Background(), encoded: validJWKS, options: []jwks.DecoderOption{nil}, assertion: assertCategory(vapi.ErrMisconfigured)},
		{name: "Option Returning Nil", decoder: defaultDecoder, ctx: context.Background(), encoded: validJWKS, options: []jwks.DecoderOption{func(jwks.DecodeFunc) jwks.DecodeFunc { return nil }}, assertion: assertCategory(vapi.ErrMisconfigured)},
		{name: "Runtime And Call Options", decoder: optionDecoder, ctx: context.Background(), encoded: validJWKS, options: []jwks.DecoderOption{option("call")}, assertion: assertOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.decoder.Decode(tt.ctx, tt.encoded, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}

}
