package symetric

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_joseDecoder_Decode(t *testing.T) {
	// keys
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	// JSON Web Keys
	signingJWK := []byte(`{"kty":"oct","kid":"signing-key","use":"sig","key_ops":["sign","verify"],"alg":"HS256","k":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"}`)
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertSigningKey := func(t *testing.T, candidate key.KeyCandidate, err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		value, ok := candidate.Material.(*material.SymmetricMaterial)
		if !ok || !reflect.DeepEqual(value.Key, keyBytes) {
			t.Fatalf("Decode() material = %#v, want fixture symmetric key", candidate.Material)
		}
		want := []key.Capability{
			{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: key.KeyAlg("HS256")},
			{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: key.KeyAlg("HS256")},
		}
		if candidate.ID != "signing-key" || !reflect.DeepEqual(candidate.Restrictions, want) {
			t.Errorf("Decode() = %#v, want signing-key with %#v", candidate, want)
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, key.KeyCandidate, error) {
		return func(t *testing.T, candidate key.KeyCandidate, err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Decode() error = %v, want error containing %q", err, want)
			}
			if !reflect.DeepEqual(candidate, key.KeyCandidate{}) {
				t.Errorf("Decode() candidate = %#v, want zero value", candidate)
			}
		}
	}
	assertCanceled := func(t *testing.T, candidate key.KeyCandidate, err error) {
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(candidate, key.KeyCandidate{}) {
			t.Errorf("Decode() = (%#v, %v), want (zero, context.Canceled)", candidate, err)
		}
	}
	tests := []struct {
		name      string
		ctx       context.Context
		encoded   []byte
		options   []key.JOSEDecodeOption
		assertion func(*testing.T, key.KeyCandidate, error)
	}{
		{name: "Symmetric Signing JWK", ctx: context.Background(), encoded: signingJWK, assertion: assertSigningKey},
		{name: "Canceled Context", ctx: canceledContext, encoded: signingJWK, assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), encoded: signingJWK, options: []key.JOSEDecodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Malformed JSON", ctx: context.Background(), encoded: []byte(`{"kty":"oct"`), assertion: assertErrorContaining("unmarshal JWK")},
		{name: "Unsupported Key Type", ctx: context.Background(), encoded: []byte(`{"kty":"RSA","k":"AQ"}`), assertion: assertErrorContaining(`unsupported kty "RSA"`)},
		{name: "Missing Key", ctx: context.Background(), encoded: []byte(`{"kty":"oct"}`), assertion: assertErrorContaining(`parameter "k" is missing`)},
		{name: "Invalid Key Encoding", ctx: context.Background(), encoded: []byte(`{"kty":"oct","k":"%%%"}`), assertion: assertErrorContaining(`decode parameter "k"`)},
	}
	decoder := &joseDecoder{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := decoder.Decode(tt.ctx, tt.encoded, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
