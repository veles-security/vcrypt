package descriptor

import (
	"context"
	stdrsa "crypto/rsa"
	"errors"
	"strings"
	"testing"

	_ "github.com/veles-security/vcrypt/backend/rsa"
	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_JWKSDecoder_Decode(t *testing.T) {
	// keys
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*stdrsa.PrivateKey)
	// JSON Web Key Sets
	valid := []byte(`{"keys":[{"kty":"RSA","kid":"signing-key","n":"x457suHRD7n8qToSDmZjxRLT2qdJpWy3qKfUmh10t-kcRgsgBMeaA9vbAgpZu8CG33ory3nZGt9gw3Q0OKJ9SMwe0SLzOgpzzPM7dhniJc2DxxLaBSAqvlQ2STaa7JABwfiNNcrTA0QLQ8kwdpVoWwiR7kYXlPwgIEMghsSE7GyLUzsIxAND7bq2z5t3RwLiZgaS5WWbb5ltc-mreO7vE0NtUlDTx3UWn8FxlmiNbi6DaCThezYsENZRI0yOIjxitFQ1wxJd7U0GgAS_LmrQQBjV8fGGfYOzazuKwIcEt0PQn54ULM9RQypjVPpfgJdUMlkLqxK2nWu09Mhr-CGNkQ","e":"AQAB"}]}`)
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertValid := func(t *testing.T, artifact JWKS[key.KeyCandidate], err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if len(artifact.Keys) != 1 {
			t.Fatalf("Decode() key count = %d, want 1", len(artifact.Keys))
		}
		decoded := artifact.Keys[0]
		if decoded.ID != "signing-key" {
			t.Errorf("Decode() key ID = %q, want signing-key", decoded.ID)
		}
		publicMaterial, ok := decoded.Material.(*material.PublicMaterial)
		if !ok {
			t.Fatalf("Decode() material = %T, want *material.PublicMaterial", decoded.Material)
		}
		publicKey, ok := publicMaterial.Key.(*stdrsa.PublicKey)
		if !ok || !publicKey.Equal(&privateKey.PublicKey) {
			t.Errorf("Decode() public key does not match fixture key")
		}
	}
	assertEmpty := func(t *testing.T, artifact JWKS[key.KeyCandidate], err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if artifact.Keys == nil || len(artifact.Keys) != 0 {
			t.Errorf("Decode() keys = %#v, want non-nil empty slice", artifact.Keys)
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, JWKS[key.KeyCandidate], error) {
		return func(t *testing.T, artifact JWKS[key.KeyCandidate], err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Decode() error = %v, want error containing %q", err, want)
			}
			if artifact.Keys != nil {
				t.Errorf("Decode() artifact = %#v, want zero value", artifact)
			}
		}
	}
	assertCanceled := func(t *testing.T, artifact JWKS[key.KeyCandidate], err error) {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Decode() error = %v, want context.Canceled", err)
		}
		if artifact.Keys != nil {
			t.Errorf("Decode() artifact = %#v, want zero value", artifact)
		}
	}
	tests := []struct {
		name      string
		ctx       context.Context
		encoded   []byte
		options   []key.JOSEDecodeOption
		assertion func(*testing.T, JWKS[key.KeyCandidate], error)
	}{
		{name: "RSA Key Set", ctx: context.Background(), encoded: valid, assertion: assertValid},
		{name: "Empty Set", ctx: context.Background(), encoded: []byte(`{"keys":[]}`), assertion: assertEmpty},
		{name: "Canceled Context", ctx: canceledContext, encoded: valid, assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), encoded: valid, options: []key.JOSEDecodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Malformed JSON", ctx: context.Background(), encoded: []byte(`{"keys":[`), assertion: assertErrorContaining("unmarshal key set")},
		{name: "Missing Keys", ctx: context.Background(), encoded: []byte(`{}`), assertion: assertErrorContaining("keys member is required")},
		{name: "Null Keys", ctx: context.Background(), encoded: []byte(`{"keys":null}`), assertion: assertErrorContaining("keys member is required")},
		{name: "Missing Key Type", ctx: context.Background(), encoded: []byte(`{"keys":[{"n":"AQ","e":"Aw"}]}`), assertion: assertErrorContaining("kty member is required")},
		{name: "Unsupported Key Type", ctx: context.Background(), encoded: []byte(`{"keys":[{"kty":"unsupported"}]}`), assertion: assertErrorContaining("select decoder")},
		{name: "Invalid Registered Key", ctx: context.Background(), encoded: []byte(`{"keys":[{"kty":"RSA","e":"AQAB"}]}`), assertion: assertErrorContaining("key 1")},
	}
	decoder := &JWKSDecoder{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := decoder.Decode(tt.ctx, tt.encoded, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
