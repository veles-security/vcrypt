package descriptor

import (
	"context"
	stdrsa "crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	_ "github.com/veles-security/vcrypt/backend/rsa"
	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_JWKSEncoder_Encode(t *testing.T) {
	// keys
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*stdrsa.PrivateKey)
	publicKey := key.New(key.KeyCandidate{ID: "public-key", Material: &material.PublicMaterial{Key: &privateKey.PublicKey}}, nil)
	private := key.New(key.KeyCandidate{ID: "private-key", Material: &material.PrivateMaterial{Key: privateKey}}, nil)
	unsupported := key.New(key.KeyCandidate{ID: "symmetric-key", Material: &material.SymmetricMaterial{Key: []byte("secret")}}, nil)
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertKeySet := func(wantCount int, wantPrivate bool) func(*testing.T, []byte, error) {
		return func(t *testing.T, encoded []byte, err error) {
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			var document struct {
				Keys []map[string]any `json:"keys"`
			}
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatalf("standard library JSON decoding failed: %v", err)
			}
			if len(document.Keys) != wantCount {
				t.Fatalf("Encode() key count = %d, want %d", len(document.Keys), wantCount)
			}
			for _, encodedKey := range document.Keys {
				if encodedKey["kty"] != "RSA" {
					t.Errorf("Encode() kty = %v, want RSA", encodedKey["kty"])
				}
				_, hasPrivate := encodedKey["d"]
				if hasPrivate != wantPrivate {
					t.Errorf("Encode() private material presence = %v, want %v", hasPrivate, wantPrivate)
				}
			}
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, []byte, error) {
		return func(t *testing.T, encoded []byte, err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Encode() error = %v, want error containing %q", err, want)
			}
			if encoded != nil {
				t.Errorf("Encode() = %q, want nil", encoded)
			}
		}
	}
	assertCanceled := func(t *testing.T, encoded []byte, err error) {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Encode() error = %v, want context.Canceled", err)
		}
		if encoded != nil {
			t.Errorf("Encode() = %q, want nil", encoded)
		}
	}
	tests := []struct {
		name      string
		ctx       context.Context
		artifact  JWKS[key.Key]
		options   []key.JOSEEncodeOption
		assertion func(*testing.T, []byte, error)
	}{
		{name: "Public Keys", ctx: context.Background(), artifact: JWKS[key.Key]{Keys: []key.Key{publicKey, private}}, assertion: assertKeySet(2, false)},
		{name: "Private Export", ctx: context.Background(), artifact: JWKS[key.Key]{Keys: []key.Key{private}}, options: []key.JOSEEncodeOption{{MaterialPolicy: key.ExportPrivateMaterial}}, assertion: assertKeySet(1, true)},
		{name: "Empty Set", ctx: context.Background(), artifact: JWKS[key.Key]{}, assertion: assertKeySet(0, false)},
		{name: "Canceled Context", ctx: canceledContext, artifact: JWKS[key.Key]{Keys: []key.Key{publicKey}}, assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), artifact: JWKS[key.Key]{}, options: []key.JOSEEncodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Unsupported Key", ctx: context.Background(), artifact: JWKS[key.Key]{Keys: []key.Key{publicKey, unsupported}}, assertion: assertErrorContaining("key 2")},
	}
	encoder := &JWKSEncoder{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := encoder.Encode(tt.ctx, tt.artifact, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
