package symetric

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_joseEncoder_Encode(t *testing.T) {
	// keys
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	// restrictions
	restrictions := []key.Capability{
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: key.KeyAlg("HS256")},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: key.KeyAlg("HS256")},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: key.KeyAlg("HS256")},
	}
	// values
	newKey := func(id string, value material.Material, capabilities ...key.Capability) key.Key {
		return key.New(key.KeyCandidate{ID: id, Material: value, Restrictions: capabilities}, nil)
	}
	symmetricKey := newKey("signing-key", &material.SymmetricMaterial{Key: keyBytes}, restrictions...)
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertEncoded := func(t *testing.T, encoded []byte, err error) {
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		var jwk symmetricJWK
		if err := json.Unmarshal(encoded, &jwk); err != nil {
			t.Fatalf("standard library JSON decoding failed: %v", err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(jwk.Key)
		if err != nil || !reflect.DeepEqual(decoded, keyBytes) {
			t.Errorf("Encode() key does not match fixture key")
		}
		if jwk.KeyType != "oct" || jwk.KeyID != "signing-key" || jwk.Use != "sig" || jwk.Algorithm != "HS256" {
			t.Errorf("Encode() metadata = %#v, want oct signing JWK", jwk)
		}
		if want := []string{"sign", "verify"}; !reflect.DeepEqual(jwk.Operations, want) {
			t.Errorf("Encode() key_ops = %#v, want %#v", jwk.Operations, want)
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
		if !errors.Is(err, context.Canceled) || encoded != nil {
			t.Errorf("Encode() = (%q, %v), want (nil, context.Canceled)", encoded, err)
		}
	}
	tests := []struct {
		name      string
		ctx       context.Context
		value     key.Key
		options   []key.JOSEEncodeOption
		assertion func(*testing.T, []byte, error)
	}{
		{name: "Symmetric Signing Key", ctx: context.Background(), value: symmetricKey, options: []key.JOSEEncodeOption{{MaterialPolicy: key.ExportPrivateMaterial}}, assertion: assertEncoded},
		{name: "Default Export Policy", ctx: context.Background(), value: symmetricKey, assertion: assertErrorContaining("not permitted")},
		{name: "Canceled Context", ctx: canceledContext, value: symmetricKey, assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), value: symmetricKey, options: []key.JOSEEncodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Unsupported Export Policy", ctx: context.Background(), value: symmetricKey, options: []key.JOSEEncodeOption{{MaterialPolicy: key.MaterialExportPolicy(255)}}, assertion: assertErrorContaining("unsupported material export policy")},
		{name: "Unsupported Material", ctx: context.Background(), value: newKey("", &material.PublicMaterial{}), options: []key.JOSEEncodeOption{{MaterialPolicy: key.ExportPrivateMaterial}}, assertion: assertErrorContaining("material is not symmetric")},
		{name: "Empty Key", ctx: context.Background(), value: newKey("", &material.SymmetricMaterial{}), options: []key.JOSEEncodeOption{{MaterialPolicy: key.ExportPrivateMaterial}}, assertion: assertErrorContaining("key is empty")},
	}
	encoder := &joseEncoder{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := encoder.Encode(tt.ctx, tt.value, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
