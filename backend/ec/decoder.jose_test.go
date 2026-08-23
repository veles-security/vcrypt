package ec

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_joseDecoder_Decode(t *testing.T) {
	// keys
	p256 := testkeys.Private(t, testkeys.ES256).(*ecdsa.PrivateKey)
	p384 := testkeys.Private(t, testkeys.ES384).(*ecdsa.PrivateKey)
	p521 := testkeys.Private(t, testkeys.ES512).(*ecdsa.PrivateKey)
	one := big.NewInt(1)
	// JSON Web Keys
	encode := func(t *testing.T, value ecJWK) []byte {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	publicJWK := func(value *ecdsa.PrivateKey, curve string) ecJWK {
		return ecJWK{KeyType: "EC", Curve: curve, X: encodeCoordinate(value.X, value.Curve), Y: encodeCoordinate(value.Y, value.Curve)}
	}
	p256Public := publicJWK(p256, "P-256")
	p256Public.KeyID = "signing-key"
	p256Public.Use = "sig"
	p256Public.Operations = []string{"sign", "verify"}
	p256Public.Algorithm = "ES256"
	p256Private := p256Public
	p256Private.Private = encodeCoordinate(p256.D, p256.Curve)
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertPublic := func(want *ecdsa.PrivateKey) func(*testing.T, key.KeyCandidate, error) {
		return func(t *testing.T, candidate key.KeyCandidate, err error) {
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			publicMaterial, ok := candidate.Material.(*material.PublicMaterial)
			if !ok {
				t.Fatalf("Decode() material = %T, want *material.PublicMaterial", candidate.Material)
			}
			decoded, ok := publicMaterial.Key.(*ecdsa.PublicKey)
			if !ok || !decoded.Equal(&want.PublicKey) {
				t.Errorf("Decode() public key does not match fixture key")
			}
		}
	}
	assertMetadata := func(t *testing.T, candidate key.KeyCandidate, err error) {
		assertPublic(p256)(t, candidate, err)
		if candidate.ID != "signing-key" {
			t.Errorf("Decode() ID = %q, want signing-key", candidate.ID)
		}
		want := []key.Capability{
			{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: ES256},
			{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES256},
		}
		if !reflect.DeepEqual(candidate.Restrictions, want) {
			t.Errorf("Decode() restrictions = %#v, want %#v", candidate.Restrictions, want)
		}
	}
	assertPrivate := func(t *testing.T, candidate key.KeyCandidate, err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		privateMaterial, ok := candidate.Material.(*material.PrivateMaterial)
		if !ok {
			t.Fatalf("Decode() material = %T, want *material.PrivateMaterial", candidate.Material)
		}
		decoded, ok := privateMaterial.Key.(*ecdsa.PrivateKey)
		if !ok || !decoded.Equal(p256) {
			t.Errorf("Decode() private key does not match fixture key")
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
	offCurve := p256Public
	offCurve.X = encodeCoordinate(one, p256.Curve)
	offCurve.Y = encodeCoordinate(one, p256.Curve)
	mismatchedPrivate := p256Private
	mismatchedPrivate.Private = encodeCoordinate(one, p256.Curve)
	tests := []struct {
		name      string
		ctx       context.Context
		encoded   []byte
		options   []key.JOSEDecodeOption
		assertion func(*testing.T, key.KeyCandidate, error)
	}{
		{name: "P-256 Public Metadata", ctx: context.Background(), encoded: encode(t, p256Public), assertion: assertMetadata},
		{name: "P-384 Public", ctx: context.Background(), encoded: encode(t, publicJWK(p384, "P-384")), assertion: assertPublic(p384)},
		{name: "P-521 Public", ctx: context.Background(), encoded: encode(t, publicJWK(p521, "P-521")), assertion: assertPublic(p521)},
		{name: "P-256 Private", ctx: context.Background(), encoded: encode(t, p256Private), assertion: assertPrivate},
		{name: "Canceled Context", ctx: canceledContext, encoded: encode(t, p256Public), assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), encoded: encode(t, p256Public), options: []key.JOSEDecodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Malformed JSON", ctx: context.Background(), encoded: []byte(`{"kty":"EC"`), assertion: assertErrorContaining("unmarshal JWK")},
		{name: "Unsupported Key Type", ctx: context.Background(), encoded: []byte(`{"kty":"RSA"}`), assertion: assertErrorContaining(`unsupported kty "RSA"`)},
		{name: "Unsupported Curve", ctx: context.Background(), encoded: []byte(`{"kty":"EC","crv":"secp256k1"}`), assertion: assertErrorContaining("unsupported curve")},
		{name: "Missing X", ctx: context.Background(), encoded: []byte(`{"kty":"EC","crv":"P-256","y":"AA"}`), assertion: assertErrorContaining(`parameter "x" is missing`)},
		{name: "Invalid X Encoding", ctx: context.Background(), encoded: []byte(`{"kty":"EC","crv":"P-256","x":"%%%","y":"AA"}`), assertion: assertErrorContaining(`decode parameter "x"`)},
		{name: "Invalid Coordinate Length", ctx: context.Background(), encoded: []byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`), assertion: assertErrorContaining("has length")},
		{name: "Point Off Curve", ctx: context.Background(), encoded: encode(t, offCurve), assertion: assertErrorContaining("not on curve")},
		{name: "Private Scalar Mismatch", ctx: context.Background(), encoded: encode(t, mismatchedPrivate), assertion: assertErrorContaining("does not match public point")},
	}
	decoder := &joseDecoder{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := decoder.Decode(tt.ctx, tt.encoded, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
