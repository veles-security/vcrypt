package rsa

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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

func Test_joseEncoder_Encode(t *testing.T) {
	// keys
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*rsa.PrivateKey)
	publicKey := &privateKey.PublicKey
	mismatchedPrivateKey := testkeys.Private(t, testkeys.ES256)
	mismatchedPublicKey := testkeys.Public(t, testkeys.ES256)
	brokenPrivateKey := testkeys.MalformedPrivate(t, testkeys.RSA2048, testkeys.IncompleteKey)
	// certificates
	certificateDER := []byte("test RSA certificate DER")
	certificate := &x509.Certificate{Raw: certificateDER, PublicKey: publicKey}
	// restrictions
	restrictions := []key.Capability{
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: RS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: RS256},
	}
	// values
	newKey := func(id string, value material.Material, capabilities ...key.Capability) key.Key {
		return key.New(key.KeyCandidate{ID: id, Material: value, Restrictions: capabilities}, nil)
	}
	publicValue := newKey("public-signing-key", &material.PublicMaterial{Key: publicKey}, restrictions...)
	privateValue := newKey("private-signing-key", &material.PrivateMaterial{Key: privateKey}, restrictions...)
	certificateValue := newKey("certificate-key", &material.CertificateMaterial{Cert: certificate})
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	decodeJWK := func(t *testing.T, encoded []byte, err error) rsaJWK {
		t.Helper()
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		var jwk rsaJWK
		if err := json.Unmarshal(encoded, &jwk); err != nil {
			t.Fatalf("standard library JSON decoding failed: %v", err)
		}
		if jwk.KeyType != "RSA" {
			t.Errorf("Encode() kty = %q, want RSA", jwk.KeyType)
		}
		modulus, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
		if err != nil {
			t.Fatalf("standard library modulus decoding failed: %v", err)
		}
		exponent, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
		if err != nil {
			t.Fatalf("standard library exponent decoding failed: %v", err)
		}
		if new(big.Int).SetBytes(modulus).Cmp(publicKey.N) != 0 || new(big.Int).SetBytes(exponent).Int64() != int64(publicKey.E) {
			t.Errorf("Encode() public key does not match fixture key")
		}
		return jwk
	}
	assertPublic := func(t *testing.T, encoded []byte, err error) {
		jwk := decodeJWK(t, encoded, err)
		if jwk.KeyID != "public-signing-key" || jwk.Use != "sig" || jwk.Algorithm != string(RS256) {
			t.Errorf("Encode() metadata = (kid %q, use %q, alg %q), want (%q, sig, RS256)", jwk.KeyID, jwk.Use, jwk.Algorithm, "public-signing-key")
		}
		if want := []string{"sign", "verify"}; !reflect.DeepEqual(jwk.Operations, want) {
			t.Errorf("Encode() key_ops = %#v, want %#v", jwk.Operations, want)
		}
		if jwk.Private != "" || jwk.Prime1 != "" || jwk.Prime2 != "" {
			t.Errorf("Encode() exposed private material")
		}
	}
	assertPrivate := func(t *testing.T, encoded []byte, err error) {
		jwk := decodeJWK(t, encoded, err)
		parameters := map[string]struct {
			encoded string
			want    *big.Int
		}{
			"d": {encoded: jwk.Private, want: privateKey.D},
			"p": {encoded: jwk.Prime1, want: privateKey.Primes[0]},
			"q": {encoded: jwk.Prime2, want: privateKey.Primes[1]},
		}
		for name, parameter := range parameters {
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(parameter.encoded)
			if decodeErr != nil || new(big.Int).SetBytes(decoded).Cmp(parameter.want) != 0 {
				t.Errorf("Encode() private parameter %q does not match fixture key", name)
			}
		}
		decodedCandidate, decodeErr := (&joseDecoder{}).Decode(context.Background(), encoded)
		if decodeErr != nil {
			t.Fatalf("independent JWK decoding failed: %v", decodeErr)
		}
		decodedMaterial, ok := decodedCandidate.Material.(*material.PrivateMaterial)
		if !ok {
			t.Fatalf("decoded material = %T, want *material.PrivateMaterial", decodedCandidate.Material)
		}
		decodedKey, keyOK := decodedMaterial.Key.(*rsa.PrivateKey)
		if !keyOK || !decodedKey.Equal(privateKey) {
			t.Errorf("Encode() private key does not round trip")
		}
	}
	assertPrivateAsPublic := func(t *testing.T, encoded []byte, err error) {
		jwk := decodeJWK(t, encoded, err)
		if jwk.Private != "" || jwk.Prime1 != "" || jwk.Prime2 != "" || jwk.Exponent1 != "" || jwk.Exponent2 != "" || jwk.Coefficient != "" {
			t.Errorf("Encode() exposed private material under public export policy")
		}
	}
	assertCertificate := func(t *testing.T, encoded []byte, err error) {
		jwk := decodeJWK(t, encoded, err)
		if want := []string{base64.StdEncoding.EncodeToString(certificateDER)}; !reflect.DeepEqual(jwk.Certificates, want) {
			t.Errorf("Encode() x5c = %#v, want %#v", jwk.Certificates, want)
		}
		sha1Sum := sha1.Sum(certificateDER)
		sha256Sum := sha256.Sum256(certificateDER)
		if jwk.SHA1Thumbprint != base64.RawURLEncoding.EncodeToString(sha1Sum[:]) {
			t.Errorf("Encode() x5t does not match certificate")
		}
		if jwk.SHA256Thumbprint != base64.RawURLEncoding.EncodeToString(sha256Sum[:]) {
			t.Errorf("Encode() x5t#S256 does not match certificate")
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, []byte, error) {
		return func(t *testing.T, encoded []byte, err error) {
			if err == nil {
				t.Fatalf("Encode() error = nil, want error containing %q", want)
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Encode() error = %q, want error containing %q", err, want)
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
		value     key.Key
		options   []key.JOSEEncodeOption
		assertion func(*testing.T, []byte, error)
	}{
		{name: "Public Signing Key", ctx: context.Background(), value: publicValue, assertion: assertPublic},
		{name: "Private Key With Default Public Export", ctx: context.Background(), value: privateValue, assertion: assertPrivateAsPublic},
		{name: "Private Key With Private Export", ctx: context.Background(), value: privateValue, options: []key.JOSEEncodeOption{{MaterialPolicy: key.ExportPrivateMaterial}}, assertion: assertPrivate},
		{name: "Certificate", ctx: context.Background(), value: certificateValue, assertion: assertCertificate},
		{name: "Canceled Context", ctx: canceledContext, value: publicValue, assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), value: publicValue, options: []key.JOSEEncodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Unsupported Export Policy", ctx: context.Background(), value: publicValue, options: []key.JOSEEncodeOption{{MaterialPolicy: key.MaterialExportPolicy(255)}}, assertion: assertErrorContaining("unsupported material export policy")},
		{name: "Mismatched Public Key", ctx: context.Background(), value: newKey("", &material.PublicMaterial{Key: mismatchedPublicKey}), assertion: assertErrorContaining("not an RSA public key")},
		{name: "Mismatched Private Key", ctx: context.Background(), value: newKey("", &material.PrivateMaterial{Key: mismatchedPrivateKey}), assertion: assertErrorContaining("not an RSA private key")},
		{name: "Invalid Private Key", ctx: context.Background(), value: newKey("", &material.PrivateMaterial{Key: brokenPrivateKey}), assertion: assertErrorContaining("invalid private key")},
		{name: "Nil Certificate", ctx: context.Background(), value: newKey("", &material.CertificateMaterial{}), assertion: assertErrorContaining("certificate is nil")},
		{name: "Mismatched Certificate", ctx: context.Background(), value: newKey("", &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: mismatchedPublicKey}}), assertion: assertErrorContaining("does not contain an RSA public key")},
		{name: "Certificate Without DER", ctx: context.Background(), value: newKey("", &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: publicKey}}), assertion: assertErrorContaining("certificate DER is empty")},
		{name: "Unsupported Material", ctx: context.Background(), value: newKey("", &material.SymmetricMaterial{Key: []byte("secret")}), assertion: assertErrorContaining("material is not supported")},
	}
	encoder := &joseEncoder{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := encoder.Encode(tt.ctx, tt.value, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
