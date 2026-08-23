package ec

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_joseEncoder_Encode(t *testing.T) {
	// keys
	p256 := testkeys.Private(t, testkeys.ES256).(*ecdsa.PrivateKey)
	p384 := testkeys.Private(t, testkeys.ES384).(*ecdsa.PrivateKey)
	p521 := testkeys.Private(t, testkeys.ES512).(*ecdsa.PrivateKey)
	rsaPublic := testkeys.Public(t, testkeys.RSA2048)
	brokenPublic := testkeys.MalformedPublic(t, testkeys.ES256, testkeys.MissingPublicPoint)
	brokenPrivate := testkeys.MalformedPrivate(t, testkeys.ES256, testkeys.ZeroPrivateValue)
	// certificate
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(3600, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &p256.PublicKey, p256)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	// values
	newKey := func(id string, value material.Material, restrictions ...key.Capability) key.Key {
		return key.New(key.KeyCandidate{ID: id, Material: value, Restrictions: restrictions}, nil)
	}
	restrictions := []key.Capability{
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: ES256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: ES256},
	}
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertKey := func(want *ecdsa.PrivateKey, curve string, wantPrivate bool) func(*testing.T, []byte, error) {
		return func(t *testing.T, encoded []byte, err error) {
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			var jwk ecJWK
			if err := json.Unmarshal(encoded, &jwk); err != nil {
				t.Fatalf("standard library JSON decoding failed: %v", err)
			}
			if jwk.KeyType != "EC" || jwk.Curve != curve {
				t.Errorf("Encode() key type/curve = %q/%q, want EC/%s", jwk.KeyType, jwk.Curve, curve)
			}
			x, xErr := base64.RawURLEncoding.DecodeString(jwk.X)
			y, yErr := base64.RawURLEncoding.DecodeString(jwk.Y)
			if xErr != nil || yErr != nil || new(big.Int).SetBytes(x).Cmp(want.X) != 0 || new(big.Int).SetBytes(y).Cmp(want.Y) != 0 {
				t.Errorf("Encode() public point does not match fixture key")
			}
			if (jwk.Private != "") != wantPrivate {
				t.Errorf("Encode() private material presence = %v, want %v", jwk.Private != "", wantPrivate)
			}
			if wantPrivate {
				d, decodeErr := base64.RawURLEncoding.DecodeString(jwk.Private)
				if decodeErr != nil || new(big.Int).SetBytes(d).Cmp(want.D) != 0 {
					t.Errorf("Encode() private scalar does not match fixture key")
				}
			}
		}
	}
	assertMetadata := func(t *testing.T, encoded []byte, err error) {
		assertKey(p256, "P-256", false)(t, encoded, err)
		var jwk ecJWK
		_ = json.Unmarshal(encoded, &jwk)
		if jwk.KeyID != "signing-key" || jwk.Use != "sig" || jwk.Algorithm != string(ES256) {
			t.Errorf("Encode() metadata = (kid %q, use %q, alg %q)", jwk.KeyID, jwk.Use, jwk.Algorithm)
		}
		if want := []string{"sign", "verify"}; !reflect.DeepEqual(jwk.Operations, want) {
			t.Errorf("Encode() key_ops = %#v, want %#v", jwk.Operations, want)
		}
	}
	assertCertificate := func(t *testing.T, encoded []byte, err error) {
		assertKey(p256, "P-256", false)(t, encoded, err)
		var jwk ecJWK
		_ = json.Unmarshal(encoded, &jwk)
		if want := []string{base64.StdEncoding.EncodeToString(certificateDER)}; !reflect.DeepEqual(jwk.Certificates, want) {
			t.Errorf("Encode() x5c = %#v, want certificate", jwk.Certificates)
		}
		if jwk.SHA1Thumbprint == "" || jwk.SHA256Thumbprint == "" {
			t.Errorf("Encode() certificate thumbprints are missing")
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
		{name: "P-256 Public Metadata", ctx: context.Background(), value: newKey("signing-key", &material.PublicMaterial{Key: &p256.PublicKey}, restrictions...), assertion: assertMetadata},
		{name: "P-384 Public", ctx: context.Background(), value: newKey("", &material.PublicMaterial{Key: &p384.PublicKey}), assertion: assertKey(p384, "P-384", false)},
		{name: "P-521 Public", ctx: context.Background(), value: newKey("", &material.PublicMaterial{Key: &p521.PublicKey}), assertion: assertKey(p521, "P-521", false)},
		{name: "Private Default Public Export", ctx: context.Background(), value: newKey("", &material.PrivateMaterial{Key: p256}), assertion: assertKey(p256, "P-256", false)},
		{name: "Private Export", ctx: context.Background(), value: newKey("", &material.PrivateMaterial{Key: p256}), options: []key.JOSEEncodeOption{{MaterialPolicy: key.ExportPrivateMaterial}}, assertion: assertKey(p256, "P-256", true)},
		{name: "Certificate", ctx: context.Background(), value: newKey("", &material.CertificateMaterial{Cert: certificate}), assertion: assertCertificate},
		{name: "Canceled Context", ctx: canceledContext, value: newKey("", &material.PublicMaterial{Key: &p256.PublicKey}), assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), value: newKey("", &material.PublicMaterial{Key: &p256.PublicKey}), options: []key.JOSEEncodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Unsupported Policy", ctx: context.Background(), value: newKey("", &material.PublicMaterial{Key: &p256.PublicKey}), options: []key.JOSEEncodeOption{{MaterialPolicy: 255}}, assertion: assertErrorContaining("unsupported material export policy")},
		{name: "Mismatched Public", ctx: context.Background(), value: newKey("", &material.PublicMaterial{Key: rsaPublic}), assertion: assertErrorContaining("not an EC public key")},
		{name: "Invalid Public", ctx: context.Background(), value: newKey("", &material.PublicMaterial{Key: brokenPublic}), assertion: assertErrorContaining("invalid public key")},
		{name: "Invalid Private", ctx: context.Background(), value: newKey("", &material.PrivateMaterial{Key: brokenPrivate}), assertion: assertErrorContaining("invalid private key")},
		{name: "Nil Certificate", ctx: context.Background(), value: newKey("", &material.CertificateMaterial{}), assertion: assertErrorContaining("certificate is nil")},
		{name: "Mismatched Certificate", ctx: context.Background(), value: newKey("", &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: rsaPublic}}), assertion: assertErrorContaining("does not contain an EC public key")},
		{name: "Certificate Without DER", ctx: context.Background(), value: newKey("", &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: &p256.PublicKey}}), assertion: assertErrorContaining("certificate DER is empty")},
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
