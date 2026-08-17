package scheme_test

import (
	"crypto"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/veles-security/vcrypt"
	"github.com/veles-security/vcrypt/alg"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/scheme"
	rsascheme "github.com/veles-security/vcrypt/scheme/rsa"
)

type symmetricMaterial []byte

func (symmetricMaterial) Public() crypto.PublicKey { return nil }

type symmetricScheme struct{}

func (*symmetricScheme) DiscoverCapabilities(*key.Key) error    { return nil }
func (*symmetricScheme) Signer(*key.Key, alg.Alg) vcrypt.Signer { return nil }

func TestLookupRsaScheme(t *testing.T) {
	publicKey := &stdrsa.PublicKey{}
	privateKey := &stdrsa.PrivateKey{PublicKey: *publicKey}

	tests := []struct {
		name     string
		material key.KeyMaterial
	}{
		{name: "public key", material: key.PublicKeyMaterial{Key: publicKey}},
		{name: "private key", material: key.PrivateKeyMaterial{Key: privateKey}},
		{name: "certificate", material: key.CertificateMaterial{Cert: &x509.Certificate{PublicKey: publicKey}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scheme.Lookup(&key.Key{Material: tt.material})
			if _, ok := got.(*rsascheme.RsaScheme); !ok {
				t.Fatalf("Lookup() = %T, want *rsa.RsaScheme", got)
			}
		})
	}
}

func TestLookupMissingMaterial(t *testing.T) {
	if got := scheme.Lookup(nil); got != nil {
		t.Fatalf("Lookup(nil) = %T, want nil", got)
	}
	if got := scheme.Lookup(&key.Key{}); got != nil {
		t.Fatalf("Lookup(key without material) = %T, want nil", got)
	}
	if got := scheme.Lookup(&key.Key{Material: key.CertificateMaterial{}}); got != nil {
		t.Fatalf("Lookup(key with empty material) = %T, want nil", got)
	}
}

func TestLookupSymmetricMaterial(t *testing.T) {
	want := &symmetricScheme{}
	scheme.Register(reflect.TypeOf(symmetricMaterial(nil)), want)

	got := scheme.Lookup(&key.Key{Material: symmetricMaterial("secret")})
	if got != want {
		t.Fatalf("Lookup() = %T, want registered symmetric scheme", got)
	}
}
