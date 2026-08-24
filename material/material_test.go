package material

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func Test_Clone(t *testing.T) {
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	assertSymmetricCopy := func(t *testing.T, original Material, cloned Material) {
		originalKey := original.(*SymmetricMaterial).Key
		clonedKey := cloned.(*SymmetricMaterial).Key
		originalKey[0] ^= 0xff
		if clonedKey[0] == originalKey[0] {
			t.Error("Clone() shared symmetric key bytes")
		}
	}
	assertRSAPrivateCopy := func(t *testing.T, original Material, cloned Material) {
		originalKey := original.(*PrivateMaterial).Key.(*rsa.PrivateKey)
		clonedKey := cloned.(*PrivateMaterial).Key.(*rsa.PrivateKey)
		originalKey.D.SetInt64(1)
		if clonedKey.D.Cmp(originalKey.D) == 0 {
			t.Error("Clone() shared RSA private parameters")
		}
	}
	assertECPublicCopy := func(t *testing.T, original Material, cloned Material) {
		originalKey := original.(*PublicMaterial).Key.(*ecdsa.PublicKey)
		clonedKey := cloned.(*PublicMaterial).Key.(*ecdsa.PublicKey)
		originalKey.X.SetInt64(1)
		if clonedKey.X.Cmp(originalKey.X) == 0 {
			t.Error("Clone() shared EC public coordinates")
		}
	}
	assertCertificateCopy := func(t *testing.T, original Material, cloned Material) {
		originalCertificate := original.(*CertificateMaterial).Cert
		clonedCertificate := cloned.(*CertificateMaterial).Cert
		if originalCertificate == clonedCertificate {
			t.Error("Clone() shared certificate pointer")
		}
		originalCertificate.PublicKey.(*rsa.PublicKey).N.SetInt64(1)
		if clonedCertificate.PublicKey.(*rsa.PublicKey).N.Cmp(originalCertificate.PublicKey.(*rsa.PublicKey).N) == 0 {
			t.Error("Clone() shared certificate public key")
		}
	}
	tests := []struct {
		name      string
		material  Material
		assertion func(*testing.T, Material, Material)
	}{
		{name: "Symmetric", material: &SymmetricMaterial{Key: []byte("secret")}, assertion: assertSymmetricCopy},
		{name: "RSA Private", material: &PrivateMaterial{Key: rsaPrivate}, assertion: assertRSAPrivateCopy},
		{name: "EC Public", material: &PublicMaterial{Key: &ecPrivate.PublicKey}, assertion: assertECPublicCopy},
		{name: "Certificate", material: &CertificateMaterial{Cert: &x509.Certificate{PublicKey: &rsaPrivate.PublicKey}}, assertion: assertCertificateCopy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.material, Clone(tt.material))
		})
	}
}
