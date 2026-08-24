package ec

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_factory_New(t *testing.T) {
	// keys
	privateKey := testkeys.Private(t, testkeys.ES256).(*ecdsa.PrivateKey)
	publicKey := &privateKey.PublicKey
	mismatchedPublicKey := testkeys.Public(t, testkeys.RSA2048)
	// materials
	publicMaterial := &material.PublicMaterial{Key: publicKey}
	privateMaterial := &material.PrivateMaterial{Key: privateKey}
	certificateMaterial := &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: publicKey}}
	mismatchedCertificateMaterial := &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: mismatchedPublicKey}}
	nilCertificateMaterial := &material.CertificateMaterial{}
	// factories
	factory := factory{}

	// assertions
	assertPublicBackend := func(t *testing.T, backend key.Backend, err error) {
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, ok := backend.(*publicBackend); !ok {
			t.Errorf("New() backend = %T, want *publicBackend", backend)
		}
	}
	assertPrivateBackend := func(t *testing.T, backend key.Backend, err error) {
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, ok := backend.(*privateBackend); !ok {
			t.Errorf("New() backend = %T, want *privateBackend", backend)
		}
	}
	assertCertificateBackend := func(t *testing.T, backend key.Backend, err error) {
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		certificateBackend, ok := backend.(*certificateBackend)
		if !ok {
			t.Fatalf("New() backend = %T, want *certificateBackend", backend)
		}
		if certificateBackend.material.Cert == certificateMaterial.Cert {
			t.Errorf("New() retained the caller's mutable certificate pointer")
		}
		if !certificateBackend.material.Cert.PublicKey.(*ecdsa.PublicKey).Equal(publicKey) {
			t.Errorf("New() copied a different certificate public key")
		}
		if _, ok := backend.(key.SignatureVerifier); !ok {
			t.Errorf("certificate backend does not implement key.SignatureVerifier")
		}
		if _, ok := backend.(key.Signer); ok {
			t.Errorf("certificate backend unexpectedly implements key.Signer")
		}
		if _, ok := backend.(key.Encrypter); ok {
			t.Errorf("certificate backend unexpectedly implements key.Encrypter")
		}
		if _, ok := backend.(key.Decrypter); ok {
			t.Errorf("certificate backend unexpectedly implements key.Decrypter")
		}
	}
	assertError := func(t *testing.T, backend key.Backend, err error) {
		if err == nil {
			t.Errorf("want err, got nil")
		}
		if backend != nil {
			t.Errorf("New() backend = %T, want nil", backend)
		}
	}
	tests := []struct {
		name      string
		material  material.Material
		assertion func(*testing.T, key.Backend, error)
	}{
		{name: "Public Material", material: publicMaterial, assertion: assertPublicBackend},
		{name: "Private Material", material: privateMaterial, assertion: assertPrivateBackend},
		{name: "Certificate Material", material: certificateMaterial, assertion: assertCertificateBackend},
		{name: "Mismatched Certificate", material: mismatchedCertificateMaterial, assertion: assertError},
		{name: "Nil Certificate", material: nilCertificateMaterial, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := factory.New(tt.material)
			tt.assertion(t, got, gotErr)
		})
	}
}

func Test_factory_Supports(t *testing.T) {
	// keys
	privateKey := testkeys.Private(t, testkeys.ES256).(*ecdsa.PrivateKey)
	mismatchedPublicKey := testkeys.Public(t, testkeys.RSA2048)
	// factories
	factory := factory{}

	// assertions
	assertSupported := func(t *testing.T, supported bool) {
		if !supported {
			t.Errorf("Supports() = false, want true")
		}
	}
	assertUnsupported := func(t *testing.T, supported bool) {
		if supported {
			t.Errorf("Supports() = true, want false")
		}
	}
	tests := []struct {
		name      string
		material  material.Material
		assertion func(*testing.T, bool)
	}{
		{name: "Public Material", material: &material.PublicMaterial{Key: &privateKey.PublicKey}, assertion: assertSupported},
		{name: "Private Material", material: &material.PrivateMaterial{Key: privateKey}, assertion: assertSupported},
		{name: "Certificate Material", material: &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: &privateKey.PublicKey}}, assertion: assertSupported},
		{name: "Mismatched Certificate", material: &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: mismatchedPublicKey}}, assertion: assertUnsupported},
		{name: "Nil Certificate", material: &material.CertificateMaterial{}, assertion: assertUnsupported},
		{name: "Nil Material", material: nil, assertion: assertUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := factory.Supports(tt.material)
			tt.assertion(t, got)
		})
	}
}
