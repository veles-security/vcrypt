package backend_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/veles-security/vcrypt/backend"
	_ "github.com/veles-security/vcrypt/backend/ec"
	_ "github.com/veles-security/vcrypt/backend/rsa"
	_ "github.com/veles-security/vcrypt/backend/symetric"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type reentrantMaterial struct{}

func (*reentrantMaterial) IsMaterial() bool                 { return true }
func (*reentrantMaterial) Public() *material.PublicMaterial { return nil }

type reentrantFactory struct{}

func (*reentrantFactory) Supports(value material.Material) bool {
	if _, ok := value.(*reentrantMaterial); !ok {
		return false
	}
	backend.Regsiter(unsupportedFactory{})
	return true
}

func (*reentrantFactory) New(material.Material) (key.Backend, error) {
	backend.Regsiter(unsupportedFactory{})
	return testBackend{}, nil
}

type unsupportedFactory struct{}

func (unsupportedFactory) Supports(material.Material) bool            { return false }
func (unsupportedFactory) New(material.Material) (key.Backend, error) { return nil, nil }

type testBackend struct{}

func (testBackend) Supports(key.KeyUse, key.KeyOperation, key.KeyAlg) bool { return false }
func (testBackend) Capabilities() []key.Capability                         { return nil }

func Test_BackendFor(t *testing.T) {
	backend.Regsiter(&reentrantFactory{})
	var privateMaterial *material.PrivateMaterial
	var publicMaterial *material.PublicMaterial
	var certificateMaterial *material.CertificateMaterial
	var symmetricMaterial *material.SymmetricMaterial
	assertBackend := func(t *testing.T, backend key.Backend, err error) {
		if err != nil || backend == nil {
			t.Errorf("BackendFor() = (%T, %v), want backend", backend, err)
		}
	}
	assertNilMaterial := func(t *testing.T, backend key.Backend, err error) {
		if backend != nil || err == nil || !strings.Contains(err.Error(), "nil material") {
			t.Errorf("BackendFor() = (%T, %v), want (nil, nil material error)", backend, err)
		}
	}
	assertUnsupported := func(t *testing.T, backend key.Backend, err error) {
		if backend != nil || err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("BackendFor() = (%T, %v), want (nil, unsupported error)", backend, err)
		}
	}
	tests := []struct {
		name      string
		material  material.Material
		assertion func(*testing.T, key.Backend, error)
	}{
		{name: "Symmetric Material", material: &material.SymmetricMaterial{Key: make([]byte, 32)}, assertion: assertBackend},
		{name: "Factory Reenters Registry", material: &reentrantMaterial{}, assertion: assertBackend},
		{name: "Nil Interface", assertion: assertNilMaterial},
		{name: "Typed Nil Private Material", material: privateMaterial, assertion: assertNilMaterial},
		{name: "Typed Nil Public Material", material: publicMaterial, assertion: assertNilMaterial},
		{name: "Typed Nil Certificate Material", material: certificateMaterial, assertion: assertNilMaterial},
		{name: "Typed Nil Symmetric Material", material: symmetricMaterial, assertion: assertNilMaterial},
		{name: "Typed Nil RSA Private Key", material: &material.PrivateMaterial{Key: (*rsa.PrivateKey)(nil)}, assertion: assertUnsupported},
		{name: "Typed Nil RSA Public Key", material: &material.PublicMaterial{Key: (*rsa.PublicKey)(nil)}, assertion: assertUnsupported},
		{name: "Typed Nil RSA Certificate Key", material: &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: (*rsa.PublicKey)(nil)}}, assertion: assertUnsupported},
		{name: "Typed Nil EC Private Key", material: &material.PrivateMaterial{Key: (*ecdsa.PrivateKey)(nil)}, assertion: assertUnsupported},
		{name: "Typed Nil EC Public Key", material: &material.PublicMaterial{Key: (*ecdsa.PublicKey)(nil)}, assertion: assertUnsupported},
		{name: "Typed Nil EC Certificate Key", material: &material.CertificateMaterial{Cert: &x509.Certificate{PublicKey: (*ecdsa.PublicKey)(nil)}}, assertion: assertUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := backend.BackendFor(tt.material)
			tt.assertion(t, got, gotErr)
		})
	}
}
