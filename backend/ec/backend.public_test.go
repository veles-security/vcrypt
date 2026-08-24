package ec

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/material"
)

func Test_publicBackend_VerifySignature(t *testing.T) {
	privateKey := testkeys.Private(t, testkeys.ES256).(*ecdsa.PrivateKey)
	privateBackend := &privateBackend{material: material.PrivateMaterial{Key: privateKey}}
	publicBackend := &publicBackend{material: material.PublicMaterial{Key: &privateKey.PublicKey}}
	message := []byte("message")
	signature, err := privateBackend.Sign(context.Background(), ES256, message)
	if err != nil {
		t.Fatal(err)
	}
	assertValid := func(t *testing.T, err error) {
		if err != nil {
			t.Errorf("VerifySignature() error = %v", err)
		}
	}
	assertError := func(t *testing.T, err error) {
		if err == nil {
			t.Error("VerifySignature() error = nil, want error")
		}
	}
	tests := []struct {
		name      string
		signature []byte
		assertion func(*testing.T, error)
	}{
		{name: "JOSE Signature", signature: signature, assertion: assertValid},
		{name: "Wrong Length", signature: signature[:len(signature)-1], assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, publicBackend.VerifySignature(context.Background(), ES256, tt.signature, message))
		})
	}
}
