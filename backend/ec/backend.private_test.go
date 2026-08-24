package ec

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_privateBackend_Sign(t *testing.T) {
	privateKey := testkeys.Private(t, testkeys.ES256).(*ecdsa.PrivateKey)
	backend := &privateBackend{material: material.PrivateMaterial{Key: privateKey}}
	message := []byte("message")

	assertSignature := func(t *testing.T, signature []byte, err error) {
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if len(signature) != 64 {
			t.Fatalf("Sign() signature length = %d, want 64", len(signature))
		}
		digest := crypto.SHA256.New()
		_, _ = digest.Write(message)
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(&privateKey.PublicKey, digest.Sum(nil), r, s) {
			t.Error("Sign() produced an invalid JOSE signature")
		}
	}
	assertError := func(t *testing.T, signature []byte, err error) {
		if err == nil || signature != nil {
			t.Errorf("Sign() = (%x, %v), want (nil, error)", signature, err)
		}
	}
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name      string
		ctx       context.Context
		backend   *privateBackend
		algorithm key.KeyAlg
		assertion func(*testing.T, []byte, error)
	}{
		{name: "ES256", ctx: context.Background(), backend: backend, algorithm: ES256, assertion: assertSignature},
		{name: "Canceled Context", ctx: canceledContext, backend: backend, algorithm: ES256, assertion: func(t *testing.T, signature []byte, err error) {
			if !errors.Is(err, context.Canceled) || signature != nil {
				t.Errorf("Sign() = (%x, %v), want (nil, context.Canceled)", signature, err)
			}
		}},
		{name: "Unsupported Algorithm", ctx: context.Background(), backend: backend, algorithm: "invalid", assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.backend.Sign(tt.ctx, tt.algorithm, message)
			tt.assertion(t, got, gotErr)
		})
	}
}

func Test_privateBackend_VerifySignature(t *testing.T) {
	privateKey := testkeys.Private(t, testkeys.ES256).(*ecdsa.PrivateKey)
	backend := &privateBackend{material: material.PrivateMaterial{Key: privateKey}}
	message := []byte("message")
	signature, err := backend.Sign(context.Background(), ES256, message)
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
		{name: "ASN.1 Signature", signature: []byte{0x30, 0x00}, assertion: assertError},
		{name: "Wrong Length", signature: signature[:len(signature)-1], assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, backend.VerifySignature(context.Background(), ES256, tt.signature, message))
		})
	}
}
