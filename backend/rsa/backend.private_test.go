package rsa

import (
	"context"
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"testing"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_privateBackend_Sign(t *testing.T) {
	privateKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var invalidPrivateKey crypto.PrivateKey = &struct{}{}
	var invalidAlg key.KeyAlg = "INVALID"

	backend := privateBackend{material: material.PrivateMaterial{Key: privateKey}}

	invalidKeyBackend := privateBackend{material: material.PrivateMaterial{Key: invalidPrivateKey}}

	message := []byte("message to sign")
	assertValidSignature := func(hash crypto.Hash, pss bool) func(*testing.T, []byte, error) {
		return func(t *testing.T, signature []byte, err error) {
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			digest := hash.New()
			_, _ = digest.Write(message)
			if pss {
				err = stdrsa.VerifyPSS(&privateKey.PublicKey, hash, digest.Sum(nil), signature, &stdrsa.PSSOptions{SaltLength: stdrsa.PSSSaltLengthEqualsHash})
			} else {
				err = stdrsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest.Sum(nil), signature)
			}
			if err != nil {
				t.Errorf("standard library verification failed: %v", err)
			}
		}
	}
	assertError := func(t *testing.T, signature []byte, err error) {
		if err == nil {
			t.Errorf("want err, got nil")
		}
	}
	tests := []struct {
		name      string // description of this test case
		backend   privateBackend
		algorithm key.KeyAlg
		message   []byte
		assertion func(*testing.T, []byte, error)
	}{
		{name: "RS256", backend: backend, algorithm: RS256, message: message, assertion: assertValidSignature(crypto.SHA256, false)},
		{name: "RS384", backend: backend, algorithm: RS384, message: message, assertion: assertValidSignature(crypto.SHA384, false)},
		{name: "RS512", backend: backend, algorithm: RS512, message: message, assertion: assertValidSignature(crypto.SHA512, false)},
		{name: "PS256", backend: backend, algorithm: PS256, message: message, assertion: assertValidSignature(crypto.SHA256, true)},
		{name: "PS384", backend: backend, algorithm: PS384, message: message, assertion: assertValidSignature(crypto.SHA384, true)},
		{name: "PS512", backend: backend, algorithm: PS512, message: message, assertion: assertValidSignature(crypto.SHA512, true)},
		{name: "Invalid KeyAlg", backend: backend, algorithm: invalidAlg, message: message, assertion: assertError},
		{name: "Invalid Key", backend: invalidKeyBackend, algorithm: RS256, message: message, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.backend.Sign(context.Background(), tt.algorithm, tt.message)
			tt.assertion(t, got, gotErr)
		})
	}
}
