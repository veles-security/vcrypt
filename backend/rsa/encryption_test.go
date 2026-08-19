package rsa

import (
	"bytes"
	"context"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"testing"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func TestEncryptionRoundTrip(t *testing.T) {
	privateKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicBackend := &publicBackend{material: material.PublicMaterial{Key: &privateKey.PublicKey}}
	privateBackend := &privateBackend{material: material.PrivateMaterial{Key: privateKey}}
	plaintext := []byte("secret")

	for _, algorithm := range []key.KeyAlg{RSA1_5, RSAOAEP, RSAOAEP256, RSAOAEP384, RSAOAEP512} {
		t.Run(string(algorithm), func(t *testing.T) {
			ciphertext, err := publicBackend.Encrypt(context.Background(), algorithm, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := privateBackend.Decrypt(context.Background(), algorithm, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("got plaintext %q, want %q", decrypted, plaintext)
			}
		})
	}
}
