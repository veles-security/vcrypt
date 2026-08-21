package symetric

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_symmetricBackend_Encrypt(t *testing.T) {
	// algs
	var invalidAlg key.KeyAlg = "INVALID"
	// keys
	key128 := bytes.Repeat([]byte{0x01}, 16)
	key192 := bytes.Repeat([]byte{0x02}, 24)
	key256 := bytes.Repeat([]byte{0x03}, 32)
	// backends
	backend128 := symmetricBackend{material: material.SymmetricMaterial{Key: key128}}
	backend192 := symmetricBackend{material: material.SymmetricMaterial{Key: key192}}
	backend256 := symmetricBackend{material: material.SymmetricMaterial{Key: key256}}
	// plaintexts
	plaintext := []byte("message to encrypt")
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertEncrypted := func(key []byte) func(*testing.T, []byte, error) {
		return func(t *testing.T, ciphertext []byte, err error) {
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatalf("create AES cipher: %v", err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("create GCM: %v", err)
			}
			if len(ciphertext) != gcm.NonceSize()+len(plaintext)+gcm.Overhead() {
				t.Fatalf("Encrypt() ciphertext length = %d, want %d", len(ciphertext), gcm.NonceSize()+len(plaintext)+gcm.Overhead())
			}
			nonce, encrypted := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
			decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
			if err != nil {
				t.Fatalf("standard library decryption failed: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted plaintext = %q, want %q", decrypted, plaintext)
			}
		}
	}
	assertError := func(t *testing.T, ciphertext []byte, err error) {
		if err == nil {
			t.Errorf("want err, got nil")
		}
		if ciphertext != nil {
			t.Errorf("Encrypt() ciphertext = %x, want nil", ciphertext)
		}
	}
	tests := []struct {
		name      string
		ctx       context.Context
		backend   symmetricBackend
		algorithm key.KeyAlg
		assertion func(*testing.T, []byte, error)
	}{
		{name: "A128GCM", ctx: context.Background(), backend: backend128, algorithm: A128GCM, assertion: assertEncrypted(key128)},
		{name: "A192GCM", ctx: context.Background(), backend: backend192, algorithm: A192GCM, assertion: assertEncrypted(key192)},
		{name: "A256GCM", ctx: context.Background(), backend: backend256, algorithm: A256GCM, assertion: assertEncrypted(key256)},
		{name: "Invalid KeyAlg", ctx: context.Background(), backend: backend128, algorithm: invalidAlg, assertion: assertError},
		{name: "Wrong Key Size", ctx: context.Background(), backend: backend128, algorithm: A256GCM, assertion: assertError},
		{name: "Canceled Context", ctx: canceledContext, backend: backend128, algorithm: A128GCM, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.backend.Encrypt(tt.ctx, tt.algorithm, plaintext)
			tt.assertion(t, got, gotErr)
		})
	}
}

func Test_symmetricBackend_Decrypt(t *testing.T) {
	// algs
	var invalidAlg key.KeyAlg = "INVALID"
	// keys
	key128 := bytes.Repeat([]byte{0x01}, 16)
	key192 := bytes.Repeat([]byte{0x02}, 24)
	key256 := bytes.Repeat([]byte{0x03}, 32)
	wrongKey128 := bytes.Repeat([]byte{0x04}, 16)
	// backends
	backend128 := symmetricBackend{material: material.SymmetricMaterial{Key: key128}}
	backend192 := symmetricBackend{material: material.SymmetricMaterial{Key: key192}}
	backend256 := symmetricBackend{material: material.SymmetricMaterial{Key: key256}}
	wrongKeyBackend := symmetricBackend{material: material.SymmetricMaterial{Key: wrongKey128}}
	// plaintexts
	plaintext := []byte("message to decrypt")
	// ciphertexts
	encrypt := func(key []byte) []byte {
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("create AES cipher: %v", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("create GCM: %v", err)
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("create nonce: %v", err)
		}
		return gcm.Seal(nonce, nonce, plaintext, nil)
	}
	ciphertext128 := encrypt(key128)
	ciphertext192 := encrypt(key192)
	ciphertext256 := encrypt(key256)
	tamperedCiphertext := append([]byte(nil), ciphertext128...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0xff
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertDecrypted := func(t *testing.T, decrypted []byte, err error) {
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
		}
	}
	assertError := func(t *testing.T, decrypted []byte, err error) {
		if err == nil {
			t.Errorf("want err, got nil")
		}
		if decrypted != nil {
			t.Errorf("Decrypt() plaintext = %x, want nil", decrypted)
		}
	}
	tests := []struct {
		name       string
		ctx        context.Context
		backend    symmetricBackend
		algorithm  key.KeyAlg
		ciphertext []byte
		assertion  func(*testing.T, []byte, error)
	}{
		{name: "A128GCM", ctx: context.Background(), backend: backend128, algorithm: A128GCM, ciphertext: ciphertext128, assertion: assertDecrypted},
		{name: "A192GCM", ctx: context.Background(), backend: backend192, algorithm: A192GCM, ciphertext: ciphertext192, assertion: assertDecrypted},
		{name: "A256GCM", ctx: context.Background(), backend: backend256, algorithm: A256GCM, ciphertext: ciphertext256, assertion: assertDecrypted},
		{name: "Invalid KeyAlg", ctx: context.Background(), backend: backend128, algorithm: invalidAlg, ciphertext: ciphertext128, assertion: assertError},
		{name: "Wrong Key Size", ctx: context.Background(), backend: backend128, algorithm: A256GCM, ciphertext: ciphertext128, assertion: assertError},
		{name: "Short Ciphertext", ctx: context.Background(), backend: backend128, algorithm: A128GCM, ciphertext: []byte("short"), assertion: assertError},
		{name: "Tampered Ciphertext", ctx: context.Background(), backend: backend128, algorithm: A128GCM, ciphertext: tamperedCiphertext, assertion: assertError},
		{name: "Wrong Key", ctx: context.Background(), backend: wrongKeyBackend, algorithm: A128GCM, ciphertext: ciphertext128, assertion: assertError},
		{name: "Canceled Context", ctx: canceledContext, backend: backend128, algorithm: A128GCM, ciphertext: ciphertext128, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.backend.Decrypt(tt.ctx, tt.algorithm, tt.ciphertext)
			tt.assertion(t, got, gotErr)
		})
	}
}

func Test_symmetricBackend_Supports(t *testing.T) {
	// algs
	var invalidAlg key.KeyAlg = "INVALID"
	// backends
	backend := symmetricBackend{}

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
		use       key.KeyUse
		operation key.KeyOperation
		algorithm key.KeyAlg
		assertion func(*testing.T, bool)
	}{
		{name: "Sign HS256", use: key.KeyUseSigning, operation: key.KeyOpSign, algorithm: HS256, assertion: assertSupported},
		{name: "Sign HS384", use: key.KeyUseSigning, operation: key.KeyOpSign, algorithm: HS384, assertion: assertSupported},
		{name: "Sign HS512", use: key.KeyUseSigning, operation: key.KeyOpSign, algorithm: HS512, assertion: assertSupported},
		{name: "Verify HS256", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: HS256, assertion: assertSupported},
		{name: "Verify HS384", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: HS384, assertion: assertSupported},
		{name: "Verify HS512", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: HS512, assertion: assertSupported},
		{name: "Encrypt A128GCM", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: A128GCM, assertion: assertSupported},
		{name: "Encrypt A192GCM", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: A192GCM, assertion: assertSupported},
		{name: "Encrypt A256GCM", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: A256GCM, assertion: assertSupported},
		{name: "Decrypt A128GCM", use: key.KeyUseEncryption, operation: key.KeyOpDecrypt, algorithm: A128GCM, assertion: assertSupported},
		{name: "Decrypt A192GCM", use: key.KeyUseEncryption, operation: key.KeyOpDecrypt, algorithm: A192GCM, assertion: assertSupported},
		{name: "Decrypt A256GCM", use: key.KeyUseEncryption, operation: key.KeyOpDecrypt, algorithm: A256GCM, assertion: assertSupported},
		{name: "Invalid Algorithm", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: invalidAlg, assertion: assertUnsupported},
		{name: "Signing Use With AES", use: key.KeyUseSigning, operation: key.KeyOpEncrypt, algorithm: A128GCM, assertion: assertUnsupported},
		{name: "Encryption Use With HMAC", use: key.KeyUseEncryption, operation: key.KeyOpSign, algorithm: HS256, assertion: assertUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backend.Supports(tt.use, tt.operation, tt.algorithm)
			tt.assertion(t, got)
		})
	}
}
