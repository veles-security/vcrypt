package rsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_publicBackend_VerifySignature(t *testing.T) {
	// algs
	var invalidAlg key.KeyAlg = "INVALID"
	// keys
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*stdrsa.PrivateKey)
	publicKey := &privateKey.PublicKey
	mismatchedPublicKey := testkeys.Public(t, testkeys.ES256)
	brokenPublicKey := testkeys.MalformedPublic(t, testkeys.RSA2048, testkeys.IncompleteKey)
	// backends
	backend := publicBackend{material: material.PublicMaterial{Key: publicKey}}
	mismatchedKeyBackend := publicBackend{material: material.PublicMaterial{Key: mismatchedPublicKey}}
	brokenKeyBackend := publicBackend{material: material.PublicMaterial{Key: brokenPublicKey}}
	// messages
	message := []byte("message to verify")
	modifiedMessage := []byte("modified message")
	// signatures
	sign := func(hash crypto.Hash, pss bool) []byte {
		digest := hash.New()
		_, _ = digest.Write(message)
		var signature []byte
		var err error
		if pss {
			signature, err = stdrsa.SignPSS(rand.Reader, privateKey, hash, digest.Sum(nil), &stdrsa.PSSOptions{SaltLength: stdrsa.PSSSaltLengthEqualsHash})
		} else {
			signature, err = stdrsa.SignPKCS1v15(rand.Reader, privateKey, hash, digest.Sum(nil))
		}
		if err != nil {
			t.Fatalf("create test signature: %v", err)
		}
		return signature
	}
	rs256Signature := sign(crypto.SHA256, false)
	rs384Signature := sign(crypto.SHA384, false)
	rs512Signature := sign(crypto.SHA512, false)
	ps256Signature := sign(crypto.SHA256, true)
	ps384Signature := sign(crypto.SHA384, true)
	ps512Signature := sign(crypto.SHA512, true)

	// assertions
	assertValid := func(t *testing.T, err error) {
		if err != nil {
			t.Errorf("VerifySignature() error = %v", err)
		}
	}
	assertError := func(t *testing.T, err error) {
		if err == nil {
			t.Errorf("want err, got nil")
		}
	}
	tests := []struct {
		name      string
		backend   publicBackend
		algorithm key.KeyAlg
		signature []byte
		message   []byte
		assertion func(*testing.T, error)
	}{
		{name: "RS256", backend: backend, algorithm: RS256, signature: rs256Signature, message: message, assertion: assertValid},
		{name: "RS384", backend: backend, algorithm: RS384, signature: rs384Signature, message: message, assertion: assertValid},
		{name: "RS512", backend: backend, algorithm: RS512, signature: rs512Signature, message: message, assertion: assertValid},
		{name: "PS256", backend: backend, algorithm: PS256, signature: ps256Signature, message: message, assertion: assertValid},
		{name: "PS384", backend: backend, algorithm: PS384, signature: ps384Signature, message: message, assertion: assertValid},
		{name: "PS512", backend: backend, algorithm: PS512, signature: ps512Signature, message: message, assertion: assertValid},
		{name: "Invalid KeyAlg", backend: backend, algorithm: invalidAlg, signature: rs256Signature, message: message, assertion: assertError},
		{name: "Invalid Signature", backend: backend, algorithm: RS256, signature: []byte("invalid"), message: message, assertion: assertError},
		{name: "Modified Message", backend: backend, algorithm: RS256, signature: rs256Signature, message: modifiedMessage, assertion: assertError},
		{name: "Mismatched Key", backend: mismatchedKeyBackend, algorithm: RS256, signature: rs256Signature, message: message, assertion: assertError},
		{name: "Broken Key", backend: brokenKeyBackend, algorithm: RS256, signature: rs256Signature, message: message, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.backend.Verify(context.Background(), tt.algorithm, tt.signature, tt.message)
			tt.assertion(t, err)
		})
	}

}

func Test_publicBackend_Encrypt(t *testing.T) {
	// algs
	var invalidAlg key.KeyAlg = "INVALID"
	// keys
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*stdrsa.PrivateKey)
	publicKey := &privateKey.PublicKey
	mismatchedPublicKey := testkeys.Public(t, testkeys.ES256)
	brokenPublicKey := testkeys.MalformedPublic(t, testkeys.RSA2048, testkeys.IncompleteKey)
	// backends
	backend := publicBackend{material: material.PublicMaterial{Key: publicKey}}
	mismatchedKeyBackend := publicBackend{material: material.PublicMaterial{Key: mismatchedPublicKey}}
	brokenKeyBackend := publicBackend{material: material.PublicMaterial{Key: brokenPublicKey}}
	// plaintexts
	plaintext := []byte("message to encrypt")
	oversizedPlaintext := make([]byte, publicKey.Size())

	// assertions
	assertEncrypted := func(algorithm key.KeyAlg) func(*testing.T, []byte, error) {
		return func(t *testing.T, ciphertext []byte, err error) {
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}
			var decrypted []byte
			switch algorithm {
			case RSA1_5:
				decrypted, err = stdrsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
			case RSAOAEP:
				decrypted, err = stdrsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, ciphertext, nil)
			case RSAOAEP256:
				decrypted, err = stdrsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
			case RSAOAEP384:
				decrypted, err = stdrsa.DecryptOAEP(sha512.New384(), rand.Reader, privateKey, ciphertext, nil)
			case RSAOAEP512:
				decrypted, err = stdrsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, ciphertext, nil)
			}
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
	}
	assertRSAOAEP := assertError
	assertRSA1_5 := assertError
	if unsafeCryptoEnabled {
		assertRSAOAEP = assertEncrypted(RSAOAEP)
		assertRSA1_5 = assertEncrypted(RSA1_5)
	}
	tests := []struct {
		name      string
		backend   publicBackend
		algorithm key.KeyAlg
		plaintext []byte
		assertion func(*testing.T, []byte, error)
	}{
		{name: "RSA1_5", backend: backend, algorithm: RSA1_5, plaintext: plaintext, assertion: assertRSA1_5},
		{name: "RSA-OAEP", backend: backend, algorithm: RSAOAEP, plaintext: plaintext, assertion: assertRSAOAEP},
		{name: "RSA-OAEP-256", backend: backend, algorithm: RSAOAEP256, plaintext: plaintext, assertion: assertEncrypted(RSAOAEP256)},
		{name: "RSA-OAEP-384", backend: backend, algorithm: RSAOAEP384, plaintext: plaintext, assertion: assertEncrypted(RSAOAEP384)},
		{name: "RSA-OAEP-512", backend: backend, algorithm: RSAOAEP512, plaintext: plaintext, assertion: assertEncrypted(RSAOAEP512)},
		{name: "Invalid KeyAlg", backend: backend, algorithm: invalidAlg, plaintext: plaintext, assertion: assertError},
		{name: "Oversized Plaintext", backend: backend, algorithm: RSA1_5, plaintext: oversizedPlaintext, assertion: assertError},
		{name: "Mismatched Key", backend: mismatchedKeyBackend, algorithm: RSA1_5, plaintext: plaintext, assertion: assertError},
		{name: "Broken Key", backend: brokenKeyBackend, algorithm: RSA1_5, plaintext: plaintext, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.backend.Encrypt(context.Background(), tt.algorithm, tt.plaintext)
			tt.assertion(t, got, gotErr)
		})
	}

}

func Test_publicBackend_Supports(t *testing.T) {
	// algs
	var invalidAlg key.KeyAlg = "INVALID"
	// uses
	var invalidUse key.KeyUse = "invalid"
	// operations
	var invalidOperation key.KeyOperation = "invalid"
	// backends
	backend := publicBackend{}

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
	assertRSAOAEPSupport := assertUnsupported
	assertRSA1_5Support := assertUnsupported
	if unsafeCryptoEnabled {
		assertRSAOAEPSupport = assertSupported
		assertRSA1_5Support = assertSupported
	}
	tests := []struct {
		name      string
		use       key.KeyUse
		operation key.KeyOperation
		algorithm key.KeyAlg
		assertion func(*testing.T, bool)
	}{
		{name: "Verify RS256", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: RS256, assertion: assertSupported},
		{name: "Verify RS384", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: RS384, assertion: assertSupported},
		{name: "Verify RS512", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: RS512, assertion: assertSupported},
		{name: "Verify PS256", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: PS256, assertion: assertSupported},
		{name: "Verify PS384", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: PS384, assertion: assertSupported},
		{name: "Verify PS512", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: PS512, assertion: assertSupported},
		{name: "Encrypt RSA1_5", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: RSA1_5, assertion: assertRSA1_5Support},
		{name: "Encrypt RSA-OAEP", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: RSAOAEP, assertion: assertRSAOAEPSupport},
		{name: "Encrypt RSA-OAEP-256", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: RSAOAEP256, assertion: assertSupported},
		{name: "Encrypt RSA-OAEP-384", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: RSAOAEP384, assertion: assertSupported},
		{name: "Encrypt RSA-OAEP-512", use: key.KeyUseEncryption, operation: key.KeyOpEncrypt, algorithm: RSAOAEP512, assertion: assertSupported},
		{name: "Sign RS256", use: key.KeyUseSigning, operation: key.KeyOpSign, algorithm: RS256, assertion: assertUnsupported},
		{name: "Decrypt RSA1_5", use: key.KeyUseEncryption, operation: key.KeyOpDecrypt, algorithm: RSA1_5, assertion: assertUnsupported},
		{name: "Invalid Use", use: invalidUse, operation: key.KeyOpVerify, algorithm: RS256, assertion: assertUnsupported},
		{name: "Invalid Operation", use: key.KeyUseSigning, operation: invalidOperation, algorithm: RS256, assertion: assertUnsupported},
		{name: "Invalid Algorithm", use: key.KeyUseSigning, operation: key.KeyOpVerify, algorithm: invalidAlg, assertion: assertUnsupported},
		{name: "Signing Use With Encrypt Operation", use: key.KeyUseSigning, operation: key.KeyOpEncrypt, algorithm: RSA1_5, assertion: assertUnsupported},
		{name: "Encryption Use With Verify Operation", use: key.KeyUseEncryption, operation: key.KeyOpVerify, algorithm: RS256, assertion: assertUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backend.Supports(tt.use, tt.operation, tt.algorithm)
			tt.assertion(t, got)
		})
	}
}
