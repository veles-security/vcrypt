package keystore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/veles-security/vcrypt/backend/symetric"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type encryptionSource struct {
	keys []key.KeyCandidate
}

func (s *encryptionSource) ID() string { return "encryption-test" }

func (s *encryptionSource) Load(context.Context) ([]key.KeyCandidate, error) {
	return s.keys, nil
}

func (s *encryptionSource) Close() error { return nil }

func encryptionKey(id string, status key.KeyStatus, secret []byte) key.KeyCandidate {
	return key.KeyCandidate{
		ID:       id,
		Source:   "encryption-test",
		Status:   status,
		Material: &material.SymmetricMaterial{Key: secret},
	}
}

func encryptionStore(t *testing.T, keys ...key.KeyCandidate) Keystore {
	t.Helper()
	store, err := New(WithSource(&encryptionSource{keys: keys}, nil))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func aesGCM(t *testing.T, secret []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

func Test_store_Signer(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	message := []byte("message to sign")
	activeStore := encryptionStore(t, encryptionKey("active", key.KeyStatusActive, secret))
	passiveStore := encryptionStore(t, encryptionKey("passive", key.KeyStatusPassive, secret))
	shortKeyStore := encryptionStore(t, encryptionKey("short", key.KeyStatusActive, []byte("short")))
	assertSigned := func(t *testing.T, descriptor key.KeyDescriptor, sign SignFunc, err error) {
		if err != nil {
			t.Fatalf("Signer() error = %v", err)
		}
		if descriptor.ID != "active" || descriptor.Algorithm != symetric.HS256 || descriptor.Material != nil {
			t.Errorf("Signer() key descriptor = %#v, want active HS256 key without secret material", descriptor)
		}
		signature, signErr := sign(message)
		if signErr != nil {
			t.Fatalf("sign() error = %v", signErr)
		}
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(message)
		if !hmac.Equal(signature, mac.Sum(nil)) {
			t.Errorf("sign() signature = %x, want independently computed HMAC", signature)
		}
		secondSignature, secondErr := sign(message)
		if secondErr == nil || !strings.Contains(secondErr.Error(), "already been used") || secondSignature != nil {
			t.Errorf("second sign() = (%x, %v), want nil signature and already-used error", secondSignature, secondErr)
		}
	}
	assertSignerErrorContaining := func(want string) func(*testing.T, key.KeyDescriptor, SignFunc, error) {
		return func(t *testing.T, descriptor key.KeyDescriptor, sign SignFunc, err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Signer() error = %v, want error containing %q", err, want)
			}
			if descriptor.ID != "" || sign != nil {
				t.Errorf("Signer() = (%#v, %v), want zero descriptor and nil function", descriptor, sign)
			}
		}
	}
	assertSigningError := func(t *testing.T, descriptor key.KeyDescriptor, sign SignFunc, err error) {
		if err != nil {
			t.Fatalf("Signer() error = %v", err)
		}
		if descriptor.ID != "short" || sign == nil {
			t.Fatalf("Signer() = (%#v, %v), want short key and signing function", descriptor, sign)
		}
		signature, signErr := sign(message)
		if signErr == nil || !strings.Contains(signErr.Error(), "key is too short") || signature != nil {
			t.Errorf("sign() = (%x, %v), want nil signature and short-key error", signature, signErr)
		}
		_, secondErr := sign(message)
		if secondErr == nil || !strings.Contains(secondErr.Error(), "already been used") {
			t.Errorf("second sign() error = %v, want already-used error", secondErr)
		}
	}
	tests := []struct {
		name       string
		store      Keystore
		algorithms []key.KeyAlg
		assertion  func(*testing.T, key.KeyDescriptor, SignFunc, error)
	}{
		{name: "HMAC And One Shot", store: activeStore, algorithms: []key.KeyAlg{symetric.HS256}, assertion: assertSigned},
		{name: "Empty Algorithms", store: activeStore, assertion: assertSignerErrorContaining("algorithms are empty")},
		{name: "Unsupported Algorithm", store: activeStore, algorithms: []key.KeyAlg{"unsupported"}, assertion: assertSignerErrorContaining("no eligible key")},
		{name: "Passive Key", store: passiveStore, algorithms: []key.KeyAlg{symetric.HS256}, assertion: assertSignerErrorContaining("no eligible key")},
		{name: "Signing Failure Consumes Signer", store: shortKeyStore, algorithms: []key.KeyAlg{symetric.HS256}, assertion: assertSigningError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDescriptor, gotSign, gotErr := tt.store.Signer(context.Background(), SignOption(WithAlgorithms(tt.algorithms...)))
			tt.assertion(t, gotDescriptor, gotSign, gotErr)
		})
	}
}

func Test_store_Encrypt(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("confidential message")
	activeStore := encryptionStore(t, encryptionKey("active", key.KeyStatusActive, secret))
	unsetStatusStore := encryptionStore(t, encryptionKey("active", "", secret))
	passiveStore := encryptionStore(t, encryptionKey("passive", key.KeyStatusPassive, secret))
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	assertEncrypted := func(t *testing.T, result EncryptResult, err error) {
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}
		gcm := aesGCM(t, secret)
		if len(result.Ciphertext) < gcm.NonceSize()+gcm.Overhead() {
			t.Fatalf("Encrypt() ciphertext length = %d, want at least %d", len(result.Ciphertext), gcm.NonceSize()+gcm.Overhead())
		}
		nonce := result.Ciphertext[:gcm.NonceSize()]
		decrypted, decryptErr := gcm.Open(nil, nonce, result.Ciphertext[gcm.NonceSize():], nil)
		if decryptErr != nil || !bytes.Equal(decrypted, plaintext) {
			t.Errorf("independent decryption = (%q, %v), want %q", decrypted, decryptErr, plaintext)
		}
		if result.Key.ID != "active" || result.Key.Algorithm != symetric.A256GCM || result.Key.Material != nil {
			t.Errorf("Encrypt() key descriptor = %#v, want active A256GCM key without secret material", result.Key)
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, EncryptResult, error) {
		return func(t *testing.T, result EncryptResult, err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Encrypt() error = %v, want error containing %q", err, want)
			}
			if result.Ciphertext != nil || result.Key.ID != "" {
				t.Errorf("Encrypt() result = %#v, want zero result", result)
			}
		}
	}
	tests := []struct {
		name       string
		store      Keystore
		ctx        context.Context
		algorithms []key.KeyAlg
		assertion  func(*testing.T, EncryptResult, error)
	}{
		{name: "AES-GCM", store: activeStore, ctx: context.Background(), algorithms: []key.KeyAlg{symetric.A256GCM}, assertion: assertEncrypted},
		{name: "Unset Status", store: unsetStatusStore, ctx: context.Background(), algorithms: []key.KeyAlg{symetric.A256GCM}, assertion: assertEncrypted},
		{name: "Empty Algorithms", store: activeStore, ctx: context.Background(), assertion: assertErrorContaining("algorithms are empty")},
		{name: "Unsupported Algorithm", store: activeStore, ctx: context.Background(), algorithms: []key.KeyAlg{"unsupported"}, assertion: assertErrorContaining("no eligible key")},
		{name: "Passive Key", store: passiveStore, ctx: context.Background(), algorithms: []key.KeyAlg{symetric.A256GCM}, assertion: assertErrorContaining("no eligible key")},
		{name: "Canceled Context", store: activeStore, ctx: canceledContext, algorithms: []key.KeyAlg{symetric.A256GCM}, assertion: assertErrorContaining("context canceled")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.store.Encrypt(tt.ctx, plaintext, WithAlgorithms(tt.algorithms...))
			tt.assertion(t, got, gotErr)
		})
	}
}

func Test_store_Decrypt(t *testing.T) {
	secret := bytes.Repeat([]byte{0x24}, 32)
	plaintext := []byte("confidential message")
	gcm := aesGCM(t, secret)
	nonce := bytes.Repeat([]byte{0x01}, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	store := encryptionStore(t,
		encryptionKey("active", key.KeyStatusActive, secret),
		encryptionKey("passive", key.KeyStatusPassive, secret),
		encryptionKey("disabled", key.KeyStatusDisabled, secret),
	)
	assertPlaintext := func(t *testing.T, got []byte, err error) {
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("Decrypt() plaintext = %q, want %q", got, plaintext)
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, []byte, error) {
		return func(t *testing.T, got []byte, err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Decrypt() error = %v, want error containing %q", err, want)
			}
			if got != nil {
				t.Errorf("Decrypt() plaintext = %x, want nil", got)
			}
		}
	}
	tests := []struct {
		name       string
		keyID      string
		algorithms []key.KeyAlg
		ciphertext []byte
		assertion  func(*testing.T, []byte, error)
	}{
		{name: "Active Key", keyID: "active", algorithms: []key.KeyAlg{symetric.A256GCM}, ciphertext: ciphertext, assertion: assertPlaintext},
		{name: "Passive Key", keyID: "passive", algorithms: []key.KeyAlg{symetric.A256GCM}, ciphertext: ciphertext, assertion: assertPlaintext},
		{name: "Empty Algorithms", keyID: "active", ciphertext: ciphertext, assertion: assertErrorContaining("algorithms are empty")},
		{name: "Disabled Key", keyID: "disabled", algorithms: []key.KeyAlg{symetric.A256GCM}, ciphertext: ciphertext, assertion: assertErrorContaining("no eligible key")},
		{name: "Malformed Ciphertext", keyID: "active", algorithms: []key.KeyAlg{symetric.A256GCM}, ciphertext: []byte("short"), assertion: assertErrorContaining("ciphertext is too short")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := store.Decrypt(
				context.Background(),
				tt.ciphertext,
				WithKeys(key.Select(key.WithID(tt.keyID))),
				WithAlgorithms(tt.algorithms...),
			)
			tt.assertion(t, got, gotErr)
		})
	}
}
