package symetric

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	stdhmac "crypto/hmac"
	"crypto/rand"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type symmetricBackend struct {
	material material.SymmetricMaterial
}

func (b *symmetricBackend) signatureOptions(algorithm key.KeyAlg) (crypto.Hash, error) {
	var hash crypto.Hash
	switch alg := algorithm; alg {
	case HS256:
		hash = crypto.SHA256
	case HS384:
		hash = crypto.SHA384
	case HS512:
		hash = crypto.SHA512
	default:
		return 0, fmt.Errorf("symetric backend: unsupported signature algorithm %q", alg)
	}
	if !hash.Available() {
		return 0, fmt.Errorf("symetric backend: hash %v is unavailable", hash)
	}
	if len(b.material.Key) < hash.Size() {
		return 0, fmt.Errorf("symetric backend: key is too short: got %d bytes, require at least %d", len(b.material.Key), hash.Size())
	}
	return hash, nil
}

func (b *symmetricBackend) encryptionOptions(algorithm key.KeyAlg) (cipher.AEAD, error) {
	var keySize int
	switch algorithm {
	case A128GCM:
		keySize = 16
	case A192GCM:
		keySize = 24
	case A256GCM:
		keySize = 32
	default:
		return nil, fmt.Errorf("symetric backend: unsupported encryption algorithm %q", algorithm)
	}
	if len(b.material.Key) != keySize {
		return nil, fmt.Errorf("symetric backend: invalid key size for %s: got %d bytes, require %d", algorithm, len(b.material.Key), keySize)
	}
	block, err := aes.NewCipher(b.material.Key)
	if err != nil {
		return nil, fmt.Errorf("symetric backend: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("symetric backend: create GCM: %w", err)
	}
	return gcm, nil
}

// Capabilities implements [key.Backend].
func (b *symmetricBackend) Capabilities() []key.Capability {
	return capabilities
}

// Sign implements [key.Signer].
func (b *symmetricBackend) Sign(ctx context.Context, algorithm key.KeyAlg, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hash, err := b.signatureOptions(algorithm)
	if err != nil {
		return nil, err
	}
	mac := stdhmac.New(hash.New, b.material.Key)
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}

// Supports implements [key.Backend].
func (b *symmetricBackend) Supports(use key.KeyUse, operation key.KeyOperation, algorithm key.KeyAlg) bool {
	for _, capability := range capabilities {
		if capability.Use == use && capability.Operation == operation && capability.Algorithm == algorithm {
			return true
		}
	}
	return false
}

// VerifySignature implements [key.SignatureVerifier].
func (b *symmetricBackend) VerifySignature(ctx context.Context, algorithm key.KeyAlg, signature []byte, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	hash, err := b.signatureOptions(algorithm)
	if err != nil {
		return err
	}
	mac := stdhmac.New(hash.New, b.material.Key)
	_, _ = mac.Write(message)
	if !stdhmac.Equal(signature, mac.Sum(nil)) {
		return fmt.Errorf("symetric backend: invalid signature")
	}
	return nil
}

// Encrypt implements [key.Encrypter].
func (b *symmetricBackend) Encrypt(ctx context.Context, algorithm key.KeyAlg, plaintext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if algorithm == DES2ECB || algorithm == DES2CBC {
		return unsafeEncrypt(b.material.Key, algorithm, plaintext)
	}
	gcm, err := b.encryptionOptions(algorithm)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("symetric backend: generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt implements [key.Decrypter].
func (b *symmetricBackend) Decrypt(ctx context.Context, algorithm key.KeyAlg, ciphertext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if algorithm == DES2ECB || algorithm == DES2CBC {
		return unsafeDecrypt(b.material.Key, algorithm, ciphertext)
	}
	gcm, err := b.encryptionOptions(algorithm)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("symetric backend: ciphertext is too short")
	}
	nonce, encrypted := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("symetric backend: decrypt ciphertext: %w", err)
	}
	return plaintext, nil
}

var _ key.Backend = &symmetricBackend{}
var _ key.Signer = &symmetricBackend{}
var _ key.SignatureVerifier = &symmetricBackend{}
var _ key.Encrypter = &symmetricBackend{}
var _ key.Decrypter = &symmetricBackend{}
