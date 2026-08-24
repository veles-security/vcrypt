//go:build with_unsafe_crypto

package symetric

import (
	"bytes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- explicitly enabled for legacy HSM interoperability
	"crypto/rand"
	"fmt"

	"github.com/veles-security/vcrypt/key"
)

const unsafeCryptoEnabled = true

var unsafeCryptoCapabilities = []key.Capability{
	{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: DES2ECB},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: DES2CBC},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: DES2ECB},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: DES2CBC},
}

func des2Cipher(keyBytes []byte, algorithm key.KeyAlg) (cipher.Block, error) {
	if len(keyBytes) != 16 {
		return nil, fmt.Errorf("symetric backend: invalid key size for %s: got %d bytes, require 16", algorithm, len(keyBytes))
	}
	if bytes.Equal(keyBytes[:8], keyBytes[8:]) {
		return nil, fmt.Errorf("symetric backend: invalid DES2 key: K1 and K2 must differ")
	}
	key24 := make([]byte, 24)
	copy(key24, keyBytes)
	copy(key24[16:], keyBytes[:8])
	return des.NewTripleDESCipher(key24) // #nosec G502 -- legacy support is explicitly build-tagged; nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-DES
}

func unsafeEncrypt(keyBytes []byte, algorithm key.KeyAlg, plaintext []byte) ([]byte, error) {
	block, err := des2Cipher(keyBytes, algorithm)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	switch algorithm {
	case DES2ECB:
		ciphertext := make([]byte, len(padded))
		ecbCrypt(block.Encrypt, ciphertext, padded, block.BlockSize())
		return ciphertext, nil
	case DES2CBC:
		iv := make([]byte, block.BlockSize())
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("symetric backend: generate IV: %w", err)
		}
		ciphertext := make([]byte, len(iv)+len(padded))
		copy(ciphertext, iv)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext[len(iv):], padded)
		return ciphertext, nil
	default:
		return nil, fmt.Errorf("symetric backend: unsupported unsafe encryption algorithm %q", algorithm)
	}
}

func unsafeDecrypt(keyBytes []byte, algorithm key.KeyAlg, ciphertext []byte) ([]byte, error) {
	block, err := des2Cipher(keyBytes, algorithm)
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	var plaintext []byte
	switch algorithm {
	case DES2ECB:
		encrypted = ciphertext
		plaintext = make([]byte, len(encrypted))
		if len(encrypted) == 0 || len(encrypted)%block.BlockSize() != 0 {
			return nil, fmt.Errorf("symetric backend: invalid DES2-ECB ciphertext length")
		}
		ecbCrypt(block.Decrypt, plaintext, encrypted, block.BlockSize())
	case DES2CBC:
		if len(ciphertext) < 2*block.BlockSize() || len(ciphertext)%block.BlockSize() != 0 {
			return nil, fmt.Errorf("symetric backend: invalid DES2-CBC ciphertext length")
		}
		iv := ciphertext[:block.BlockSize()]
		encrypted = ciphertext[block.BlockSize():]
		plaintext = make([]byte, len(encrypted))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, encrypted)
	default:
		return nil, fmt.Errorf("symetric backend: unsupported unsafe encryption algorithm %q", algorithm)
	}
	return pkcs7Unpad(plaintext, block.BlockSize())
}

func pkcs7Pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	return append(append([]byte(nil), plaintext...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(plaintext []byte, blockSize int) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("symetric backend: invalid PKCS#7 padding")
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > blockSize || !bytes.Equal(plaintext[len(plaintext)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		return nil, fmt.Errorf("symetric backend: invalid PKCS#7 padding")
	}
	return plaintext[:len(plaintext)-padding], nil
}

func ecbCrypt(cryptBlock func([]byte, []byte), dst, src []byte, blockSize int) {
	for len(src) > 0 {
		cryptBlock(dst[:blockSize], src[:blockSize])
		dst = dst[blockSize:]
		src = src[blockSize:]
	}
}
