package keystore

import "github.com/veles-security/vcrypt/key"

type operationQuery struct {
	Keys       key.Selector
	Algorithms []key.KeyAlg
}

type KeystoreRuntimeOption func(*operationQuery)

// SignOption configures key selection for a signing operation.
type SignOption KeystoreRuntimeOption

// VerifyOption configures key selection for a signature verification operation.
type VerifyOption = KeystoreRuntimeOption

// EncryptOption configures key selection for an encryption operation.
type EncryptOption = KeystoreRuntimeOption

// DecryptOption configures key selection for a decryption operation.
type DecryptOption = KeystoreRuntimeOption

// WithKeys restricts an operation to keys matching selector.
func WithKeys(selector key.Selector) KeystoreRuntimeOption {
	return func(options *operationQuery) {
		options.Keys = selector
	}
}

// WithAlgorithms sets algorithms in order of preference.
func WithAlgorithms(algorithms ...key.KeyAlg) KeystoreRuntimeOption {
	return func(options *operationQuery) {
		options.Algorithms = append([]key.KeyAlg(nil), algorithms...)
	}
}
