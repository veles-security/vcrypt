package keystore

import "github.com/veles-security/vcrypt/key"

type operationQuery struct {
	Keys       KeySelector
	Algorithms []key.KeyAlg
}

// SignOption configures key selection for a signing operation.
type SignOption func(*operationQuery) error

// VerifyOption configures key selection for a signature verification
// operation.
type VerifyOption = SignOption

// EncryptOption configures key selection for an encryption operation.
type EncryptOption = SignOption

// DecryptOption configures key selection for a decryption operation.
type DecryptOption = SignOption

// WithKeys restricts an operation to keys matching selector.
func WithKeys(selector KeySelector) SignOption {
	return func(options *operationQuery) error {
		options.Keys = selector
		return nil
	}
}

// WithAlgorithms sets algorithms in order of preference.
func WithAlgorithms(algorithms ...key.KeyAlg) SignOption {
	return func(options *operationQuery) error {
		options.Algorithms = append([]key.KeyAlg(nil), algorithms...)
		return nil
	}
}

func applyOperationQuery[T ~func(*operationQuery) error](options []T) (operationQuery, error) {
	var request operationQuery
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&request); err != nil {
			return operationQuery{}, err
		}
	}
	return request, nil
}
