package keystore

import "github.com/veles-security/vcrypt/key"

type signerQuery struct {
	Keys       KeySelector
	Algorithms []key.KeyAlg
}

// SignOption configures key selection for a signing operation.
type SignOption func(*signerQuery) error

// VerifyOption configures key selection for a signature verification
// operation.
type VerifyOption = func(*signerQuery) error

// WithKeys restricts an operation to keys matching selector.
func WithKeys(selector KeySelector) SignOption {
	return func(options *signerQuery) error {
		options.Keys = selector
		return nil
	}
}

// WithAlgorithms sets algorithms in order of preference.
func WithAlgorithms(algorithms ...key.KeyAlg) SignOption {
	return func(options *signerQuery) error {
		options.Algorithms = append([]key.KeyAlg(nil), algorithms...)
		return nil
	}
}

func applySignerQuery[T ~func(*signerQuery) error](options []T) (signerQuery, error) {
	var request signerQuery
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&request); err != nil {
			return signerQuery{}, err
		}
	}
	return request, nil
}
