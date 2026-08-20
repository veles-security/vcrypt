package keystore

import "github.com/veles-security/vcrypt/key"

type signerQuery struct {
	Owner      string
	Source     string
	Algorithms []key.KeyAlg
	Kid        string
}

// SignOption configures key selection for a signing operation.
type SignOption func(*signerQuery) error

// VerifyOption configures key selection for a signature verification
// operation.
type VerifyOption = func(*signerQuery) error

// WithSignatureOwner restricts key selection to keys owned by owner.
func WithSignatureOwner(owner string) SignOption {
	return func(options *signerQuery) error {
		options.Owner = owner
		return nil
	}
}

// WithSignatureSource restricts key selection to keys from source.
func WithSignatureSource(source string) SignOption {
	return func(options *signerQuery) error {
		options.Source = source
		return nil
	}
}

// WithSignatureAlgorithms sets algorithms in order of preference.
func WithSignatureAlgorithms(algorithms ...key.KeyAlg) SignOption {
	return func(options *signerQuery) error {
		options.Algorithms = append([]key.KeyAlg(nil), algorithms...)
		return nil
	}
}

// WithSignatureKid restricts key selection to the key with kid.
func WithSignatureKid(kid string) SignOption {
	return func(options *signerQuery) error {
		options.Kid = kid
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
