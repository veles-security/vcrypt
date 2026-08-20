package keystore

import "github.com/veles-security/vcrypt/key"

type runtimeOptions struct {
	Owner      string
	Source     string
	Algorithms []key.KeyAlg
	Kid        string
}

// SignOption configures key selection for a signing operation.
type SignOption func(*runtimeOptions) error

// VerifyOption configures key selection for a signature verification
// operation.
type VerifyOption = SignOption

// WithSignatureOwner restricts key selection to keys owned by owner.
func WithSignatureOwner(owner string) SignOption {
	return func(options *runtimeOptions) error {
		options.Owner = owner
		return nil
	}
}

// WithSignatureSource restricts key selection to keys from source.
func WithSignatureSource(source string) SignOption {
	return func(options *runtimeOptions) error {
		options.Source = source
		return nil
	}
}

// WithSignatureAlgorithms sets algorithms in order of preference.
func WithSignatureAlgorithms(algorithms ...key.KeyAlg) SignOption {
	return func(options *runtimeOptions) error {
		options.Algorithms = append([]key.KeyAlg(nil), algorithms...)
		return nil
	}
}

// WithSignatureKid restricts key selection to the key with kid.
func WithSignatureKid(kid string) SignOption {
	return func(options *runtimeOptions) error {
		options.Kid = kid
		return nil
	}
}

func applyRuntimeOptions[T ~func(*runtimeOptions) error](options []T) (runtimeOptions, error) {
	var request runtimeOptions
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&request); err != nil {
			return runtimeOptions{}, err
		}
	}
	return request, nil
}
