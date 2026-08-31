package errs

import "errors"

var (
	ErrInvalidAlgorithm     = errors.New("invalid algorithm")
	ErrInvalidKey           = errors.New("invalid key")
	ErrAlgorithmKeyMismatch = errors.New("algorithm and key mismatch")

	ErrMalformedSignature = errors.New("malformed signature")
)
