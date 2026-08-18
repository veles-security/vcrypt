package key

import (
	"context"
)

type SignOption KeyAlg
type VerifyOption KeyAlg

type Backend interface {
	Supports(use KeyUse, operation KeyOperation, algorithm KeyAlg) bool
	Capabilities() []Capability

	Sign(ctx context.Context, message []byte, options ...SignOption) ([]byte, error)
	VerifySignature(ctx context.Context, signature []byte, message []byte, options ...VerifyOption) error
}
