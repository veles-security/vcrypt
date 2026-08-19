package key

import (
	"context"
)

type Backend interface {
	Supports(use KeyUse, operation KeyOperation, algorithm KeyAlg) bool
	Capabilities() []Capability

	Sign(ctx context.Context, algorithm KeyAlg, message []byte) ([]byte, error)
	VerifySignature(ctx context.Context, algorithm KeyAlg, signature []byte, message []byte) error
	Encrypt(ctx context.Context, algorithm KeyAlg, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, algorithm KeyAlg, ciphertext []byte) ([]byte, error)
}
