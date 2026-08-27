package key

import (
	"context"
)

type Backend interface {
	Supports(use KeyUse, operation KeyOperation, algorithm KeyAlg) bool
	Capabilities() []Capability
}

type Signer interface {
	Sign(ctx context.Context, algorithm KeyAlg, message []byte) ([]byte, error)
}

type Verifier interface {
	Verify(ctx context.Context, algorithm KeyAlg, signature []byte, message []byte) error
}

type Encrypter interface {
	Encrypt(ctx context.Context, algorithm KeyAlg, plaintext []byte) ([]byte, error)
}

type Decrypter interface {
	Decrypt(ctx context.Context, algorithm KeyAlg, ciphertext []byte) ([]byte, error)
}
