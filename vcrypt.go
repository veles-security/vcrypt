package vcrypt

import "context"

type Signer interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

type Verifier interface {
	Verify(ctx context.Context, message []byte, signature []byte) error
}
