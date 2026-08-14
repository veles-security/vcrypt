package rsa

import (
	"context"
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
)

type rsaSigner struct {
	key  *stdrsa.PrivateKey
	hash crypto.Hash
	pss  bool
}

func (s *rsaSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest, err := hashMessage(s.hash, message)
	if err != nil {
		return nil, err
	}
	if s.pss {
		return stdrsa.SignPSS(rand.Reader, s.key, s.hash, digest, &stdrsa.PSSOptions{
			SaltLength: stdrsa.PSSSaltLengthEqualsHash,
		})
	}
	return stdrsa.SignPKCS1v15(rand.Reader, s.key, s.hash, digest)
}
