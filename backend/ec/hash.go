package ec

import (
	"crypto"
	"fmt"
)

func hashMessage(hash crypto.Hash, message []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("sig: hash %v is unavailable", hash)
	}
	h := hash.New()
	_, _ = h.Write(message)
	return h.Sum(nil), nil
}
