package scheme

import (
	"github.com/veles-security/vcrypt"
	"github.com/veles-security/vcrypt/alg"
	"github.com/veles-security/vcrypt/key"
)

type Scheme interface {
	DiscoverCapabilities(*key.Key) error
	Signer(*key.Key, alg.Alg) vcrypt.Signer
}
