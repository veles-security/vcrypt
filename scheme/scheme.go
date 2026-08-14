package scheme

import "github.com/veles-security/vcrypt/key"

type Scheme interface {
	DiscoverCapabilities(*key.Key) error
}
