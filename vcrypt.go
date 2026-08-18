package vcrypt

import (
	"github.com/veles-security/vcrypt/keysource"
	"github.com/veles-security/vcrypt/keystore"
)

type Service struct {
	keystore keystore.Store
}

type CryptoOption func(service *Service) error

func WithKeystoreFileSourceOptions(id, path string, options ...keysource.FileOption) CryptoOption {
	return func(service *Service) error {
		s, err := keysource.NewFileSource(id, path, options...)
		if err != nil {
			return err
		}
		err = service.keystore.Bind(s)
		if err != nil {
			return err
		}
		return nil
	}
}

func New(options ...CryptoOption) *Service {
	s := &Service{}
	return s
}
