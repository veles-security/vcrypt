package vcrypt

import (
	"github.com/veles-security/vcrypt/keysource/filesource"
	"github.com/veles-security/vcrypt/keystore"
)

type Service struct {
	keystore keystore.Store
}

func (s *Service) Keystore() keystore.Store {
	return s.keystore
}

type CryptoOption func(service *Service) error

func WithFileSource(id, path string, options ...filesource.Option) CryptoOption {
	return func(service *Service) error {
		s, err := filesource.New(id, path, options...)
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

func New(options ...CryptoOption) (*Service, error) {
	kstore, err := keystore.New()
	if err != nil {
		return nil, err
	}
	s := &Service{
		keystore: kstore,
	}
	for _, option := range options {
		err := option(s)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}
