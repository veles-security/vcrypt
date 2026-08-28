package jws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keystore"
)

type Signer struct {
	keystore keystore.Keystore
}

func New(keystore keystore.Keystore) (*Signer, error) {
	if keystore == nil {
		return nil, fmt.Errorf("JWS: nil keystore")
	}
	return &Signer{
		keystore: keystore,
	}, nil
}

func (j *Signer) Sign(ctx context.Context, claims []byte, options ...keystore.SignOption) (JWS, error) {
	var header, message []byte
	result, err := j.keystore.SignPrepared(ctx, func(signKey key.KeyDescriptor) ([]byte, error) {
		headerMap := map[string]string{
			"kid": signKey.ID,
			"alg": string(signKey.Algorithm),
		}
		var err error
		header, err = json.Marshal(headerMap)
		if err != nil {
			return nil, fmt.Errorf("JWS: marshal protected header: %w", err)
		}
		message = []byte(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims))
		return message, nil
	}, options...)
	if err != nil {
		return JWS{}, err
	}
	return JWS{
		Header:    header,
		Claims:    append([]byte(nil), claims...),
		Signature: result.Signature,
		Key:       result.Key,
		Encoded:   []byte(string(message) + "." + base64.RawURLEncoding.EncodeToString(result.Signature)),
	}, nil
}
