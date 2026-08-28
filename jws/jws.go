package jws

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/veles-security/vcrypt/keystore"
)

type JWS struct {
	keystore keystore.Keystore
}

func (j *JWS) Sign(ctx context.Context, claims []byte, options ...keystore.SignOption) (keystore.SignResult, error) {
	key, err := j.keystore.SignKey(ctx, options...)
	if err != nil {
		return keystore.SignResult{}, err
	}
	headerMap := map[string]string{
		"kid": key.ID,
		"alg": string(key.Algorithm),
	}
	header, err := json.Marshal(headerMap)
	signingInput := []byte(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims))
	return j.keystore.Sign(ctx, signingInput, options...)
}
