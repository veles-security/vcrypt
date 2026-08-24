package symetric

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type joseDecoder struct{}

// NewJOSEDecoder returns a symmetric single-key JOSE decoder.
func NewJOSEDecoder() key.JOSEDecoder { return &joseDecoder{} }

// SupportsJOSEKeyType implements [key.JOSEDecoder].
func (d *joseDecoder) SupportsJOSEKeyType(keyType string) bool { return keyType == "oct" }

// Decode implements [key.JOSEDecoder].
func (d *joseDecoder) Decode(ctx context.Context, encoded []byte, options ...key.JOSEDecodeOption) (key.KeyCandidate, error) {
	if err := ctx.Err(); err != nil {
		return key.KeyCandidate{}, err
	}
	if len(options) > 1 {
		return key.KeyCandidate{}, fmt.Errorf("symetric JOSE decoder: expected at most one option, got %d", len(options))
	}
	var jwk symmetricJWK
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		return key.KeyCandidate{}, fmt.Errorf("symetric JOSE decoder: unmarshal JWK: %w", err)
	}
	if !d.SupportsJOSEKeyType(jwk.KeyType) {
		return key.KeyCandidate{}, fmt.Errorf("symetric JOSE decoder: unsupported kty %q", jwk.KeyType)
	}
	if jwk.Key == "" {
		return key.KeyCandidate{}, fmt.Errorf("symetric JOSE decoder: parameter %q is missing", "k")
	}
	decodedKey, err := base64.RawURLEncoding.DecodeString(jwk.Key)
	if err != nil {
		return key.KeyCandidate{}, fmt.Errorf("symetric JOSE decoder: decode parameter %q: %w", "k", err)
	}
	if len(decodedKey) == 0 {
		return key.KeyCandidate{}, fmt.Errorf("symetric JOSE decoder: key is empty")
	}

	return key.KeyCandidate{
		ID:           jwk.KeyID,
		Restrictions: symmetricRestrictionsFromJWK(jwk),
		Material:     &material.SymmetricMaterial{Key: decodedKey},
	}, nil
}

func symmetricRestrictionsFromJWK(jwk symmetricJWK) []key.Capability {
	if jwk.Algorithm == "" || len(jwk.Operations) == 0 {
		return nil
	}
	restrictions := make([]key.Capability, 0, len(jwk.Operations))
	for _, operation := range jwk.Operations {
		keyOperation := key.KeyOperation(operation)
		use := key.KeyUseSigning
		if keyOperation == key.KeyOpEncrypt || keyOperation == key.KeyOpDecrypt {
			use = key.KeyUseEncryption
		}
		switch jwk.Use {
		case "sig":
			use = key.KeyUseSigning
		case "enc":
			use = key.KeyUseEncryption
		}
		restrictions = append(restrictions, key.Capability{Use: use, Operation: keyOperation, Algorithm: key.KeyAlg(jwk.Algorithm)})
	}
	return restrictions
}

var _ key.JOSEDecoder = &joseDecoder{}
