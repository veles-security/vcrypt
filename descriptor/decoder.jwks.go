package descriptor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/backend"
	"github.com/veles-security/vcrypt/key"
)

// JWKSDecoder decodes JSON Web Key Sets using the registered JOSE decoders.
type JWKSDecoder struct{}

// NewJWKSDecoder returns a JSON Web Key Set decoder.
func NewJWKSDecoder() vapi.Decoder[JWKS[key.KeyCandidate], key.JOSEDecodeOption] {
	return &JWKSDecoder{}
}

// Decode implements [vapi.Decoder].
func (d *JWKSDecoder) Decode(ctx context.Context, encoded []byte, options ...key.JOSEDecodeOption) (JWKS[key.KeyCandidate], error) {
	if err := ctx.Err(); err != nil {
		return JWKS[key.KeyCandidate]{}, err
	}
	if len(options) > 1 {
		return JWKS[key.KeyCandidate]{}, fmt.Errorf("JWKS decoder: expected at most one option, got %d", len(options))
	}

	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		return JWKS[key.KeyCandidate]{}, fmt.Errorf("JWKS decoder: unmarshal key set: %w", err)
	}
	if document.Keys == nil {
		return JWKS[key.KeyCandidate]{}, fmt.Errorf("JWKS decoder: keys member is required")
	}

	result := JWKS[key.KeyCandidate]{Keys: make([]key.KeyCandidate, 0, len(document.Keys))}
	for i, encodedKey := range document.Keys {
		if err := ctx.Err(); err != nil {
			return JWKS[key.KeyCandidate]{}, err
		}
		var header struct {
			KeyType string `json:"kty"`
		}
		if err := json.Unmarshal(encodedKey, &header); err != nil {
			return JWKS[key.KeyCandidate]{}, fmt.Errorf("JWKS decoder: key %d: unmarshal header: %w", i+1, err)
		}
		if header.KeyType == "" {
			return JWKS[key.KeyCandidate]{}, fmt.Errorf("JWKS decoder: key %d: kty member is required", i+1)
		}
		decoder, err := backend.JOSEDecoderFor(header.KeyType)
		if err != nil {
			return JWKS[key.KeyCandidate]{}, fmt.Errorf("JWKS decoder: key %d: select decoder for kty %q: %w", i+1, header.KeyType, err)
		}
		candidate, err := decoder.Decode(ctx, encodedKey, options...)
		if err != nil {
			return JWKS[key.KeyCandidate]{}, fmt.Errorf("JWKS decoder: key %d: %w", i+1, err)
		}
		result.Keys = append(result.Keys, candidate)
	}
	return result, nil
}

var _ vapi.Decoder[JWKS[key.KeyCandidate], key.JOSEDecodeOption] = &JWKSDecoder{}
