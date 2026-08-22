package descriptor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/backend"
	"github.com/veles-security/vcrypt/key"
)

// JWKSEncoder encodes JSON Web Key Sets using the registered JOSE encoders.
type JWKSEncoder struct{}

// NewJWKSEncoder returns a JSON Web Key Set encoder.
func NewJWKSEncoder() vapi.Encoder[JWKS[key.Key], key.JOSEEncodeOption] {
	return &JWKSEncoder{}
}

// Encode implements [vapi.Encoder].
func (e *JWKSEncoder) Encode(ctx context.Context, artifact JWKS[key.Key], options ...key.JOSEEncodeOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(options) > 1 {
		return nil, fmt.Errorf("JWKS encoder: expected at most one option, got %d", len(options))
	}

	encodedKeys := make([]json.RawMessage, 0, len(artifact.Keys))
	for i, value := range artifact.Keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		encoder, err := backend.JOSEEncoderFor(value.Material())
		if err != nil {
			return nil, fmt.Errorf("JWKS encoder: key %d: select encoder: %w", i+1, err)
		}
		encoded, err := encoder.Encode(ctx, value, options...)
		if err != nil {
			return nil, fmt.Errorf("JWKS encoder: key %d: %w", i+1, err)
		}
		encodedKeys = append(encodedKeys, json.RawMessage(encoded))
	}

	encoded, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: encodedKeys})
	if err != nil {
		return nil, fmt.Errorf("JWKS encoder: marshal key set: %w", err)
	}
	return encoded, nil
}

var _ vapi.Encoder[JWKS[key.Key], key.JOSEEncodeOption] = &JWKSEncoder{}
