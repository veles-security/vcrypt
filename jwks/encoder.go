package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/backend"
	"github.com/veles-security/vcrypt/key"
)

// Encoder encodes JSON Web Key Sets using the registered JOSE encoders.
type Encoder struct {
	runtimeOptions []EncoderOption
}

type EncoderConfigOption func(*Encoder) error

type EncodeFunc func(ctx context.Context, artifact *JWKS[key.Key], options ...key.JOSEEncodeOption) ([]byte, error)

type EncoderOption func(next EncodeFunc) EncodeFunc

// NewJWKSEncoder returns a JSON Web Key Set encoder.
func NewEncoder(configOptions ...EncoderConfigOption) (vapi.Encoder[*JWKS[key.Key], EncoderOption], error) {
	encoder := &Encoder{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil encoder config option"))
		}
		if err := option(encoder); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return encoder, nil
}

// Encode implements [vapi.Encoder].
func (e *Encoder) Encode(ctx context.Context, artifact *JWKS[key.Key], options ...EncoderOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode nil JWKS"))
	}
	if artifact.Keys == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode JWKS with nil Keys"))
	}
	if len(artifact.Keys) == 0 {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode JWKS with no Keys"))
	}

	allOptions := make([]EncoderOption, 0, len(e.runtimeOptions)+len(options))
	allOptions = append(allOptions, e.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := e.encode
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil encoder option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("encoder option at index %d returned nil EncodeFunc", index))
		}
		next = wrapped
	}

	return next(ctx, artifact)
}

func (e *Encoder) encode(ctx context.Context, artifact *JWKS[key.Key], options ...key.JOSEEncodeOption) ([]byte, error) {
	encodedKeys := make([]json.RawMessage, 0, len(artifact.Keys))
	for i, value := range artifact.Keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		encoder, err := backend.JOSEEncoderFor(value.Material())
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("JWKS encoder: key %d: select encoder: %w", i+1, err))
		}
		encoded, err := encoder.Encode(ctx, value, options...)
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrInternal, fmt.Errorf("JWKS encoder: key %d: %w", i+1, err))
		}
		encodedKeys = append(encodedKeys, json.RawMessage(encoded))
	}

	encoded, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: encodedKeys})
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrInternal, fmt.Errorf("JWKS encoder: marshal key set: %w", err))
	}
	return encoded, nil
}

var _ vapi.Encoder[*JWKS[key.Key], EncoderOption] = &Encoder{}
