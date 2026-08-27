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

// Decoder decodes JSON Web Key Sets using the registered JOSE decoders.
type Decoder struct {
	runtimeOptions []DecoderOption
}

type DecoderConfigOption func(*Decoder) error

type DecodeFunc func(ctx context.Context, payload []byte, options ...key.JOSEDecodeOption) (JWKS[key.KeyCandidate], error)

type DecoderOption func(next DecodeFunc) DecodeFunc

// NewDecoder returns a JSON Web Key Set decoder.
func NewDecoder(configOptions ...DecoderConfigOption) (vapi.Decoder[JWKS[key.KeyCandidate], DecoderOption], error) {
	decoder := &Decoder{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil decoder config option"))
		}
		if err := option(decoder); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return decoder, nil
}

// Decode implements [vapi.Decoder].
func (d *Decoder) Decode(ctx context.Context, encoded []byte, options ...DecoderOption) (JWKS[key.KeyCandidate], error) {
	if err := ctx.Err(); err != nil {
		return JWKS[key.KeyCandidate]{}, err
	}
	if d == nil {
		return JWKS[key.KeyCandidate]{}, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot decode JWKS with nil JWK decoder"))
	}
	if encoded == nil {
		return JWKS[key.KeyCandidate]{}, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot decode nil JWKS payload"))
	}

	allOptions := make([]DecoderOption, 0, len(d.runtimeOptions)+len(options))
	allOptions = append(allOptions, d.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := d.decode
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return JWKS[key.KeyCandidate]{}, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil decoder option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return JWKS[key.KeyCandidate]{}, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("decoder option at index %d returned nil DecodeFunc", index))
		}
		next = wrapped
	}
	return next(ctx, encoded)
}

func (d *Decoder) decode(ctx context.Context, encoded []byte, options ...key.JOSEDecodeOption) (JWKS[key.KeyCandidate], error) {
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

var _ vapi.Decoder[JWKS[key.KeyCandidate], DecoderOption] = &Decoder{}
