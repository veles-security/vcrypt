package jws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keystore"
)

type Signer struct {
	keystore       keystore.Keystore
	runtimeOptions []SignerOption
}

type SignerConfigOption func(*Signer) error

// HeaderFunc builds the protected header for the key selected by the keystore.
type HeaderFunc func(key.KeyDescriptor) ([]byte, error)

// SignFunc signs claims using the supplied protected-header builder and
// keystore options.
type SignFunc func(ctx context.Context, claims []byte, header HeaderFunc, options ...keystore.SignOption) (JWS, error)

type SignerOption func(next SignFunc) SignFunc

func New(options ...SignerConfigOption) (vapi.Signer[SignerOption, JWS], error) {
	signer := &Signer{}
	for _, option := range options {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil signer config option"))
		}
		if err := option(signer); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if signer.keystore == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil signer keystore"))
	}
	return signer, nil
}

func (j *Signer) Sign(ctx context.Context, claims []byte, options ...SignerOption) (JWS, error) {
	if err := ctx.Err(); err != nil {
		return JWS{}, err
	}

	allOptions := make([]SignerOption, 0, len(j.runtimeOptions)+len(options))
	allOptions = append(allOptions, j.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := j.sign
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return JWS{}, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil signer option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return JWS{}, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("signer option at index %d returned nil SignFunc", index))
		}
		next = wrapped
	}

	return next(ctx, claims, defaultHeader)
}

func (j *Signer) sign(ctx context.Context, claims []byte, buildHeader HeaderFunc, options ...keystore.SignOption) (JWS, error) {
	if buildHeader == nil {
		return JWS{}, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil JWS header function"))
	}

	var header, message []byte
	result, err := j.keystore.SignPrepared(ctx, func(signKey key.KeyDescriptor) ([]byte, error) {
		var err error
		header, err = buildHeader(signKey)
		if err != nil {
			return nil, fmt.Errorf("JWS: build protected header: %w", err)
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

func defaultHeader(signKey key.KeyDescriptor) ([]byte, error) {
	header, err := json.Marshal(map[string]string{
		"kid": signKey.ID,
		"alg": string(signKey.Algorithm),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal protected header: %w", err)
	}
	return header, nil
}

var _ vapi.Signer[SignerOption, JWS] = &Signer{}
