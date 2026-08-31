package jws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keystore"
)

type Signer struct {
	keystore       keystore.Keystore
	runtimeOptions []SignerOption
}

type SignerConfigOption func(*Signer) error

type HeaderFunc func(signKey key.KeyDescriptor) map[string]string

// SignFunc signs claims using the supplied protected header and keystore
// options. Signer options may decorate header before passing it to next.
type SignFunc func(ctx context.Context, claims []byte, headerFunc HeaderFunc, options ...keystore.SignOption) (JWS, error)

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

	allOptions := slices.Concat(j.runtimeOptions, options)

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

	return next(ctx, claims, j.mapHeader)
}

func (j *Signer) sign(ctx context.Context, claims []byte, headerFunc HeaderFunc, options ...keystore.SignOption) (JWS, error) {
	if headerFunc == nil {
		return JWS{}, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil JWS header func"))
	}

	signKey, sign, err := j.keystore.Signer(ctx, options...)
	if err != nil {
		return JWS{}, err
	}
	headerMap := headerFunc(signKey)
	header, err := json.Marshal(headerMap)
	if err != nil {
		return JWS{}, vapi.NewErrorCategory(vapi.ErrInternal, fmt.Errorf("marshal header: %w", err))
	}
	message := []byte(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims))
	signature, err := sign(message)
	if err != nil {
		return JWS{}, err
	}
	return JWS{
		Header:    header,
		Claims:    append([]byte(nil), claims...),
		Signature: signature,
		Key:       signKey,
		Encoded:   []byte(string(message) + "." + base64.RawURLEncoding.EncodeToString(signature)),
	}, nil
}

func (j *Signer) mapHeader(signKey key.KeyDescriptor) map[string]string {
	header := map[string]string{}
	header["kid"] = signKey.ID
	header["alg"] = string(signKey.Algorithm)
	return header
}

var _ vapi.Signer[SignerOption, JWS] = &Signer{}
