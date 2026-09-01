package jws

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/keystore"
)

type Verifier struct {
	keystore       keystore.Keystore
	runtimeOptions []VerifierOption
}

type VerifierConfigOption func(*Verifier) error

type VerifyFunc func(ctx context.Context, message []byte, signature []byte, options ...keystore.VerifyOption) error

type VerifierOption func(next VerifyFunc) VerifyFunc

func NewVerifier(options ...VerifierConfigOption) (vapi.Verifier[VerifierOption], error) {
	verifier := &Verifier{}
	for _, option := range options {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier config option"))
		}
		if err := option(verifier); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if verifier.keystore == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier keystore"))
	}
	return verifier, nil
}

// Verify implements [vapi.Verifier].
func (v *Verifier) Verify(ctx context.Context, message []byte, signature []byte, options ...VerifierOption) error {
	if v == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier"))
	}
	if ctx == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier context"))
	}
	if v.keystore == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier keystore"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	allOptions := slices.Concat(v.runtimeOptions, options)

	next := v.verify
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil verifier option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("verifier option at index %d returned nil VerifyFunc", index))
		}
		next = wrapped
	}

	return next(ctx, message, signature)
}

func (v *Verifier) verify(ctx context.Context, message []byte, signature []byte, options ...keystore.VerifyOption) error {
	if v == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier"))
	}
	if ctx == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier context"))
	}
	if v.keystore == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil verifier keystore"))
	}
	return v.keystore.Verify(ctx, message, signature, options...)
}

var _ vapi.Verifier[VerifierOption] = &Verifier{}
