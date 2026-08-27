package jwks

import (
	"context"
	"fmt"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/key"
)

// Writer writes JSON Web Key Sets to HTTP responses.
type Writer struct {
	encoder        vapi.Encoder[*JWKS[key.Key], EncoderOption]
	runtimeOptions []WriterOption
}

type WriterConfigOption func(*Writer) error

type WriteFunc func(ctx context.Context, carrierWriter http.ResponseWriter, artifact *JWKS[key.Key], options ...EncoderOption) error

type WriterOption func(next WriteFunc) WriteFunc

// NewWriter returns a JSON Web Key Set HTTP response writer.
func NewWriter(options ...WriterConfigOption) vapi.Writer[http.ResponseWriter, *JWKS[key.Key], WriterOption] {
	return &Writer{
		encoder: &Encoder{},
	}
}

// WriteArtifact implements [vapi.Writer].
func (w *Writer) WriteArtifact(ctx context.Context, carrierWriter http.ResponseWriter, artifact *JWKS[key.Key], options ...WriterOption) error {
	if w.encoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("cannot write JWKS response with nil JWKS encoder"))
	}
	if artifact.Keys == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("cannot write JWKS response with nil Keys"))
	}
	if len(artifact.Keys) == 0 {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("cannot write JWKS response with no Keys"))
	}

	allOptions := make([]WriterOption, 0, len(w.runtimeOptions)+len(options))
	allOptions = append(allOptions, w.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := w.writeArtifact
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil writer option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("writer option at index %d returned nil WriteFunc", index))
		}
		next = wrapped
	}

	return next(ctx, carrierWriter, artifact)
}

func (w *Writer) writeArtifact(ctx context.Context, carrierWriter http.ResponseWriter, artifact *JWKS[key.Key], options ...EncoderOption) error {
	payload, err := w.encoder.Encode(ctx, artifact, options...)
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrInternal, fmt.Errorf("encode JWKS: %w", err))
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     carrierWriter.Header(),
	}

	response.Header.Set("Content-Type", "application/jwk-set+json")
	response.Header.Set("X-Content-Type-Options", "nosniff")

	carrierWriter.WriteHeader(response.StatusCode)

	if _, err := carrierWriter.Write(payload); err != nil {
		return vapi.NewErrorCategory(vapi.ErrInternal, fmt.Errorf("write JWKS response: %w", err))
	}
	return nil
}

var _ vapi.Writer[http.ResponseWriter, *JWKS[key.Key], WriterOption] = &Writer{}
