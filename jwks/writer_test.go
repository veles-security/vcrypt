package jwks_test

import (
	"context"
	stdrsa "crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	_ "github.com/veles-security/vcrypt/backend/rsa"
	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/jwks"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type encoderFunc func(context.Context, *jwks.JWKS[key.Key], ...jwks.EncoderOption) ([]byte, error)

func (f encoderFunc) Encode(ctx context.Context, artifact *jwks.JWKS[key.Key], options ...jwks.EncoderOption) ([]byte, error) {
	return f(ctx, artifact, options...)
}

type errorResponseWriter struct {
	header http.Header
	err    error
}

func (w *errorResponseWriter) Header() http.Header        { return w.header }
func (w *errorResponseWriter) WriteHeader(statusCode int) {}
func (w *errorResponseWriter) Write([]byte) (int, error)  { return 0, w.err }

func TestWriter_WriteArtifact(t *testing.T) {
	// keys
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*stdrsa.PrivateKey)
	publicKey := key.New(key.KeyCandidate{ID: "public-key", Material: &material.PublicMaterial{Key: &privateKey.PublicKey}}, nil)
	artifact := &jwks.JWKS[key.Key]{Keys: []key.Key{publicKey}}
	// errors
	encodeFailure := errors.New("encode failure")
	writeFailure := errors.New("write failure")
	// writers
	newWriter := func(options ...jwks.WriterConfigOption) vapi.Writer[http.ResponseWriter, *jwks.JWKS[key.Key], jwks.WriterOption] {
		writer, err := jwks.NewWriter(options...)
		if err != nil {
			t.Fatalf("NewWriter() error = %v", err)
		}
		return writer
	}
	defaultWriter := newWriter()
	encodeFailingWriter := newWriter(jwks.WithWriterEncoder(encoderFunc(func(context.Context, *jwks.JWKS[key.Key], ...jwks.EncoderOption) ([]byte, error) {
		return nil, encodeFailure
	})))
	optionOrder := []string{}
	option := func(name string) jwks.WriterOption {
		return func(next jwks.WriteFunc) jwks.WriteFunc {
			return func(ctx context.Context, carrierWriter http.ResponseWriter, artifact *jwks.JWKS[key.Key], options ...jwks.EncoderOption) error {
				optionOrder = append(optionOrder, name+" before")
				err := next(ctx, carrierWriter, artifact, options...)
				optionOrder = append(optionOrder, name+" after")
				return err
			}
		}
	}
	optionWriter := newWriter(jwks.WithWriterRuntimeOptions(option("runtime")))

	// assertions
	assertWritten := func(t *testing.T, carrierWriter http.ResponseWriter, err error) {
		if err != nil {
			t.Fatalf("WriteArtifact() error = %v", err)
		}
		recorder := carrierWriter.(*httptest.ResponseRecorder)
		response := recorder.Result()
		if response.StatusCode != http.StatusOK {
			t.Errorf("WriteArtifact() status = %d, want %d", response.StatusCode, http.StatusOK)
		}
		if got := response.Header.Get("Content-Type"); got != "application/jwk-set+json" {
			t.Errorf("WriteArtifact() Content-Type = %q, want %q", got, "application/jwk-set+json")
		}
		if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("WriteArtifact() X-Content-Type-Options = %q, want %q", got, "nosniff")
		}
		var document struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
			t.Fatalf("standard library JSON decoding failed: %v", err)
		}
		if len(document.Keys) != 1 {
			t.Fatalf("WriteArtifact() key count = %d, want 1", len(document.Keys))
		}
		if got := document.Keys[0]["kid"]; got != publicKey.ID() {
			t.Errorf("WriteArtifact() kid = %v, want %q", got, publicKey.ID())
		}
		if _, ok := document.Keys[0]["d"]; ok {
			t.Error("WriteArtifact() exposed private key material")
		}
	}
	assertCategory := func(category error) func(*testing.T, http.ResponseWriter, error) {
		return func(t *testing.T, carrierWriter http.ResponseWriter, err error) {
			if !errors.Is(err, category) {
				t.Errorf("WriteArtifact() error = %v, want category %v", err, category)
			}
		}
	}
	assertCause := func(category, cause error) func(*testing.T, http.ResponseWriter, error) {
		return func(t *testing.T, carrierWriter http.ResponseWriter, err error) {
			if !errors.Is(err, category) {
				t.Errorf("WriteArtifact() error = %v, want category %v", err, category)
			}
			if !errors.Is(err, cause) {
				t.Errorf("WriteArtifact() error = %v, want preserved cause %v", err, cause)
			}
		}
	}
	assertOptions := func(t *testing.T, carrierWriter http.ResponseWriter, err error) {
		assertWritten(t, carrierWriter, err)
		want := []string{"runtime before", "call before", "call after", "runtime after"}
		if !reflect.DeepEqual(optionOrder, want) {
			t.Errorf("WriteArtifact() option order = %v, want %v", optionOrder, want)
		}
	}
	tests := []struct {
		name          string
		writer        vapi.Writer[http.ResponseWriter, *jwks.JWKS[key.Key], jwks.WriterOption]
		carrierWriter http.ResponseWriter
		artifact      *jwks.JWKS[key.Key]
		options       []jwks.WriterOption
		assertion     func(*testing.T, http.ResponseWriter, error)
	}{
		{name: "JWKS", writer: defaultWriter, carrierWriter: httptest.NewRecorder(), artifact: artifact, assertion: assertWritten},
		{name: "Nil Writer", writer: (*jwks.Writer)(nil), carrierWriter: httptest.NewRecorder(), artifact: artifact, assertion: assertCategory(vapi.ErrMisconfigured)},
		{name: "Nil Response Writer", writer: defaultWriter, artifact: artifact, assertion: assertCategory(vapi.ErrMalformed)},
		{name: "Nil JWKS", writer: defaultWriter, carrierWriter: httptest.NewRecorder(), assertion: assertCategory(vapi.ErrMalformed)},
		{name: "Nil Keys", writer: defaultWriter, carrierWriter: httptest.NewRecorder(), artifact: &jwks.JWKS[key.Key]{}, assertion: assertCategory(vapi.ErrMalformed)},
		{name: "No Keys", writer: defaultWriter, carrierWriter: httptest.NewRecorder(), artifact: &jwks.JWKS[key.Key]{Keys: []key.Key{}}, assertion: assertCategory(vapi.ErrMalformed)},
		{name: "Encoding Failure", writer: encodeFailingWriter, carrierWriter: httptest.NewRecorder(), artifact: artifact, assertion: assertCause(vapi.ErrInternal, encodeFailure)},
		{name: "Response Write Failure", writer: defaultWriter, carrierWriter: &errorResponseWriter{header: make(http.Header), err: writeFailure}, artifact: artifact, assertion: assertCause(vapi.ErrInternal, writeFailure)},
		{name: "Nil Option", writer: defaultWriter, carrierWriter: httptest.NewRecorder(), artifact: artifact, options: []jwks.WriterOption{nil}, assertion: assertCategory(vapi.ErrMisconfigured)},
		{name: "Option Returning Nil", writer: defaultWriter, carrierWriter: httptest.NewRecorder(), artifact: artifact, options: []jwks.WriterOption{func(jwks.WriteFunc) jwks.WriteFunc { return nil }}, assertion: assertCategory(vapi.ErrMisconfigured)},
		{name: "Runtime And Call Options", writer: optionWriter, carrierWriter: httptest.NewRecorder(), artifact: artifact, options: []jwks.WriterOption{option("call")}, assertion: assertOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.writer.WriteArtifact(context.Background(), tt.carrierWriter, tt.artifact, tt.options...)
			tt.assertion(t, tt.carrierWriter, err)
		})
	}
}
