package keystore

import (
	"context"
	"errors"
	"testing"

	_ "github.com/veles-security/vcrypt/backend/symetric"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type selfRefreshingSourceStub struct {
	id                string
	loadErr           error
	candidateMaterial material.Material
	callback          func([]key.KeyCandidate) error
	closeErr          error
	closed            bool
}

func (s *selfRefreshingSourceStub) ID() string { return s.id }

func (s *selfRefreshingSourceStub) Load(context.Context) ([]key.KeyCandidate, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	candidateMaterial := s.candidateMaterial
	if candidateMaterial == nil {
		candidateMaterial = &material.SymmetricMaterial{Key: make([]byte, 32)}
	}
	return []key.KeyCandidate{{
		ID:       s.id + "-key",
		Source:   s.id,
		Status:   key.KeyStatusActive,
		Material: candidateMaterial,
	}}, nil
}

func (s *selfRefreshingSourceStub) Close() error {
	s.closed = true
	return s.closeErr
}

func (s *selfRefreshingSourceStub) SetRefreshCallback(callback func([]key.KeyCandidate) error) {
	s.callback = callback
}

func Test_New(t *testing.T) {
	loadErr := errors.New("load failed")
	optionErr := errors.New("option failed")
	assertActivated := func(t *testing.T, store Store, err error, sources ...*selfRefreshingSourceStub) {
		if err != nil || store == nil {
			t.Fatalf("New() = (%v, %v), want store", store, err)
		}
		for _, source := range sources {
			if source.callback == nil {
				t.Errorf("source %q callback = nil, want activated", source.id)
			}
		}
	}
	assertNotActivated := func(t *testing.T, store Store, err error, sources ...*selfRefreshingSourceStub) {
		if err == nil || store != nil {
			t.Fatalf("New() = (%v, %v), want (nil, error)", store, err)
		}
		for _, source := range sources {
			if source.callback != nil {
				t.Errorf("source %q callback was activated after construction failure", source.id)
			}
			if !source.closed {
				t.Errorf("source %q was not closed after construction failure", source.id)
			}
		}
	}
	tests := []struct {
		name      string
		sources   []*selfRefreshingSourceStub
		options   []Option
		assertion func(*testing.T, Store, error, ...*selfRefreshingSourceStub)
	}{
		{name: "No Options", assertion: assertActivated},
		{name: "Successful Sources Activated", sources: []*selfRefreshingSourceStub{{id: "first"}, {id: "second"}}, assertion: assertActivated},
		{name: "Nil Option Ignored", options: []Option{nil}, assertion: assertActivated},
		{name: "Option Failure", options: []Option{func(*store) error { return optionErr }}, assertion: assertNotActivated},
		{name: "Load Failure Leaves Sources Inactive", sources: []*selfRefreshingSourceStub{{id: "first"}, {id: "second", loadErr: loadErr}}, assertion: assertNotActivated},
		{name: "Build Failure Leaves Sources Inactive", sources: []*selfRefreshingSourceStub{{id: "first"}, {id: "second", candidateMaterial: &material.PublicMaterial{}}}, assertion: assertNotActivated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := append([]Option(nil), tt.options...)
			for _, source := range tt.sources {
				options = append(options, WithSource(source, nil))
			}
			got, gotErr := New(options...)
			tt.assertion(t, got, gotErr, tt.sources...)
		})
	}
}

func Test_WithSource(t *testing.T) {
	sourceErr := errors.New("source construction failed")
	assertValid := func(t *testing.T, store Store, err error) {
		if err != nil || store == nil {
			t.Fatalf("New() = (%v, %v), want store", store, err)
		}
	}
	assertError := func(t *testing.T, store Store, err error) {
		if err == nil || store != nil {
			t.Fatalf("New() = (%v, %v), want (nil, error)", store, err)
		}
	}
	tests := []struct {
		name      string
		options   []Option
		assertion func(*testing.T, Store, error)
	}{
		{name: "Source", options: []Option{WithSource(&selfRefreshingSourceStub{id: "first"}, nil)}, assertion: assertValid},
		{name: "Source And Nil Constructor Error", options: []Option{WithSource(&selfRefreshingSourceStub{id: "first"}, nil)}, assertion: assertValid},
		{name: "Constructor Error", options: []Option{WithSource(nil, sourceErr)}, assertion: assertError},
		{name: "Nil Source", options: []Option{WithSource(nil, nil)}, assertion: assertError},
		{name: "Empty Source ID", options: []Option{WithSource(&selfRefreshingSourceStub{id: " "}, nil)}, assertion: assertError},
		{name: "Duplicate Source ID", options: []Option{WithSource(&selfRefreshingSourceStub{id: "same"}, nil), WithSource(&selfRefreshingSourceStub{id: "same"}, nil)}, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := New(tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
