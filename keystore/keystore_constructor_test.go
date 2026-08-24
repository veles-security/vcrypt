package keystore

import (
	"context"
	"errors"
	"testing"

	_ "github.com/veles-security/vcrypt/backend/symetric"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource"
	"github.com/veles-security/vcrypt/material"
)

type selfRefreshingSourceStub struct {
	id                string
	loadErr           error
	candidateMaterial material.Material
	callback          func([]key.KeyCandidate) error
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

func (s *selfRefreshingSourceStub) Close() error { return nil }

func (s *selfRefreshingSourceStub) SetRefreshCallback(callback func([]key.KeyCandidate) error) {
	s.callback = callback
}

func Test_New(t *testing.T) {
	loadErr := errors.New("load failed")
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
		}
	}
	tests := []struct {
		name      string
		sources   []*selfRefreshingSourceStub
		assertion func(*testing.T, Store, error, ...*selfRefreshingSourceStub)
	}{
		{name: "Successful Sources Activated", sources: []*selfRefreshingSourceStub{{id: "first"}, {id: "second"}}, assertion: assertActivated},
		{name: "Load Failure Leaves Sources Inactive", sources: []*selfRefreshingSourceStub{{id: "first"}, {id: "second", loadErr: loadErr}}, assertion: assertNotActivated},
		{name: "Build Failure Leaves Sources Inactive", sources: []*selfRefreshingSourceStub{{id: "first"}, {id: "second", candidateMaterial: &material.PublicMaterial{}}}, assertion: assertNotActivated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources := make([]keysource.Source, len(tt.sources))
			for i := range tt.sources {
				sources[i] = tt.sources[i]
			}
			got, gotErr := New(sources...)
			tt.assertion(t, got, gotErr, tt.sources...)
		})
	}
}
