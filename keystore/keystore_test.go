package keystore

import (
	"errors"
	"testing"

	"github.com/veles-security/vcrypt/material"
)

func Test_store_Close(t *testing.T) {
	closeErr := errors.New("close failed")
	assertClosed := func(t *testing.T, store Keystore, sources ...*selfRefreshingSourceStub) {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		for _, source := range sources {
			if !source.closed {
				t.Errorf("source %q was not closed", source.id)
			}
			if source.callback != nil {
				t.Errorf("source %q callback was not detached", source.id)
			}
		}
	}
	assertError := func(t *testing.T, store Keystore, sources ...*selfRefreshingSourceStub) {
		if err := store.Close(); !errors.Is(err, closeErr) {
			t.Errorf("Close() error = %v, want %v", err, closeErr)
		}
		for _, source := range sources {
			if !source.closed {
				t.Errorf("source %q was not closed", source.id)
			}
		}
	}
	tests := []struct {
		name      string
		sources   []*selfRefreshingSourceStub
		assertion func(*testing.T, Keystore, ...*selfRefreshingSourceStub)
	}{
		{name: "No Sources", assertion: assertClosed},
		{name: "All Sources", sources: []*selfRefreshingSourceStub{{id: "first"}, {id: "second"}}, assertion: assertClosed},
		{name: "Close Error Does Not Stop Other Sources", sources: []*selfRefreshingSourceStub{{id: "first", closeErr: closeErr}, {id: "second"}}, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := make([]Option, 0, len(tt.sources))
			for _, source := range tt.sources {
				options = append(options, WithSource(source, nil))
			}
			store, err := New(options...)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			tt.assertion(t, store, tt.sources...)
		})
	}
}

func Test_store_Bind(t *testing.T) {
	loadErr := errors.New("load failed")
	assertActivated := func(t *testing.T, source *selfRefreshingSourceStub, err error) {
		if err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		if source.callback == nil {
			t.Error("source callback = nil, want activated")
		}
	}
	assertNotActivated := func(t *testing.T, source *selfRefreshingSourceStub, err error) {
		if err == nil {
			t.Fatal("Bind() error = nil, want error")
		}
		if source.callback != nil {
			t.Error("source callback was activated after bind failure")
		}
	}
	assertClosed := func(t *testing.T, source *selfRefreshingSourceStub, err error) {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Bind() error = %v, want %v", err, ErrClosed)
		}
		if source.callback != nil {
			t.Error("source callback was activated after store closure")
		}
	}
	tests := []struct {
		name      string
		source    *selfRefreshingSourceStub
		close     bool
		assertion func(*testing.T, *selfRefreshingSourceStub, error)
	}{
		{name: "Success Activates Source", source: &selfRefreshingSourceStub{id: "success"}, assertion: assertActivated},
		{name: "Load Failure Leaves Source Inactive", source: &selfRefreshingSourceStub{id: "failure", loadErr: loadErr}, assertion: assertNotActivated},
		{name: "Build Failure Leaves Source Inactive", source: &selfRefreshingSourceStub{id: "failure", candidateMaterial: &material.PublicMaterial{}}, assertion: assertNotActivated},
		{name: "Closed Store", source: &selfRefreshingSourceStub{id: "closed"}, close: true, assertion: assertClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := New()
			if err != nil {
				t.Fatal(err)
			}
			if tt.close {
				if err := store.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			}
			gotErr := store.Bind(tt.source)
			tt.assertion(t, tt.source, gotErr)
		})
	}
}

func Test_store_RefreshAll(t *testing.T) {
	assertSuccess := func(t *testing.T, store Keystore) {
		if err := store.RefreshAll(); err != nil {
			t.Errorf("RefreshAll() error = %v", err)
		}
	}
	assertClosed := func(t *testing.T, store Keystore) {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if err := store.RefreshAll(); !errors.Is(err, ErrClosed) {
			t.Errorf("RefreshAll() error = %v, want %v", err, ErrClosed)
		}
	}
	tests := []struct {
		name      string
		assertion func(*testing.T, Keystore)
	}{
		{name: "Open Store", assertion: assertSuccess},
		{name: "Closed Store", assertion: assertClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := New()
			if err != nil {
				t.Fatal(err)
			}
			tt.assertion(t, store)
		})
	}
}
