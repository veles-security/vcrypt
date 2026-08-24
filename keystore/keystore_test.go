package keystore

import (
	"errors"
	"testing"

	"github.com/veles-security/vcrypt/material"
)

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
	tests := []struct {
		name      string
		source    *selfRefreshingSourceStub
		assertion func(*testing.T, *selfRefreshingSourceStub, error)
	}{
		{name: "Success Activates Source", source: &selfRefreshingSourceStub{id: "success"}, assertion: assertActivated},
		{name: "Load Failure Leaves Source Inactive", source: &selfRefreshingSourceStub{id: "failure", loadErr: loadErr}, assertion: assertNotActivated},
		{name: "Build Failure Leaves Source Inactive", source: &selfRefreshingSourceStub{id: "failure", candidateMaterial: &material.PublicMaterial{}}, assertion: assertNotActivated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := New()
			if err != nil {
				t.Fatal(err)
			}
			gotErr := store.Bind(tt.source)
			tt.assertion(t, tt.source, gotErr)
		})
	}
}
