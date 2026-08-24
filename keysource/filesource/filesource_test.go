package filesource

import (
	"context"
	"errors"
	"testing"
)

func Test_fileSource_Close(t *testing.T) {
	source, err := New("keys", "unused")
	if err != nil {
		t.Fatal(err)
	}
	assertClosed := func(t *testing.T, err error) {
		if err != nil {
			t.Errorf("Close() error = %v", err)
		}
		if _, err := source.Load(context.Background()); !errors.Is(err, ErrClosed) {
			t.Errorf("Load() after Close error = %v, want ErrClosed", err)
		}
	}
	assertIdempotent := func(t *testing.T, err error) {
		if err != nil {
			t.Errorf("second Close() error = %v", err)
		}
	}
	tests := []struct {
		name      string
		assertion func(*testing.T, error)
	}{
		{name: "Closed", assertion: assertClosed},
		{name: "Idempotent", assertion: assertIdempotent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, source.Close())
		})
	}
}
