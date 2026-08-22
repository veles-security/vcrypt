package jwkssource

import (
	"net/http"
	"testing"
	"time"
)

func Test_WithHTTPClient(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	assertClient := func(t *testing.T, source *Source, err error) {
		if err != nil {
			t.Fatalf("option error = %v", err)
		}
		if source.client != client {
			t.Errorf("configured client = %p, want %p", source.client, client)
		}
	}
	assertError := func(t *testing.T, _ *Source, err error) {
		if err == nil {
			t.Errorf("option error = nil, want error")
		}
	}
	tests := []struct {
		name      string
		option    Option
		assertion func(*testing.T, *Source, error)
	}{
		{name: "Client", option: WithHTTPClient(client), assertion: assertClient},
		{name: "Nil Client", option: WithHTTPClient(nil), assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &Source{}
			err := tt.option(source)
			tt.assertion(t, source, err)
		})
	}
}

func Test_New(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	assertSource := func(t *testing.T, source *Source, err error) {
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if source.id != "issuer" || source.url != "https://issuer.example/jwks" || source.frequency != time.Minute {
			t.Errorf("New() source = %#v", source)
		}
		if source.client != client || source.decoder == nil {
			t.Errorf("New() dependencies were not configured")
		}
	}
	assertError := func(t *testing.T, source *Source, err error) {
		if err == nil || source != nil {
			t.Errorf("New() = (%v, %v), want (nil, error)", source, err)
		}
	}
	tests := []struct {
		name      string
		id        string
		url       string
		frequency time.Duration
		options   []Option
		assertion func(*testing.T, *Source, error)
	}{
		{name: "Source", id: "issuer", url: "https://issuer.example/jwks", frequency: time.Minute, options: []Option{nil, WithHTTPClient(client)}, assertion: assertSource},
		{name: "Empty ID", url: "https://issuer.example/jwks", frequency: time.Minute, assertion: assertError},
		{name: "Empty URL", id: "issuer", frequency: time.Minute, assertion: assertError},
		{name: "Relative URL", id: "issuer", url: "/jwks", frequency: time.Minute, assertion: assertError},
		{name: "Unsupported URL Scheme", id: "issuer", url: "file:///tmp/jwks", frequency: time.Minute, assertion: assertError},
		{name: "Zero Frequency", id: "issuer", url: "https://issuer.example/jwks", assertion: assertError},
		{name: "Invalid Option", id: "issuer", url: "https://issuer.example/jwks", frequency: time.Minute, options: []Option{WithHTTPClient(nil)}, assertion: assertError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := New(tt.id, tt.url, tt.frequency, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}
