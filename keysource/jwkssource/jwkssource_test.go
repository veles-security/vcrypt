package jwkssource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/veles-security/vcrypt/backend/rsa"
	"github.com/veles-security/vcrypt/key"
)

const rsaJWK = `{"kty":"RSA","kid":%q,"n":"x457suHRD7n8qToSDmZjxRLT2qdJpWy3qKfUmh10t-kcRgsgBMeaA9vbAgpZu8CG33ory3nZGt9gw3Q0OKJ9SMwe0SLzOgpzzPM7dhniJc2DxxLaBSAqvlQ2STaa7JABwfiNNcrTA0QLQ8kwdpVoWwiR7kYXlPwgIEMghsSE7GyLUzsIxAND7bq2z5t3RwLiZgaS5WWbb5ltc-mreO7vE0NtUlDTx3UWn8FxlmiNbi6DaCThezYsENZRI0yOIjxitFQ1wxJd7U0GgAS_LmrQQBjV8fGGfYOzazuKwIcEt0PQn54ULM9RQypjVPpfgJdUMlkLqxK2nWu09Mhr-CGNkQ","e":"AQAB"}`

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jwks(id string) string {
	return fmt.Sprintf(`{"keys":[%s]}`, fmt.Sprintf(rsaJWK, id))
}

func Test_Source_ID(t *testing.T) {
	source := &Source{id: "issuer"}
	tests := []struct {
		name string
		want string
	}{
		{name: "ID", want: "issuer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := source.ID(); got != tt.want {
				t.Errorf("ID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_Source_Load(t *testing.T) {
	assertKeys := func(t *testing.T, keys []key.KeyCandidate, err error) {
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if len(keys) != 1 || keys[0].ID != "key-1" {
			t.Fatalf("Load() keys = %#v, want key-1", keys)
		}
		if keys[0].Source != "issuer" || keys[0].Status != key.KeyStatusActive {
			t.Errorf("Load() metadata = (source %q, status %q), want (issuer, active)", keys[0].Source, keys[0].Status)
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, []key.KeyCandidate, error) {
		return func(t *testing.T, keys []key.KeyCandidate, err error) {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Load() error = %v, want error containing %q", err, want)
			}
			if keys != nil {
				t.Errorf("Load() keys = %#v, want nil", keys)
			}
		}
	}
	tests := []struct {
		name      string
		status    int
		body      string
		assertion func(*testing.T, []key.KeyCandidate, error)
	}{
		{name: "JWKS", status: http.StatusOK, body: jwks("key-1"), assertion: assertKeys},
		{name: "HTTP Error", status: http.StatusServiceUnavailable, body: "unavailable", assertion: assertErrorContaining("503")},
		{name: "Malformed JWKS", status: http.StatusOK, body: `{"keys":[`, assertion: assertErrorContaining("decode JWKS")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tt.status,
					Status:     fmt.Sprintf("%d %s", tt.status, http.StatusText(tt.status)),
					Body:       io.NopCloser(strings.NewReader(tt.body)),
					Header:     make(http.Header),
					Request:    request,
				}, nil
			})}
			source, err := New("issuer", "https://issuer.example/jwks", time.Hour, WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			got, gotErr := source.Load(context.Background())
			tt.assertion(t, got, gotErr)
		})
	}
	t.Run("Cancellation", testSourceLoadCancellation)
}

func testSourceLoadCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	assertCanceled := func(t *testing.T, keys []key.KeyCandidate, err error) {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Load() error = %v, want context.Canceled", err)
		}
		if keys != nil {
			t.Errorf("Load() keys = %#v, want nil", keys)
		}
	}
	assertNilContext := func(t *testing.T, keys []key.KeyCandidate, err error) {
		if err == nil || keys != nil {
			t.Errorf("Load() = (%#v, %v), want (nil, error)", keys, err)
		}
	}
	tests := []struct {
		name      string
		ctx       context.Context
		cancel    bool
		assertion func(*testing.T, []key.KeyCandidate, error)
	}{
		{name: "Canceled Request", ctx: context.Background(), cancel: true, assertion: assertCanceled},
		{name: "Nil Context", ctx: nil, assertion: assertNilContext},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := New("issuer", "https://issuer.example/jwks", time.Hour, WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			ctx := tt.ctx
			var cancel context.CancelFunc
			if tt.cancel {
				ctx, cancel = context.WithCancel(ctx)
				go func() {
					<-started
					cancel()
				}()
			}
			got, gotErr := source.Load(ctx)
			tt.assertion(t, got, gotErr)
		})
	}
}

func Test_Source_Close(t *testing.T) {
	started := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	source, err := New("issuer", "https://issuer.example/jwks", time.Hour, WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	loadResult := make(chan error, 1)
	go func() {
		_, err := source.Load(context.Background())
		loadResult <- err
	}()
	<-started

	assertClosed := func(t *testing.T, closeErr, loadErr error) {
		if closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
		if !errors.Is(loadErr, context.Canceled) && !errors.Is(loadErr, ErrClosed) {
			t.Errorf("in-flight Load() error = %v, want cancellation", loadErr)
		}
		if _, err := source.Load(context.Background()); !errors.Is(err, ErrClosed) {
			t.Errorf("Load() after Close error = %v, want ErrClosed", err)
		}
	}
	assertIdempotent := func(t *testing.T, closeErr, _ error) {
		if closeErr != nil {
			t.Errorf("second Close() error = %v", closeErr)
		}
	}
	tests := []struct {
		name      string
		close     func() error
		load      func() error
		assertion func(*testing.T, error, error)
	}{
		{name: "Cancel In-flight Load", close: source.Close, load: func() error { return <-loadResult }, assertion: assertClosed},
		{name: "Idempotent", close: source.Close, load: func() error { return nil }, assertion: assertIdempotent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.close(), tt.load())
		})
	}
}

func Test_Source_SetRefreshCallback(t *testing.T) {
	var mu sync.RWMutex
	body := jwks("key-1")
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.RLock()
		defer mu.RUnlock()
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	source, err := New("issuer", "https://issuer.example/jwks", 10*time.Millisecond, WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	refreshed := make(chan []key.KeyCandidate, 1)
	source.SetRefreshCallback(func(keys []key.KeyCandidate) error {
		refreshed <- keys
		return nil
	})
	mu.Lock()
	body = jwks("key-2")
	mu.Unlock()

	tests := []struct {
		name      string
		assertion func(*testing.T)
	}{
		{name: "Changed JWKS", assertion: func(t *testing.T) {
			select {
			case keys := <-refreshed:
				if len(keys) != 1 || keys[0].ID != "key-2" || keys[0].Source != "issuer" || keys[0].Status != key.KeyStatusActive {
					t.Errorf("refresh keys = %#v", keys)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for JWKS refresh")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.assertion)
	}
}
