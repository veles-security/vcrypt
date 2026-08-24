package jwkssource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/descriptor"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource"
)

const maximumJWKSSize = 10 << 20

// ErrClosed is returned when a load is attempted after the source is closed.
var ErrClosed = errors.New("JWKS source is closed")

// Source loads keys from a remote JSON Web Key Set endpoint and periodically
// publishes changed sets through its refresh callback.
type Source struct {
	id         string
	url        string
	frequency  time.Duration
	client     *http.Client
	ownsClient bool
	decoder    vapi.Decoder[descriptor.JWKS[key.KeyCandidate], key.JOSEDecodeOption]
	allowHTTP  bool
	ctx        context.Context
	cancel     context.CancelFunc

	loadMu sync.Mutex
	mu     sync.Mutex

	callback func([]key.KeyCandidate) error
	started  bool
	closed   bool
	snapshot string
}

// ID implements [keysource.Source].
func (s *Source) ID() string { return s.id }

// Load retrieves and decodes the current JSON Web Key Set. Closing the source
// also cancels the load.
func (s *Source) Load(ctx context.Context) ([]key.KeyCandidate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("load JWKS: nil context")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	lifecycleContext := s.ctx
	s.mu.Unlock()

	requestContext, cancel := context.WithCancel(ctx)
	defer cancel()
	if lifecycleContext != nil {
		stop := context.AfterFunc(lifecycleContext, cancel)
		defer stop()
	}
	keys, snapshot, err := s.load(requestContext)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	s.snapshot = snapshot
	s.startLocked()
	s.mu.Unlock()
	return keys, nil
}

// Close stops periodic refresh and cancels in-flight HTTP requests. It is safe
// to call Close multiple times.
func (s *Source) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if s.ownsClient && s.client != nil {
		s.client.CloseIdleConnections()
	}
	return nil
}

// SetRefreshCallback supplies the callback used to replace keys after the
// endpoint publishes a changed JSON Web Key Set.
func (s *Source) SetRefreshCallback(callback func([]key.KeyCandidate) error) {
	s.mu.Lock()
	s.callback = callback
	s.startLocked()
	s.mu.Unlock()
}

func (s *Source) startLocked() {
	if s.closed || s.started || s.callback == nil || s.snapshot == "" {
		return
	}
	s.started = true
	go s.watch()
}

func (s *Source) watch() {
	ticker := time.NewTicker(s.frequency)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		keys, snapshot, err := s.load(s.ctx)
		if err != nil {
			continue
		}
		s.mu.Lock()
		if snapshot == s.snapshot {
			s.mu.Unlock()
			continue
		}
		callback := s.callback
		s.mu.Unlock()
		if callback == nil || callback(keys) != nil {
			continue
		}
		s.mu.Lock()
		s.snapshot = snapshot
		s.mu.Unlock()
	}
}

func (s *Source) load(ctx context.Context) ([]key.KeyCandidate, string, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create JWKS request: %w", err)
	}
	request.Header.Set("Accept", "application/jwk-set+json, application/json")
	client := *s.client
	client.CheckRedirect = s.checkRedirect
	response, err := client.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("request JWKS %q: %w", s.url, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return nil, "", fmt.Errorf("request JWKS %q: unexpected HTTP status %s", s.url, response.Status)
	}

	encoded, err := io.ReadAll(io.LimitReader(response.Body, maximumJWKSSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("read JWKS %q: %w", s.url, err)
	}
	if len(encoded) > maximumJWKSSize {
		return nil, "", fmt.Errorf("read JWKS %q: response exceeds %d bytes", s.url, maximumJWKSSize)
	}
	artifact, err := s.decoder.Decode(ctx, encoded)
	if err != nil {
		return nil, "", fmt.Errorf("decode JWKS %q: %w", s.url, err)
	}
	for i := range artifact.Keys {
		if artifact.Keys[i].Source == "" {
			artifact.Keys[i].Source = s.id
		}
		if artifact.Keys[i].Status == "" {
			artifact.Keys[i].Status = key.KeyStatusActive
		}
	}
	digest := sha256.Sum256(encoded)
	return artifact.Keys, hex.EncodeToString(digest[:]), nil
}

func (s *Source) checkRedirect(request *http.Request, via []*http.Request) error {
	if request.URL.Scheme != "https" && !s.allowHTTP {
		return fmt.Errorf("JWKS source redirect to insecure URL %q is not permitted", request.URL.String())
	}
	if s.client.CheckRedirect != nil {
		return s.client.CheckRedirect(request, via)
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

var _ keysource.SelfRefreshingSource = (*Source)(nil)
