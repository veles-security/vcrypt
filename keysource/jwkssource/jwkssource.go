package jwkssource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Source loads keys from a remote JSON Web Key Set endpoint and periodically
// publishes changed sets through its refresh callback.
type Source struct {
	id        string
	url       string
	frequency time.Duration
	client    *http.Client
	decoder   vapi.Decoder[descriptor.JWKS[key.KeyCandidate], key.JOSEDecodeOption]
	allowHTTP bool

	loadMu sync.Mutex
	mu     sync.Mutex

	callback func([]key.KeyCandidate) error
	started  bool
	snapshot string
}

// ID implements [keysource.Source].
func (s *Source) ID() string { return s.id }

// Load retrieves and decodes the current JSON Web Key Set.
func (s *Source) Load() ([]key.KeyCandidate, error) {
	keys, snapshot, err := s.load(context.Background())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.snapshot = snapshot
	s.startLocked()
	s.mu.Unlock()
	return keys, nil
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
	if s.started || s.callback == nil || s.snapshot == "" {
		return
	}
	s.started = true
	go s.watch()
}

func (s *Source) watch() {
	ticker := time.NewTicker(s.frequency)
	defer ticker.Stop()
	for range ticker.C {
		keys, snapshot, err := s.load(context.Background())
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
	response, err := s.client.Do(request)
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

var _ keysource.SelfRefreshingSource = (*Source)(nil)
