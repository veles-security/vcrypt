package keysource

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keybuilder"
	"github.com/veles-security/vcrypt/material"
)

const defaultFilePollInterval = time.Second

// FileOption configures a file source.
type FileOption func(*fileSource) error

// WithFileMonitoring enables or disables automatic refresh. Monitoring uses a
// lightweight content snapshot, so it also detects atomic file replacement.
func WithFileMonitoring(enabled bool) FileOption {
	return func(source *fileSource) error {
		source.monitor = enabled
		return nil
	}
}

// WithFilePollInterval changes how often a monitored source is checked.
func WithFilePollInterval(interval time.Duration) FileOption {
	return func(source *fileSource) error {
		if interval <= 0 {
			return fmt.Errorf("file source poll interval must be positive")
		}
		source.pollInterval = interval
		return nil
	}
}

// WithFileCandidate configures metadata copied to every key candidate. ID and
// Source are supplied by the file source unless explicitly set in the template.
func WithFileCandidate(candidate key.KeyCandidate) FileOption {
	return func(source *fileSource) error {
		source.candidate = candidate
		return nil
	}
}

type fileSource struct {
	id           string
	path         string
	monitor      bool
	pollInterval time.Duration
	candidate    key.KeyCandidate

	mu       sync.Mutex
	callback func([]key.Key) error
	started  bool
	snapshot string
}

// NewFileSource creates a source for either one PEM/DER file or all regular
// files directly inside a directory.
func NewFileSource(id, path string, options ...FileOption) (*fileSource, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("file source ID is empty")
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("file source path is empty")
	}
	source := &fileSource{id: id, path: filepath.Clean(path), pollInterval: defaultFilePollInterval}
	for _, option := range options {
		if option != nil {
			if err := option(source); err != nil {
				return nil, err
			}
		}
	}
	return source, nil
}

func (f *fileSource) ID() string { return f.id }

func (f *fileSource) Load() ([]key.Key, error) {
	keys, snapshot, err := f.load()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.snapshot = snapshot
	f.startMonitorLocked()
	f.mu.Unlock()
	return keys, nil
}

func (f *fileSource) SetRefreshCallback(callback func([]key.Key) error) {
	f.mu.Lock()
	f.callback = callback
	f.startMonitorLocked()
	f.mu.Unlock()
}

func (f *fileSource) startMonitorLocked() {
	if !f.monitor || f.started || f.callback == nil || f.snapshot == "" {
		return
	}
	f.started = true
	go f.watch()
}

func (f *fileSource) watch() {
	ticker := time.NewTicker(f.pollInterval)
	defer ticker.Stop()
	for range ticker.C {
		keys, snapshot, err := f.load()
		if err != nil {
			continue // a transient partial write must not evict usable keys
		}
		f.mu.Lock()
		if snapshot == f.snapshot {
			f.mu.Unlock()
			continue
		}
		callback := f.callback
		f.mu.Unlock()
		if callback == nil || callback(keys) != nil {
			continue
		}
		f.mu.Lock()
		f.snapshot = snapshot
		f.mu.Unlock()
	}
}

func (f *fileSource) load() ([]key.Key, string, error) {
	files, err := sourceFiles(f.path)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.New()
	keys := make([]key.Key, 0, len(files))
	for _, path := range files {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("read key file %q: %w", path, err)
		}
		hash.Write([]byte(path))
		hash.Write([]byte{0})
		hash.Write(encoded)
		loaded, err := f.decode(path, encoded)
		if err != nil {
			return nil, "", err
		}
		keys = append(keys, loaded...)
	}
	return keys, hex.EncodeToString(hash.Sum(nil)), nil
}

func sourceFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat file source %q: %w", path, err)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("file source %q is not a regular file", path)
		}
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read file source directory %q: %w", path, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			files = append(files, filepath.Join(path, entry.Name()))
		} else if entry.Type()&fs.ModeSymlink != 0 {
			info, err := entry.Info()
			if err == nil && info.Mode().IsRegular() {
				files = append(files, filepath.Join(path, entry.Name()))
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

func (f *fileSource) decode(path string, encoded []byte) ([]key.Key, error) {
	var blocks []*pem.Block
	rest := encoded
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		rest = next
	}
	if len(blocks) == 0 {
		blocks = []*pem.Block{{Bytes: encoded}}
	} else if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("decode key file %q: data found outside PEM blocks", path)
	}

	result := make([]key.Key, 0, len(blocks))
	for i, block := range blocks {
		candidate := f.candidate
		candidate.Restrictions = append([]key.Capability(nil), f.candidate.Restrictions...)
		candidate.Source = firstNonEmpty(candidate.Source, f.id)
		candidate.ID = firstNonEmpty(candidate.ID, fileKeyID(path, i, len(blocks)))
		if candidate.Status == "" {
			candidate.Status = key.KeyStatusActive
		}
		parsed, err := parseMaterial(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("decode key file %q block %d: %w", path, i+1, err)
		}
		candidate.Material = parsed
		built, err := keybuilder.Build(candidate)
		if err != nil {
			return nil, fmt.Errorf("build key from %q block %d: %w", path, i+1, err)
		}
		result = append(result, *built)
	}
	return result, nil
}

func parseMaterial(der []byte) (material.Material, error) {
	if cert, err := x509.ParseCertificate(der); err == nil {
		return &material.CertificateMaterial{Cert: cert}, nil
	}
	if privateKey, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return privateMaterial(privateKey)
	}
	if privateKey, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return &material.PrivateMaterial{Key: privateKey}, nil
	}
	if privateKey, err := x509.ParseECPrivateKey(der); err == nil {
		return &material.PrivateMaterial{Key: privateKey}, nil
	}
	if publicKey, err := x509.ParsePKIXPublicKey(der); err == nil {
		return publicMaterial(publicKey)
	}
	if publicKey, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return &material.PublicMaterial{Key: publicKey}, nil
	}
	return nil, errors.New("unsupported private key, public key, or certificate encoding")
}

func privateMaterial(value any) (material.Material, error) {
	if _, ok := value.(crypto.PrivateKey); !ok {
		return nil, fmt.Errorf("unsupported private key type %T", value)
	}
	return &material.PrivateMaterial{Key: value}, nil
}

func publicMaterial(value any) (material.Material, error) {
	if _, ok := value.(crypto.PublicKey); !ok {
		return nil, fmt.Errorf("unsupported public key type %T", value)
	}
	return &material.PublicMaterial{Key: value}, nil
}

func fileKeyID(path string, index, count int) string {
	id := filepath.Base(path)
	if count > 1 {
		return fmt.Sprintf("%s#%d", id, index+1)
	}
	return id
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

var _ SelfRefreshingSource = (*fileSource)(nil)
