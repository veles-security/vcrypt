package filesource

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/veles-security/vcrypt/key"
)

// Option configures a file source.
type Option func(*fileSource) error

// WithFileMonitoring enables or disables automatic refresh. Monitoring uses a
// lightweight content snapshot, so it also detects atomic file replacement.
func WithFileMonitoring(enabled bool) Option {
	return func(source *fileSource) error {
		source.monitor = enabled
		return nil
	}
}

// WithFilePollInterval changes how often a monitored source is checked.
func WithFilePollInterval(interval time.Duration) Option {
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
func WithFileCandidate(candidate key.KeyCandidate) Option {
	return func(source *fileSource) error {
		source.candidate = candidate
		return nil
	}
}

// New creates a source for either one PEM/DER file or all regular
// files directly inside a directory.
func New(id, path string, options ...Option) (*fileSource, error) {
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
