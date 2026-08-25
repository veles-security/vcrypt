package keystore

import (
	"fmt"
	"strings"

	"github.com/veles-security/vcrypt/keysource"
)

// Option configures a Store during construction.
type Option func(*store) error

// WithSource adds a key source to the store. The error allows the
// result of a source constructor to be passed directly, for example:
//
//	keystore.New(keystore.WithSource(randomsource.New(...)))
func WithSource(source keysource.Source, sourceError error) Option {
	return func(store *store) error {
		if sourceError != nil {
			return fmt.Errorf("failed to initialize source: %w", sourceError)
		}
		if source == nil {
			return fmt.Errorf("source is nil")
		}
		id := source.ID()
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("source ID is empty")
		}
		if _, ok := store.sources[id]; ok {
			return fmt.Errorf("source %s already bound", id)
		}
		store.sources[id] = source
		return nil
	}
}

func WithRuntimeOptions(options ...KeystoreRuntimeOption) Option {
	return func(store *store) error {
		store.runtimeOptions = append(store.runtimeOptions, options...)
		return nil
	}
}
