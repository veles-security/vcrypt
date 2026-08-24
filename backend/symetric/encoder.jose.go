package symetric

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type symmetricJWK struct {
	KeyType    string   `json:"kty"`
	KeyID      string   `json:"kid,omitempty"`
	Use        string   `json:"use,omitempty"`
	Operations []string `json:"key_ops,omitempty"`
	Algorithm  string   `json:"alg,omitempty"`
	Key        string   `json:"k"`
}

type joseEncoder struct{}

// NewJOSEEncoder returns a symmetric single-key JOSE encoder.
func NewJOSEEncoder() key.JOSEEncoder { return &joseEncoder{} }

// SupportsMaterial implements [key.JOSEEncoder].
func (e *joseEncoder) SupportsMaterial(value material.Material) bool {
	_, ok := value.(*material.SymmetricMaterial)
	return ok
}

// Encode implements [key.JOSEEncoder].
func (e *joseEncoder) Encode(ctx context.Context, value key.Key, options ...key.JOSEEncodeOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(options) > 1 {
		return nil, fmt.Errorf("symetric JOSE encoder: expected at most one option, got %d", len(options))
	}
	option := key.JOSEEncodeOption{}
	if len(options) == 1 {
		option = options[0]
	}
	if option.MaterialPolicy != key.ExportPublicMaterial && option.MaterialPolicy != key.ExportPrivateMaterial {
		return nil, fmt.Errorf("symetric JOSE encoder: unsupported material export policy %d", option.MaterialPolicy)
	}
	if option.MaterialPolicy != key.ExportPrivateMaterial {
		return nil, fmt.Errorf("symetric JOSE encoder: symmetric material export is not permitted")
	}

	valueMaterial, ok := value.Material().(*material.SymmetricMaterial)
	if !ok {
		return nil, fmt.Errorf("symetric JOSE encoder: material is not symmetric")
	}
	if len(valueMaterial.Key) == 0 {
		return nil, fmt.Errorf("symetric JOSE encoder: key is empty")
	}

	jwk := symmetricJWK{
		KeyType: "oct",
		KeyID:   value.ID(),
		Key:     base64.RawURLEncoding.EncodeToString(valueMaterial.Key),
	}
	setSymmetricJWKMetadata(&jwk, value.Restrictions())
	encoded, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("symetric JOSE encoder: marshal JWK: %w", err)
	}
	return encoded, nil
}

func setSymmetricJWKMetadata(jwk *symmetricJWK, restrictions []key.Capability) {
	if len(restrictions) == 0 {
		return
	}
	use := restrictions[0].Use
	algorithm := restrictions[0].Algorithm
	consistentUse := true
	consistentAlgorithm := true
	for _, restriction := range restrictions {
		consistentUse = consistentUse && restriction.Use == use
		consistentAlgorithm = consistentAlgorithm && restriction.Algorithm == algorithm
		operation := string(restriction.Operation)
		if operation != "" && !slices.Contains(jwk.Operations, operation) {
			jwk.Operations = append(jwk.Operations, operation)
		}
	}
	if consistentUse {
		switch use {
		case key.KeyUseSigning:
			jwk.Use = "sig"
		case key.KeyUseEncryption:
			jwk.Use = "enc"
		}
	}
	if consistentAlgorithm {
		jwk.Algorithm = string(algorithm)
	}
}

var _ key.JOSEEncoder = &joseEncoder{}
