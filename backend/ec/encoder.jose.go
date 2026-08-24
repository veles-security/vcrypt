package ec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1" // #nosec G505 -- SHA-1 is required for the legacy JOSE x5t descriptor
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type ecJWK struct {
	KeyType          string   `json:"kty"`
	KeyID            string   `json:"kid,omitempty"`
	Use              string   `json:"use,omitempty"`
	Operations       []string `json:"key_ops,omitempty"`
	Algorithm        string   `json:"alg,omitempty"`
	Curve            string   `json:"crv"`
	X                string   `json:"x"`
	Y                string   `json:"y"`
	Private          string   `json:"d,omitempty"`
	Certificates     []string `json:"x5c,omitempty"`
	SHA1Thumbprint   string   `json:"x5t,omitempty"`
	SHA256Thumbprint string   `json:"x5t#S256,omitempty"`
}

type joseEncoder struct{}

// NewJOSEEncoder returns an EC single-key JOSE encoder.
func NewJOSEEncoder() key.JOSEEncoder { return &joseEncoder{} }

// SupportsMaterial implements [key.JOSEEncoder].
func (e *joseEncoder) SupportsMaterial(value material.Material) bool {
	switch value := value.(type) {
	case *material.PublicMaterial:
		_, ok := value.Key.(*ecdsa.PublicKey)
		return ok
	case *material.PrivateMaterial:
		_, ok := value.Key.(*ecdsa.PrivateKey)
		return ok
	case *material.CertificateMaterial:
		if value.Cert == nil {
			return false
		}
		_, ok := value.Cert.PublicKey.(*ecdsa.PublicKey)
		return ok
	default:
		return false
	}
}

// Encode implements [key.JOSEEncoder].
func (e *joseEncoder) Encode(ctx context.Context, value key.Key, options ...key.JOSEEncodeOption) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(options) > 1 {
		return nil, fmt.Errorf("EC JOSE encoder: expected at most one option, got %d", len(options))
	}
	option := key.JOSEEncodeOption{}
	if len(options) == 1 {
		option = options[0]
	}
	if option.MaterialPolicy != key.ExportPublicMaterial && option.MaterialPolicy != key.ExportPrivateMaterial {
		return nil, fmt.Errorf("EC JOSE encoder: unsupported material export policy %d", option.MaterialPolicy)
	}

	jwk := ecJWK{KeyType: "EC", KeyID: value.ID()}
	setJWKMetadata(&jwk, value.Restrictions())
	switch value := value.Material().(type) {
	case *material.PublicMaterial:
		publicKey, ok := value.Key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("EC JOSE encoder: material is not an EC public key")
		}
		if err := setPublicJWK(&jwk, publicKey); err != nil {
			return nil, err
		}
	case *material.PrivateMaterial:
		privateKey, ok := value.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("EC JOSE encoder: material is not an EC private key")
		}
		if err := validatePrivateKey(privateKey); err != nil {
			return nil, fmt.Errorf("EC JOSE encoder: invalid private key: %w", err)
		}
		if err := setPublicJWK(&jwk, &privateKey.PublicKey); err != nil {
			return nil, err
		}
		if option.MaterialPolicy == key.ExportPrivateMaterial {
			jwk.Private = encodeCoordinate(privateKey.D, privateKey.Curve)
		}
	case *material.CertificateMaterial:
		if value.Cert == nil {
			return nil, fmt.Errorf("EC JOSE encoder: certificate is nil")
		}
		publicKey, ok := value.Cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("EC JOSE encoder: certificate does not contain an EC public key")
		}
		if len(value.Cert.Raw) == 0 {
			return nil, fmt.Errorf("EC JOSE encoder: certificate DER is empty")
		}
		if err := setPublicJWK(&jwk, publicKey); err != nil {
			return nil, err
		}
		jwk.Certificates = []string{base64.StdEncoding.EncodeToString(value.Cert.Raw)}
		sha1Sum := sha1.Sum(value.Cert.Raw) // #nosec G401 -- SHA-1 is required for the legacy JOSE x5t descriptor; nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
		sha256Sum := sha256.Sum256(value.Cert.Raw)
		jwk.SHA1Thumbprint = base64.RawURLEncoding.EncodeToString(sha1Sum[:])
		jwk.SHA256Thumbprint = base64.RawURLEncoding.EncodeToString(sha256Sum[:])
	default:
		return nil, fmt.Errorf("EC JOSE encoder: material is not supported")
	}

	encoded, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("EC JOSE encoder: marshal JWK: %w", err)
	}
	return encoded, nil
}

func setPublicJWK(jwk *ecJWK, publicKey *ecdsa.PublicKey) error {
	curveName, ok := joseCurveName(publicKey.Curve)
	if !ok {
		return fmt.Errorf("EC JOSE encoder: unsupported curve")
	}
	if publicKey.X == nil || publicKey.Y == nil || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return fmt.Errorf("EC JOSE encoder: invalid public key")
	}
	jwk.Curve = curveName
	jwk.X = encodeCoordinate(publicKey.X, publicKey.Curve)
	jwk.Y = encodeCoordinate(publicKey.Y, publicKey.Curve)
	return nil
}

func joseCurveName(curve elliptic.Curve) (string, bool) {
	switch curve {
	case elliptic.P256():
		return "P-256", true
	case elliptic.P384():
		return "P-384", true
	case elliptic.P521():
		return "P-521", true
	default:
		return "", false
	}
}

func encodeCoordinate(value *big.Int, curve elliptic.Curve) string {
	size := (curve.Params().BitSize + 7) / 8
	encoded := make([]byte, size)
	value.FillBytes(encoded)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func setJWKMetadata(jwk *ecJWK, restrictions []key.Capability) {
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
