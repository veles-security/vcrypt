package rsa

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type rsaJWK struct {
	KeyType          string   `json:"kty"`
	KeyID            string   `json:"kid,omitempty"`
	Use              string   `json:"use,omitempty"`
	Operations       []string `json:"key_ops,omitempty"`
	Algorithm        string   `json:"alg,omitempty"`
	Modulus          string   `json:"n"`
	Exponent         string   `json:"e"`
	Private          string   `json:"d,omitempty"`
	Prime1           string   `json:"p,omitempty"`
	Prime2           string   `json:"q,omitempty"`
	Exponent1        string   `json:"dp,omitempty"`
	Exponent2        string   `json:"dq,omitempty"`
	Coefficient      string   `json:"qi,omitempty"`
	Certificates     []string `json:"x5c,omitempty"`
	SHA1Thumbprint   string   `json:"x5t,omitempty"`
	SHA256Thumbprint string   `json:"x5t#S256,omitempty"`
}

type joseEncoder struct{}

// NewJOSEEncoder returns an RSA single-key JOSE encoder.
func NewJOSEEncoder() key.JOSEEncoder {
	return &joseEncoder{}
}

// SupportsMaterial implements [key.JOSEEncoder].
func (e *joseEncoder) SupportsMaterial(value material.Material) bool {
	switch value := value.(type) {
	case *material.PublicMaterial:
		_, ok := value.Key.(*rsa.PublicKey)
		return ok
	case *material.PrivateMaterial:
		_, ok := value.Key.(*rsa.PrivateKey)
		return ok
	case *material.CertificateMaterial:
		if value.Cert == nil {
			return false
		}
		_, ok := value.Cert.PublicKey.(*rsa.PublicKey)
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
		return nil, fmt.Errorf("RSA JOSE encoder: expected at most one option, got %d", len(options))
	}
	option := key.JOSEEncodeOption{}
	if len(options) == 1 {
		option = options[0]
	}
	if option.MaterialPolicy != key.ExportPublicMaterial && option.MaterialPolicy != key.ExportPrivateMaterial {
		return nil, fmt.Errorf("RSA JOSE encoder: unsupported material export policy %d", option.MaterialPolicy)
	}

	jwk := rsaJWK{KeyType: "RSA", KeyID: value.ID()}
	setJWKMetadata(&jwk, value.Restrictions())
	switch value := value.Material().(type) {
	case *material.PublicMaterial:
		publicKey, ok := value.Key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("RSA JOSE encoder: material is not an RSA public key")
		}
		setPublicJWK(&jwk, publicKey)
	case *material.PrivateMaterial:
		privateKey, ok := value.Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("RSA JOSE encoder: material is not an RSA private key")
		}
		if err := privateKey.Validate(); err != nil {
			return nil, fmt.Errorf("RSA JOSE encoder: invalid private key: %w", err)
		}
		setPublicJWK(&jwk, &privateKey.PublicKey)
		if option.MaterialPolicy == key.ExportPrivateMaterial {
			privateKeyCopy := *privateKey
			privateKeyCopy.Precomputed = rsa.PrecomputedValues{}
			privateKeyCopy.Precompute()
			jwk.Private = encodeBigInt(privateKey.D)
			jwk.Prime1 = encodeBigInt(privateKey.Primes[0])
			jwk.Prime2 = encodeBigInt(privateKey.Primes[1])
			jwk.Exponent1 = encodeBigInt(privateKeyCopy.Precomputed.Dp)
			jwk.Exponent2 = encodeBigInt(privateKeyCopy.Precomputed.Dq)
			jwk.Coefficient = encodeBigInt(privateKeyCopy.Precomputed.Qinv)
		}
	case *material.CertificateMaterial:
		if value.Cert == nil {
			return nil, fmt.Errorf("RSA JOSE encoder: certificate is nil")
		}
		publicKey, ok := value.Cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("RSA JOSE encoder: certificate does not contain an RSA public key")
		}
		if len(value.Cert.Raw) == 0 {
			return nil, fmt.Errorf("RSA JOSE encoder: certificate DER is empty")
		}
		setPublicJWK(&jwk, publicKey)
		jwk.Certificates = []string{base64.StdEncoding.EncodeToString(value.Cert.Raw)}
		sha1Sum := sha1.Sum(value.Cert.Raw)
		sha256Sum := sha256.Sum256(value.Cert.Raw)
		jwk.SHA1Thumbprint = base64.RawURLEncoding.EncodeToString(sha1Sum[:])
		jwk.SHA256Thumbprint = base64.RawURLEncoding.EncodeToString(sha256Sum[:])
	default:
		return nil, fmt.Errorf("RSA JOSE encoder: material is not supported")
	}

	encoded, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("RSA JOSE encoder: marshal JWK: %w", err)
	}
	return encoded, nil
}

func setPublicJWK(jwk *rsaJWK, publicKey *rsa.PublicKey) {
	jwk.Modulus = encodeBigInt(publicKey.N)
	jwk.Exponent = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
}

func setJWKMetadata(jwk *rsaJWK, restrictions []key.Capability) {
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

func encodeBigInt(value *big.Int) string {
	if value == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(value.Bytes())
}

var _ key.JOSEEncoder = &joseEncoder{}
