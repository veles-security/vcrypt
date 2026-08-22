package rsa

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type joseDecoder struct{}

// NewJOSEDecoder returns an RSA single-key JOSE decoder.
func NewJOSEDecoder() key.JOSEDecoder {
	return &joseDecoder{}
}

// SupportsJOSEKeyType implements [key.JOSEDecoder].
func (d *joseDecoder) SupportsJOSEKeyType(keyType string) bool {
	return keyType == "RSA"
}

// Decode implements [key.JOSEDecoder].
func (d *joseDecoder) Decode(ctx context.Context, encoded []byte, options ...key.JOSEDecodeOption) (key.KeyCandidate, error) {
	if err := ctx.Err(); err != nil {
		return key.KeyCandidate{}, err
	}
	if len(options) > 1 {
		return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: expected at most one option, got %d", len(options))
	}
	var jwk rsaJWK
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: unmarshal JWK: %w", err)
	}
	if !d.SupportsJOSEKeyType(jwk.KeyType) {
		return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: unsupported kty %q", jwk.KeyType)
	}
	publicKey, err := publicKeyFromJWK(jwk)
	if err != nil {
		return key.KeyCandidate{}, err
	}

	var decodedMaterial material.Material
	hasPrivate := jwk.Private != "" || jwk.Prime1 != "" || jwk.Prime2 != "" || jwk.Exponent1 != "" || jwk.Exponent2 != "" || jwk.Coefficient != ""
	if len(jwk.Certificates) > 0 && hasPrivate {
		return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: JWK cannot contain both certificate and private key material")
	}
	if len(jwk.Certificates) > 0 {
		certificateDER, err := base64.StdEncoding.DecodeString(jwk.Certificates[0])
		if err != nil {
			return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: decode x5c certificate: %w", err)
		}
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: parse x5c certificate: %w", err)
		}
		certificateKey, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok || certificateKey.E != publicKey.E || certificateKey.N.Cmp(publicKey.N) != 0 {
			return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: x5c certificate does not match JWK public key")
		}
		sha1Sum := sha1.Sum(certificate.Raw)
		if jwk.SHA1Thumbprint != "" && jwk.SHA1Thumbprint != base64.RawURLEncoding.EncodeToString(sha1Sum[:]) {
			return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: x5t does not match x5c certificate")
		}
		sha256Sum := sha256.Sum256(certificate.Raw)
		if jwk.SHA256Thumbprint != "" && jwk.SHA256Thumbprint != base64.RawURLEncoding.EncodeToString(sha256Sum[:]) {
			return key.KeyCandidate{}, fmt.Errorf("RSA JOSE decoder: x5t#S256 does not match x5c certificate")
		}
		decodedMaterial = &material.CertificateMaterial{Cert: certificate}
	} else if hasPrivate {
		privateKey, err := privateKeyFromJWK(jwk, publicKey)
		if err != nil {
			return key.KeyCandidate{}, err
		}
		decodedMaterial = &material.PrivateMaterial{Key: privateKey}
	} else {
		decodedMaterial = &material.PublicMaterial{Key: publicKey}
	}

	return key.KeyCandidate{
		ID:           jwk.KeyID,
		Restrictions: restrictionsFromJWK(jwk),
		Material:     decodedMaterial,
	}, nil
}

func restrictionsFromJWK(jwk rsaJWK) []key.Capability {
	if jwk.Algorithm == "" || len(jwk.Operations) == 0 {
		return nil
	}
	restrictions := make([]key.Capability, 0, len(jwk.Operations))
	for _, operation := range jwk.Operations {
		keyOperation := key.KeyOperation(operation)
		use := key.KeyUseSigning
		if keyOperation == key.KeyOpEncrypt || keyOperation == key.KeyOpDecrypt {
			use = key.KeyUseEncryption
		}
		switch jwk.Use {
		case "sig":
			use = key.KeyUseSigning
		case "enc":
			use = key.KeyUseEncryption
		}
		restrictions = append(restrictions, key.Capability{Use: use, Operation: keyOperation, Algorithm: key.KeyAlg(jwk.Algorithm)})
	}
	return restrictions
}

func publicKeyFromJWK(jwk rsaJWK) (*rsa.PublicKey, error) {
	modulus, err := decodeBigInt("n", jwk.Modulus)
	if err != nil {
		return nil, err
	}
	exponent, err := decodeBigInt("e", jwk.Exponent)
	if err != nil {
		return nil, err
	}
	if !exponent.IsInt64() || exponent.Int64() < 2 || exponent.Int64() > int64(^uint(0)>>1) {
		return nil, fmt.Errorf("RSA JOSE decoder: invalid exponent")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func privateKeyFromJWK(jwk rsaJWK, publicKey *rsa.PublicKey) (*rsa.PrivateKey, error) {
	if jwk.Private == "" || jwk.Prime1 == "" || jwk.Prime2 == "" || jwk.Exponent1 == "" || jwk.Exponent2 == "" || jwk.Coefficient == "" {
		return nil, fmt.Errorf("RSA JOSE decoder: private JWK parameters d, p, q, dp, dq, and qi are required")
	}
	privateExponent, err := decodeBigInt("d", jwk.Private)
	if err != nil {
		return nil, err
	}
	prime1, err := decodeBigInt("p", jwk.Prime1)
	if err != nil {
		return nil, err
	}
	prime2, err := decodeBigInt("q", jwk.Prime2)
	if err != nil {
		return nil, err
	}
	privateKey := &rsa.PrivateKey{PublicKey: *publicKey, D: privateExponent, Primes: []*big.Int{prime1, prime2}}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("RSA JOSE decoder: invalid private key: %w", err)
	}
	privateKey.Precompute()
	exponent1, err := decodeBigInt("dp", jwk.Exponent1)
	if err != nil {
		return nil, err
	}
	exponent2, err := decodeBigInt("dq", jwk.Exponent2)
	if err != nil {
		return nil, err
	}
	coefficient, err := decodeBigInt("qi", jwk.Coefficient)
	if err != nil {
		return nil, err
	}
	if privateKey.Precomputed.Dp.Cmp(exponent1) != 0 || privateKey.Precomputed.Dq.Cmp(exponent2) != 0 || privateKey.Precomputed.Qinv.Cmp(coefficient) != 0 {
		return nil, fmt.Errorf("RSA JOSE decoder: private CRT parameters are inconsistent")
	}
	return privateKey, nil
}

func decodeBigInt(name, encoded string) (*big.Int, error) {
	if encoded == "" {
		return nil, fmt.Errorf("RSA JOSE decoder: parameter %q is missing", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("RSA JOSE decoder: decode parameter %q: %w", name, err)
	}
	value := new(big.Int).SetBytes(decoded)
	if value.Sign() <= 0 {
		return nil, fmt.Errorf("RSA JOSE decoder: parameter %q must be positive", name)
	}
	return value, nil
}

var _ key.JOSEDecoder = &joseDecoder{}
