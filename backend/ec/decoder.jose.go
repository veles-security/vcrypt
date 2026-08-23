package ec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// NewJOSEDecoder returns an EC single-key JOSE decoder.
func NewJOSEDecoder() key.JOSEDecoder { return &joseDecoder{} }

// SupportsJOSEKeyType implements [key.JOSEDecoder].
func (d *joseDecoder) SupportsJOSEKeyType(keyType string) bool { return keyType == "EC" }

// Decode implements [key.JOSEDecoder].
func (d *joseDecoder) Decode(ctx context.Context, encoded []byte, options ...key.JOSEDecodeOption) (key.KeyCandidate, error) {
	if err := ctx.Err(); err != nil {
		return key.KeyCandidate{}, err
	}
	if len(options) > 1 {
		return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: expected at most one option, got %d", len(options))
	}
	var jwk ecJWK
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: unmarshal JWK: %w", err)
	}
	if !d.SupportsJOSEKeyType(jwk.KeyType) {
		return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: unsupported kty %q", jwk.KeyType)
	}
	publicKey, err := publicKeyFromJWK(jwk)
	if err != nil {
		return key.KeyCandidate{}, err
	}

	var decodedMaterial material.Material
	if len(jwk.Certificates) > 0 && jwk.Private != "" {
		return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: JWK cannot contain both certificate and private key material")
	}
	if len(jwk.Certificates) > 0 {
		certificateDER, err := base64.StdEncoding.DecodeString(jwk.Certificates[0])
		if err != nil {
			return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: decode x5c certificate: %w", err)
		}
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: parse x5c certificate: %w", err)
		}
		certificateKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || !equalPublicKeys(certificateKey, publicKey) {
			return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: x5c certificate does not match JWK public key")
		}
		sha1Sum := sha1.Sum(certificate.Raw)
		if jwk.SHA1Thumbprint != "" && jwk.SHA1Thumbprint != base64.RawURLEncoding.EncodeToString(sha1Sum[:]) {
			return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: x5t does not match x5c certificate")
		}
		sha256Sum := sha256.Sum256(certificate.Raw)
		if jwk.SHA256Thumbprint != "" && jwk.SHA256Thumbprint != base64.RawURLEncoding.EncodeToString(sha256Sum[:]) {
			return key.KeyCandidate{}, fmt.Errorf("EC JOSE decoder: x5t#S256 does not match x5c certificate")
		}
		decodedMaterial = &material.CertificateMaterial{Cert: certificate}
	} else if jwk.Private != "" {
		privateKey, err := privateKeyFromJWK(jwk, publicKey)
		if err != nil {
			return key.KeyCandidate{}, err
		}
		decodedMaterial = &material.PrivateMaterial{Key: privateKey}
	} else {
		decodedMaterial = &material.PublicMaterial{Key: publicKey}
	}

	return key.KeyCandidate{ID: jwk.KeyID, Restrictions: restrictionsFromJWK(jwk), Material: decodedMaterial}, nil
}

func publicKeyFromJWK(jwk ecJWK) (*ecdsa.PublicKey, error) {
	curve, ok := curveFromJOSEName(jwk.Curve)
	if !ok {
		return nil, fmt.Errorf("EC JOSE decoder: unsupported curve %q", jwk.Curve)
	}
	x, err := decodeCoordinate("x", jwk.X, curve)
	if err != nil {
		return nil, err
	}
	y, err := decodeCoordinate("y", jwk.Y, curve)
	if err != nil {
		return nil, err
	}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC JOSE decoder: public point is not on curve %q", jwk.Curve)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func privateKeyFromJWK(jwk ecJWK, publicKey *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	d, err := decodeCoordinate("d", jwk.Private, publicKey.Curve)
	if err != nil {
		return nil, err
	}
	privateKey := &ecdsa.PrivateKey{PublicKey: *publicKey, D: d}
	if err := validatePrivateKey(privateKey); err != nil {
		return nil, fmt.Errorf("EC JOSE decoder: invalid private key: %w", err)
	}
	return privateKey, nil
}

func validatePrivateKey(privateKey *ecdsa.PrivateKey) error {
	if privateKey == nil || privateKey.Curve == nil || privateKey.D == nil || privateKey.D.Sign() <= 0 || privateKey.D.Cmp(privateKey.Curve.Params().N) >= 0 {
		return fmt.Errorf("private scalar is out of range")
	}
	if privateKey.X == nil || privateKey.Y == nil || !privateKey.Curve.IsOnCurve(privateKey.X, privateKey.Y) {
		return fmt.Errorf("invalid public point")
	}
	x, y := privateKey.Curve.ScalarBaseMult(privateKey.D.Bytes())
	if x.Cmp(privateKey.X) != 0 || y.Cmp(privateKey.Y) != 0 {
		return fmt.Errorf("private scalar does not match public point")
	}
	return nil
}

func curveFromJOSEName(name string) (elliptic.Curve, bool) {
	switch name {
	case "P-256":
		return elliptic.P256(), true
	case "P-384":
		return elliptic.P384(), true
	case "P-521":
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

func decodeCoordinate(name, encoded string, curve elliptic.Curve) (*big.Int, error) {
	if encoded == "" {
		return nil, fmt.Errorf("EC JOSE decoder: parameter %q is missing", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("EC JOSE decoder: decode parameter %q: %w", name, err)
	}
	wantSize := (curve.Params().BitSize + 7) / 8
	if len(decoded) != wantSize {
		return nil, fmt.Errorf("EC JOSE decoder: parameter %q has length %d, want %d", name, len(decoded), wantSize)
	}
	return new(big.Int).SetBytes(decoded), nil
}

func equalPublicKeys(first, second *ecdsa.PublicKey) bool {
	return first != nil && second != nil && first.Curve == second.Curve && first.X.Cmp(second.X) == 0 && first.Y.Cmp(second.Y) == 0
}

func restrictionsFromJWK(jwk ecJWK) []key.Capability {
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

var _ key.JOSEDecoder = &joseDecoder{}
