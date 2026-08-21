package testkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"testing"
)

type Kind string

const (
	RSA2048 Kind = "RSA2048"
	ES256   Kind = "ES256"
	ES384   Kind = "ES384"
	ES512   Kind = "ES512"
	Ed25519 Kind = "Ed25519"
)

//go:embed testdata/rsa2048.pem
var rsa2048PEM []byte

//go:embed testdata/es256.pem
var es256PEM []byte

//go:embed testdata/es384.pem
var es384PEM []byte

//go:embed testdata/es512.pem
var es512PEM []byte

//go:embed testdata/ed25519.pem
var ed25519PEM []byte

func Private(t testing.TB, kind Kind) crypto.PrivateKey {
	t.Helper()

	pemData := pemForKind(t, kind)

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("testkeys: cannot decode PEM for %q", kind)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("testkeys: parse private key %q: %v", kind, err)
	}

	validateType(t, kind, key)

	return key
}

func Public(t testing.TB, kind Kind) crypto.PublicKey {
	t.Helper()

	privateKey := Private(t, kind)

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey

	case *ecdsa.PrivateKey:
		return &key.PublicKey

	case ed25519.PrivateKey:
		publicKey, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("testkeys: unexpected Ed25519 public key type %T", key.Public())
		}
		return publicKey

	default:
		t.Fatalf("testkeys: unsupported private key type %T", privateKey)
		return nil
	}
}

func pemForKind(t testing.TB, kind Kind) []byte {
	t.Helper()

	switch kind {
	case RSA2048:
		return rsa2048PEM
	case ES256:
		return es256PEM
	case ES384:
		return es384PEM
	case ES512:
		return es512PEM
	case Ed25519:
		return ed25519PEM
	default:
		t.Fatalf("testkeys: unknown key kind %q", kind)
		return nil
	}
}

func validateType(t testing.TB, kind Kind, key any) {
	t.Helper()

	switch kind {
	case RSA2048:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("testkeys: %q contains %T, want *rsa.PrivateKey", kind, key)
		}
		if rsaKey.N.BitLen() != 2048 {
			t.Fatalf(
				"testkeys: RSA key has %d bits, want 2048",
				rsaKey.N.BitLen(),
			)
		}

	case ES256:
		requireECDSACurve(t, kind, key, elliptic.P256())

	case ES384:
		requireECDSACurve(t, kind, key, elliptic.P384())

	case ES512:
		requireECDSACurve(t, kind, key, elliptic.P521())

	case Ed25519:
		if _, ok := key.(ed25519.PrivateKey); !ok {
			t.Fatalf("testkeys: %q contains %T, want ed25519.PrivateKey", kind, key)
		}
	}
}

func requireECDSACurve(
	t testing.TB,
	kind Kind,
	key any,
	want elliptic.Curve,
) {
	t.Helper()

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("testkeys: %q contains %T, want *ecdsa.PrivateKey", kind, key)
	}

	if ecdsaKey.Curve != want {
		t.Fatalf(
			"testkeys: %q uses curve %q, want %q",
			kind,
			ecdsaKey.Curve.Params().Name,
			want.Params().Name,
		)
	}
}
