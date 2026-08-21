package testkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"testing"
)

type Malformation string

const (
	MissingPublicPoint Malformation = "missing-public-point"
	ZeroPrivateValue   Malformation = "zero-private-value"
	InvalidLength      Malformation = "invalid-length"
	IncompleteKey      Malformation = "incomplete-key"
)

func MalformedPublic(
	t testing.TB,
	kind Kind,
	malformation Malformation,
) crypto.PublicKey {
	t.Helper()

	switch {
	case kind == RSA2048 && malformation == IncompleteKey:
		return &rsa.PublicKey{
			N: big.NewInt(15),
			E: 0,
		}

	case kind == ES256 && malformation == MissingPublicPoint:
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     nil,
			Y:     nil,
		}

	case kind == Ed25519 && malformation == InvalidLength:
		return ed25519.PublicKey(make([]byte, 17))

	default:
		t.Fatalf(
			"testkeys: unsupported malformed key combination %q/%q",
			kind,
			malformation,
		)
		return nil
	}
}

func MalformedPrivate(
	t testing.TB,
	kind Kind,
	malformation Malformation,
) crypto.PrivateKey {
	t.Helper()

	switch {
	case kind == RSA2048 && malformation == IncompleteKey:
		return &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: big.NewInt(15),
				E: 65537,
			},
			D: big.NewInt(1),
		}

	case kind == ES256 && malformation == MissingPublicPoint:
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     nil,
				Y:     nil,
			},
			D: big.NewInt(1),
		}

	case kind == ES256 && malformation == ZeroPrivateValue:
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     big.NewInt(0),
				Y:     big.NewInt(0),
			},
			D: big.NewInt(0),
		}

	case kind == Ed25519 && malformation == InvalidLength:
		return ed25519.PrivateKey(make([]byte, 17))

	default:
		t.Fatalf(
			"testkeys: unsupported malformed key combination %q/%q",
			kind,
			malformation,
		)
		return nil
	}
}
