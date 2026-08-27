package material

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
)

// Clone returns an independent copy of material. The key types supported by
// vcrypt are copied deeply so callers cannot mutate cryptographic state owned
// by a key or backend through a retained reference.
func Clone(value Material) Material {
	switch value := value.(type) {
	case *PrivateMaterial:
		if value == nil {
			return (*PrivateMaterial)(nil)
		}
		return &PrivateMaterial{Key: clonePrivateKey(value.Key)}
	case *PublicMaterial:
		if value == nil {
			return (*PublicMaterial)(nil)
		}
		return &PublicMaterial{Key: clonePublicKey(value.Key)}
	case *CertificateMaterial:
		if value == nil {
			return (*CertificateMaterial)(nil)
		}
		return &CertificateMaterial{Cert: cloneCertificate(value.Cert)}
	case *SymmetricMaterial:
		if value == nil {
			return (*SymmetricMaterial)(nil)
		}
		return &SymmetricMaterial{Key: append([]byte(nil), value.Key...)}
	default:
		return value
	}
}

func clonePrivateKey(value crypto.PrivateKey) crypto.PrivateKey {
	switch value := value.(type) {
	case *rsa.PrivateKey:
		if value == nil {
			return (*rsa.PrivateKey)(nil)
		}
		primes := make([]*big.Int, len(value.Primes))
		for i, prime := range value.Primes {
			primes[i] = cloneBigInt(prime)
		}
		cloned := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: cloneBigInt(value.N), E: value.E},
			D:         cloneBigInt(value.D),
			Primes:    primes,
		}
		return cloned
	case *ecdsa.PrivateKey:
		if value == nil {
			return (*ecdsa.PrivateKey)(nil)
		}
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: value.Curve, X: cloneBigInt(value.X), Y: cloneBigInt(value.Y)},
			D:         cloneBigInt(value.D),
		}
	case ed25519.PrivateKey:
		return append(ed25519.PrivateKey(nil), value...)
	default:
		return value
	}
}

func clonePublicKey(value crypto.PublicKey) crypto.PublicKey {
	switch value := value.(type) {
	case *rsa.PublicKey:
		if value == nil {
			return (*rsa.PublicKey)(nil)
		}
		return &rsa.PublicKey{N: cloneBigInt(value.N), E: value.E}
	case *ecdsa.PublicKey:
		if value == nil {
			return (*ecdsa.PublicKey)(nil)
		}
		return &ecdsa.PublicKey{Curve: value.Curve, X: cloneBigInt(value.X), Y: cloneBigInt(value.Y)}
	case ed25519.PublicKey:
		return append(ed25519.PublicKey(nil), value...)
	default:
		return value
	}
}

func cloneCertificate(value *x509.Certificate) *x509.Certificate {
	if value == nil {
		return nil
	}
	if len(value.Raw) != 0 {
		if cloned, err := x509.ParseCertificate(append([]byte(nil), value.Raw...)); err == nil {
			return cloned
		}
	}
	cloned := *value
	cloned.Raw = append([]byte(nil), value.Raw...)
	cloned.RawTBSCertificate = append([]byte(nil), value.RawTBSCertificate...)
	cloned.RawSubjectPublicKeyInfo = append([]byte(nil), value.RawSubjectPublicKeyInfo...)
	cloned.RawSubject = append([]byte(nil), value.RawSubject...)
	cloned.RawIssuer = append([]byte(nil), value.RawIssuer...)
	cloned.Signature = append([]byte(nil), value.Signature...)
	cloned.PublicKey = clonePublicKey(value.PublicKey)
	return &cloned
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}
