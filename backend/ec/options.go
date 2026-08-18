package ec

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"github.com/veles-security/vcrypt/key"
)

func signatureOptions(publicKey *ecdsa.PublicKey, options ...key.SignOption) (crypto.Hash, error) {
	if len(options) != 1 {
		return 0, fmt.Errorf("EC backend: expected 1 signature algorithm option, got %d", len(options))
	}

	alg := key.KeyAlg(options[0])
	var hash crypto.Hash
	var curve string
	switch alg {
	case ES256:
		hash, curve = crypto.SHA256, "P-256"
	case ES384:
		hash, curve = crypto.SHA384, "P-384"
	case ES512:
		hash, curve = crypto.SHA512, "P-521"
	default:
		return 0, fmt.Errorf("EC backend: unsupported signature algorithm %q", alg)
	}

	if publicKey == nil || publicKey.Curve == nil || publicKey.Curve.Params() == nil {
		return 0, fmt.Errorf("EC backend: invalid ECDSA public key")
	}
	if publicKey.Curve.Params().Name != curve {
		return 0, fmt.Errorf("EC backend: curve %q cannot be used with signature algorithm %q", publicKey.Curve.Params().Name, alg)
	}
	return hash, nil
}
