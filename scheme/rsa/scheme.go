package rsa

import (
	"crypto/rsa"
	"fmt"

	"github.com/veles-security/vcrypt/alg"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/scheme"
)

const (
	RS256 alg.Alg = "RS256"
	RS384 alg.Alg = "RS384"
	RS512 alg.Alg = "RS512"
	PS256 alg.Alg = "PS256"
	PS384 alg.Alg = "PS384"
	PS512 alg.Alg = "PS512"

	RSA1_5     alg.Alg = "RSA1_5"
	RSAOAEP    alg.Alg = "RSA-OAEP"
	RSAOAEP256 alg.Alg = "RSA-OAEP-256"
	RSAOAEP384 alg.Alg = "RSA-OAEP-384"
	RSAOAEP512 alg.Alg = "RSA-OAEP-512"
)

type RsaScheme struct{}

// DiscoverCapabilities implements [scheme.Scheme].
func (r *RsaScheme) DiscoverCapabilities(k *key.Key) error {
	if k == nil || k.Material == nil {
		return fmt.Errorf("RSA scheme: missing key material")
	}
	if _, ok := k.Material.Public().(*rsa.PublicKey); !ok {
		return fmt.Errorf("RSA scheme: key material is not RSA")
	}

	k.Uses = []key.KeyUse{key.KeyUseSigning, key.KeyUseEncryption}
	k.Operations = []key.KeyOperation{key.KeyOpVerify, key.KeyOpEncrypt}
	if material, ok := k.Material.(key.PrivateKeyMaterial); ok {
		if _, ok := material.Key.(*rsa.PrivateKey); ok {
			k.Operations = []key.KeyOperation{
				key.KeyOpSign,
				key.KeyOpVerify,
				key.KeyOpEncrypt,
				key.KeyOpDecrypt,
			}
		}
	}
	k.Algorithms = []alg.Alg{
		RS256, RS384, RS512,
		PS256, PS384, PS512,
		RSA1_5, RSAOAEP, RSAOAEP256, RSAOAEP384, RSAOAEP512,
	}

	return nil
}

var _ scheme.Scheme = &RsaScheme{}
