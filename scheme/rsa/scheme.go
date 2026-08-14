package rsa

import (
	"crypto"
	stdrsa "crypto/rsa"
	"fmt"

	"github.com/veles-security/vcrypt"
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

var capabilities = map[string][]key.Capability{
	"public": {
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS512},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS512},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSA1_5},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP256},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP384},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP512},
	},
	"private": {
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: RS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: RS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: RS512},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: PS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: PS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: PS512},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS512},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS512},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSA1_5},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP256},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP384},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP512},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSA1_5},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP256},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP384},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP512},
	},
}

// DiscoverCapabilities implements [scheme.Scheme].
func (r *RsaScheme) DiscoverCapabilities(k *key.Key) error {
	if k == nil || k.Material == nil {
		return fmt.Errorf("RSA scheme: missing key material")
	}
	if _, ok := k.Material.Public().(*stdrsa.PublicKey); !ok {
		return fmt.Errorf("RSA scheme: key material is not RSA")
	}

	capabilitySet := "public"
	if material, ok := k.Material.(key.PrivateKeyMaterial); ok {
		if _, ok := material.Key.(*stdrsa.PrivateKey); ok {
			capabilitySet = "private"
		}
	}
	k.Capabilities = capabilities[capabilitySet]

	return nil
}

// Signer implements [scheme.Scheme].
func (r *RsaScheme) Signer(k *key.Key, algorithm alg.Alg) vcrypt.Signer {
	if k == nil {
		return nil
	}
	material, ok := k.Material.(key.PrivateKeyMaterial)
	if !ok {
		return nil
	}
	privateKey, ok := material.Key.(*stdrsa.PrivateKey)
	if !ok {
		return nil
	}

	var hash crypto.Hash
	var pss bool
	switch algorithm {
	case RS256:
		hash = crypto.SHA256
	case RS384:
		hash = crypto.SHA384
	case RS512:
		hash = crypto.SHA512
	case PS256:
		hash, pss = crypto.SHA256, true
	case PS384:
		hash, pss = crypto.SHA384, true
	case PS512:
		hash, pss = crypto.SHA512, true
	default:
		return nil
	}

	return &rsaSigner{key: privateKey, hash: hash, pss: pss}
}

var _ scheme.Scheme = &RsaScheme{}
