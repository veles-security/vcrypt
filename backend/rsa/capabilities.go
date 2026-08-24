package rsa

import "github.com/veles-security/vcrypt/key"

const (
	RS256 key.KeyAlg = "RS256"
	RS384 key.KeyAlg = "RS384"
	RS512 key.KeyAlg = "RS512"
	PS256 key.KeyAlg = "PS256"
	PS384 key.KeyAlg = "PS384"
	PS512 key.KeyAlg = "PS512"

	// RSA1_5 uses legacy PKCS #1 v1.5 encryption padding and is available only
	// in builds made with the with_unsafe_crypto build tag.
	RSA1_5 key.KeyAlg = "RSA1_5"
	// RSAOAEP uses SHA-1 and is available only in builds made with the
	// with_unsafe_crypto build tag.
	RSAOAEP    key.KeyAlg = "RSA-OAEP"
	RSAOAEP256 key.KeyAlg = "RSA-OAEP-256"
	RSAOAEP384 key.KeyAlg = "RSA-OAEP-384"
	RSAOAEP512 key.KeyAlg = "RSA-OAEP-512"
)

type MaterialType string

const (
	PUBLIC_MATERIAL  MaterialType = "public"
	PRIVATE_MATERIAL MaterialType = "private"
)

var capabilities = map[MaterialType][]key.Capability{
	PUBLIC_MATERIAL: {
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS512},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: PS512},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP256},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP384},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP512},
	},
	PRIVATE_MATERIAL: {
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
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP256},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP384},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP512},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP256},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP384},
		{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: RSAOAEP512},
	},
}

func init() {
	for materialType, materialCapabilities := range unsafeCryptoCapabilities {
		capabilities[materialType] = append(capabilities[materialType], materialCapabilities...)
	}
}
