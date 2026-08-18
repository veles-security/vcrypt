package ec

import "github.com/veles-security/vcrypt/key"

const (
	ES256 key.KeyAlg = "ES256"
	ES384 key.KeyAlg = "ES384"
	ES512 key.KeyAlg = "ES512"
)

type MaterialType string

const (
	PUBLIC_MATERIAL  MaterialType = "public"
	PRIVATE_MATERIAL MaterialType = "private"
)

var capabilities = map[MaterialType][]key.Capability{
	PUBLIC_MATERIAL: {
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES512},
	},
	PRIVATE_MATERIAL: {
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: ES256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: ES384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: ES512},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES256},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES384},
		{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: ES512},
	},
}
