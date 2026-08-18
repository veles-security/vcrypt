package hmac

import "github.com/veles-security/vcrypt/key"

const (
	HS256 key.KeyAlg = "HS256"
	HS384 key.KeyAlg = "HS384"
	HS512 key.KeyAlg = "HS512"
)

var capabilities = []key.Capability{
	{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: HS256},
	{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: HS384},
	{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: HS512},
	{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: HS256},
	{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: HS384},
	{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: HS512},
}
