package symetric

import "github.com/veles-security/vcrypt/key"

const (
	HS256 key.KeyAlg = "HS256"
	HS384 key.KeyAlg = "HS384"
	HS512 key.KeyAlg = "HS512"

	A128GCM key.KeyAlg = "A128GCM"
	A192GCM key.KeyAlg = "A192GCM"
	A256GCM key.KeyAlg = "A256GCM"
)

var capabilities = []key.Capability{
	{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: HS256},
	{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: HS384},
	{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: HS512},
	{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: HS256},
	{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: HS384},
	{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: HS512},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: A128GCM},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: A192GCM},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: A256GCM},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: A128GCM},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: A192GCM},
	{Use: key.KeyUseEncryption, Operation: key.KeyOpDecrypt, Algorithm: A256GCM},
}
