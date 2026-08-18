package key

type KeyUse string

const (
	// KeyUseSigning identifies keys used to sign or verify OAuth 2.0 tokens and
	// SAML assertions, protocol messages, and metadata.
	KeyUseSigning KeyUse = "signing"
	// KeyUseEncryption identifies keys used to encrypt or decrypt OAuth 2.0
	// token data and SAML assertions, names, and protocol messages.
	KeyUseEncryption KeyUse = "encryption"
)

type KeyOperation string

const (
	// KeyOpSign creates signatures for OAuth 2.0 tokens and client assertions,
	// or for SAML assertions, protocol messages, and metadata.
	KeyOpSign KeyOperation = "sign"
	// KeyOpVerify validates signatures on OAuth 2.0 tokens and client
	// assertions, or on SAML assertions, protocol messages, and metadata.
	KeyOpVerify KeyOperation = "verify"
	// KeyOpEncrypt protects OAuth 2.0 token data or SAML assertions, names, and
	// protocol messages by encryption.
	KeyOpEncrypt KeyOperation = "encrypt"
	// KeyOpDecrypt recovers OAuth 2.0 token data or SAML assertions, names, and
	// protocol messages protected by encryption.
	KeyOpDecrypt KeyOperation = "decrypt"
)

type KeyAlg string

// Capability describes one cryptographic action that a key can perform with a
// particular algorithm. Keeping use, operation, and algorithm in one value
// prevents an algorithm from being interpreted as valid for an unrelated use
// or operation.
type Capability struct {
	Use       KeyUse
	Operation KeyOperation
	Algorithm KeyAlg
}
