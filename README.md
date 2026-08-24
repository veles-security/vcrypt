# vcrypt

`vcrypt` is a Go keystore for loading, rotating, selecting, and using RSA,
ECDSA, and symmetric keys. Keys can be generated in memory, fetched from a
remote JWKS endpoint, or read from PEM/DER files.

```shell
go get github.com/veles-security/vcrypt
```

Creating a keystore loads every configured source immediately. Random and JWKS
sources then refresh themselves automatically; file sources can optionally be
monitored for changes. Source IDs must be unique within a keystore. A keystore
owns its configured sources, so close the store to stop background refreshes.

## Secure token service: generated signing keys and remote JWKS keys

This service rotates an in-memory RSA signing key every 24 hours and also
fetches public keys used to verify tokens from another issuer.

```go
package tokenservice

import (
	"context"
	"time"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource/jwkssource"
	"github.com/veles-security/vcrypt/keysource/randomsource"
	"github.com/veles-security/vcrypt/keystore"
)

func newKeyStore() (keystore.Store, error) {
	return keystore.New(
		keystore.WithSource(randomsource.New(
			"token-signing",
			randomsource.RSA3072,
			24*time.Hour,
		)),
		keystore.WithSource(jwkssource.New(
			"partner",
			"https://partner.example.com/.well-known/jwks.json",
			15*time.Minute,
		)),
	)
}

func signPayload(ctx context.Context, keys keystore.Store, payload []byte) (keystore.SignResult, error) {
	return keys.Sign(
		ctx,
		payload,
		keystore.WithKeys(keystore.Select(keystore.WithKeySource("token-signing"))),
		keystore.WithAlgorithms(key.KeyAlg("PS256")),
	)
}

func verifyPartnerPayload(
	ctx context.Context,
	keys keystore.Store,
	keyID string,
	payload, signature []byte,
) error {
	return keys.VerifySignature(
		ctx,
		payload,
		signature,
		keystore.WithKeys(keystore.Select(
			keystore.WithKeySource("partner"),
			keystore.WithKeyID(keyID),
		)),
		keystore.WithAlgorithms(key.KeyAlg("PS256")),
	)
}
```

`SignResult.Key.ID` is the `kid` to place in the token header. For verification,
pass the incoming token's `kid` as `keyID`.

## Client application: remote JWKS keys only

A client that only validates tokens needs no private keys:

```go
keys, err := keystore.New(keystore.WithSource(jwkssource.New(
	"issuer", "https://login.example.com/.well-known/jwks.json", 15*time.Minute,
)))
if err != nil {
	return err
}
defer keys.Close()

err = keys.VerifySignature(
	ctx,
	signedContent,
	signature,
	keystore.WithKeys(keystore.Select(
		keystore.WithKeySource("issuer"),
		keystore.WithKeyID(keyID), // the token header's kid
	)),
	keystore.WithAlgorithms(key.KeyAlg("RS256")),
)
```

The imports specific to this snippet are `time`, `key`, `jwkssource`, and
`keystore`, using the paths shown in the first example.

## Authorization server: keys loaded from a file path

The path may name one PEM/DER file or a directory of key files. This example
loads a private signing key and monitors it for atomic replacement:

```go
keys, err := keystore.New(keystore.WithSource(filesource.New(
	"authorization-server",
	"/etc/authorization-server/keys/signing-key.pem",
	filesource.WithFileMonitoring(true),
	filesource.WithFileCandidate(key.KeyCandidate{
		ID:       "authorization-server-signing-key",
		Owner:    "https://login.example.com",
		Status:   key.KeyStatusActive,
		Priority: 100,
	}),
)))
if err != nil {
	return err
}
defer keys.Close()

result, err := keys.Sign(
	ctx,
	claims,
	keystore.WithKeys(keystore.Select(
		keystore.WithKeySource("authorization-server"),
	)),
	keystore.WithAlgorithms(key.KeyAlg("PS256")),
)
if err != nil {
	return err
}

signature := result.Signature
keyID := result.Key.ID
_, _ = signature, keyID
```

The imports specific to this snippet are `key`, `filesource`, and `keystore`.
Supported file encodings include PKCS #8, PKCS #1 RSA, SEC 1 EC private keys,
PKIX and PKCS #1 public keys, and X.509 certificates. The process must be able
to read the path when `keystore.New` is called.

## Key selection

Operations select keys by ID, owner, and/or source, then by algorithm. Signing
and encryption use active keys; verification and decryption can also use
passive rollover keys. Specify algorithms in preference order:

```go
keystore.WithAlgorithms(key.KeyAlg("PS256"), key.KeyAlg("RS256"))
```

See [backend/README.md](backend/README.md) for supported algorithms, key types,
and the legacy algorithms that require the `with_unsafe_crypto` build tag.
