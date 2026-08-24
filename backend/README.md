# Cryptographic backends

The backend packages expose the algorithms below. Algorithms marked as unsafe
are excluded from backend capabilities and reject operations in a default
build. They can be enabled for legacy interoperability with:

```shell
go build -tags with_unsafe_crypto ./...
```

The security levels are approximate classical security strengths. Actual RSA
strength depends on the modulus: a 2048-bit RSA key provides about 112 bits, a
3072-bit key about 128 bits, a 7680-bit key about 192 bits, and a 15360-bit key
about 256 bits. The RSA backend currently accepts key sizes below 2048 bits, so
callers must enforce their own minimum.

| Backend | Algorithm | Operations | Required key | Security level | `with_unsafe_crypto` | JOSE encoder | JOSE decoder |
|---|---|---|---|---:|:---:|:---:|:---:|
| `rsa` | `RS256` | Sign, verify | RSA private/public key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `RS384` | Sign, verify | RSA private/public key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `RS512` | Sign, verify | RSA private/public key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `PS256` | Sign, verify | RSA private/public key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `PS384` | Sign, verify | RSA private/public key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `PS512` | Sign, verify | RSA private/public key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `RSA1_5` | Encrypt, decrypt | RSA public/private key; 2048 bits or more recommended | No reliable level; padding-oracle-prone | **Yes** | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `RSA-OAEP` | Encrypt, decrypt | RSA public/private key; 2048 bits or more recommended | At most 80 bits because it uses SHA-1 | **Yes** | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `RSA-OAEP-256` | Encrypt, decrypt | RSA public/private key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `RSA-OAEP-384` | Encrypt, decrypt | RSA public/private key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `rsa` | `RSA-OAEP-512` | Encrypt, decrypt | RSA public/private key; 2048 bits or more recommended | RSA-dependent; 112 bits at RSA-2048 | No | Yes (`RSA`) | Yes (`RSA`) |
| `ec` | `ES256` | Sign, verify | ECDSA P-256 private/public key | 128 bits | No | Yes (`EC`) | Yes (`EC`) |
| `ec` | `ES384` | Sign, verify | ECDSA P-384 private/public key | 192 bits | No | Yes (`EC`) | Yes (`EC`) |
| `ec` | `ES512` | Sign, verify | ECDSA P-521 private/public key | 256 bits | No | Yes (`EC`) | Yes (`EC`) |
| `symetric` | `HS256` | Sign, verify | Symmetric key, at least 32 bytes | 256 bits | No | Yes (`oct`) | Yes (`oct`) |
| `symetric` | `HS384` | Sign, verify | Symmetric key, at least 48 bytes | 384 bits | No | Yes (`oct`) | Yes (`oct`) |
| `symetric` | `HS512` | Sign, verify | Symmetric key, at least 64 bytes | 512 bits | No | Yes (`oct`) | Yes (`oct`) |
| `symetric` | `A128GCM` | Encrypt, decrypt | 16-byte symmetric key | 128 bits | No | Yes (`oct`) | Yes (`oct`) |
| `symetric` | `A192GCM` | Encrypt, decrypt | 24-byte symmetric key | 192 bits | No | Yes (`oct`) | Yes (`oct`) |
| `symetric` | `A256GCM` | Encrypt, decrypt | 32-byte symmetric key | 256 bits | No | Yes (`oct`) | Yes (`oct`) |
| `symetric` | `DES2-ECB` | Encrypt, decrypt | 16-byte DES2 key (`K1 \|\| K2`, expanded to `K1 \|\| K2 \|\| K1`) | About 80 bits; 64-bit block size | **Yes** | Yes (`oct`)* | Yes (`oct`)* |
| `symetric` | `DES2-CBC` | Encrypt, decrypt | 16-byte DES2 key (`K1 \|\| K2`, expanded to `K1 \|\| K2 \|\| K1`) | About 80 bits; 64-bit block size | **Yes** | Yes (`oct`)* | Yes (`oct`)* |

Public RSA and EC material can also be represented by a certificate containing
the corresponding public key. Private material is required for signing and
decryption; public or certificate material is sufficient for verification and
encryption.

The JOSE codecs operate on key material and preserve algorithm restrictions.
They do not independently enable an unsafe backend capability. Consequently,
an unsafe algorithm named in a decoded JWK remains unusable unless the library
was compiled with `with_unsafe_crypto`. Encoding an `oct` key requires the
explicit private-material export policy because symmetric key bytes are secret.

\* `DES2-ECB` and `DES2-CBC` are private algorithm identifiers rather than
IANA-registered JOSE `alg` values. The `oct` JWK codec can preserve them for
application-specific interoperability.
