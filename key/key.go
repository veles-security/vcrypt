package key

import (
	"time"

	"github.com/veles-security/vcrypt/material"
)

type KeyStatus string

const (
	// KeyStatusActive marks a key as eligible for new cryptographic output and
	// for processing existing input. Use it to sign SAML assertions or OAuth 2.0
	// and OIDC tokens, encrypt SAML messages or OIDC data, and verify or decrypt
	// incoming protocol messages.
	KeyStatusActive KeyStatus = "active"
	// KeyStatusPassive marks a rollover key that remains eligible only for
	// processing existing input. Use it to verify SAML assertions or OAuth 2.0
	// and OIDC tokens issued before rotation, or to decrypt messages encrypted
	// to the old key; do not use it to sign or encrypt new messages.
	KeyStatusPassive KeyStatus = "passive"
	// KeyStatusDisabled marks a revoked, compromised, or retired key that must
	// not be used for signing, verification, encryption, or decryption in SAML,
	// OAuth 2.0, or OIDC flows.
	KeyStatusDisabled KeyStatus = "disabled"
)

type Key struct {
	// ID identifies the key. For JWKs, this corresponds to the "kid" member.
	id string
	// Owner identifies the party that owns or publishes the key, typically an
	// OAuth 2.0 authorization server, OpenID Provider issuer, or SAML entity.
	owner string
	// Source identifies the origin from which the key material was obtained,
	// such as a JWKS endpoint or SAML metadata document.
	source string

	// Restrictions lists the restricted combinations of key use,
	// operation, and OAuth 2.0, OpenID Connect, JOSE, or SAML algorithm.
	restrictions []Capability

	// Status controls whether the key is eligible for use in its lifecycle.
	status KeyStatus
	// Priority determines preference when multiple eligible keys match.
	priority int
	// NotBefore is the earliest instant at which the key is valid. A zero value
	// means that no lower validity bound is specified.
	notBefore time.Time
	// NotAfter is the instant after which the key is no longer valid. A zero
	// value means that no upper validity bound is specified.
	notAfter time.Time

	// Material contains the cryptographic key and its representation-specific
	// metadata.
	material material.Material
	backend  Backend
}

// Kind implements [vapi.Artifact].
func (key Key) Kind() string {
	return "key"
}

func New(candidate KeyCandidate, backend Backend) Key {
	return Key{
		id:           candidate.ID,
		owner:        candidate.Owner,
		source:       candidate.Source,
		restrictions: append([]Capability(nil), candidate.Restrictions...),
		status:       candidate.Status,
		priority:     candidate.Priority,
		notBefore:    candidate.NotBefore,
		notAfter:     candidate.NotAfter,
		material:     material.Clone(candidate.Material),
		backend:      backend,
	}
}

func (key Key) ID() string                  { return key.id }
func (key Key) Owner() string               { return key.owner }
func (key Key) Source() string              { return key.source }
func (key Key) Status() KeyStatus           { return key.status }
func (key Key) Priority() int               { return key.priority }
func (key Key) NotBefore() time.Time        { return key.notBefore }
func (key Key) NotAfter() time.Time         { return key.notAfter }
func (key Key) Material() material.Material { return material.Clone(key.material) }
func (key Key) Backend() Backend            { return key.backend }
func (key Key) Restrictions() []Capability {
	return append([]Capability(nil), key.restrictions...)
}
