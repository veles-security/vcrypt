package jwks

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/key"
)

const JWKSKind = "oauth2:jwks"

type JWKS[K vapi.Artifact] struct {
	Keys []K
}

type JWKSOption[K vapi.Artifact] func(*JWKS[K])

func (JWKS[K]) Kind() string {
	return JWKSKind
}

var _ vapi.Artifact = JWKS[key.Key]{}
var _ vapi.Artifact = JWKS[key.KeyCandidate]{}
