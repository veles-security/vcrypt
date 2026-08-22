// Package descriptor encodes and decodes collections of keys in protocol
// descriptor formats.
package descriptor

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/key"
)

// JWKS is a JSON Web Key Set. Encoders consume JWKS[key.Key], while decoders
// produce JWKS[key.KeyCandidate].
type JWKS[A vapi.Artifact] struct {
	Keys []A
}

// Kind implements [vapi.Artifact].
func (JWKS[A]) Kind() string {
	return "jwks"
}

var _ vapi.Artifact = JWKS[key.Key]{}
var _ vapi.Artifact = JWKS[key.KeyCandidate]{}
