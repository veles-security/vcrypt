package key

import (
	"encoding/xml"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/material"
)

// MaterialExportPolicy controls whether an encoder may expose sensitive key
// material. Its zero value permits only public material to be encoded.
type MaterialExportPolicy uint8

const (
	// ExportPublicMaterial permits only public key material and certificates to
	// be encoded.
	ExportPublicMaterial MaterialExportPolicy = iota
	// ExportPrivateMaterial additionally permits private and symmetric key
	// material to be encoded.
	ExportPrivateMaterial
)

// JOSEEncodeOption configures encoding a single key into a JOSE
// representation.
type JOSEEncodeOption struct {
	MaterialPolicy MaterialExportPolicy
}

// JOSEDecodeOption configures decoding a single key from a JOSE
// representation.
type JOSEDecodeOption struct{}

// SAMLEncodeOption configures encoding a single key into a SAML
// representation.
type SAMLEncodeOption struct{}

// SAMLDecodeOption configures decoding a single key from a SAML
// representation.
type SAMLDecodeOption struct{}

// JOSEEncoder encodes a single key as JOSE. SupportsMaterial allows a codec
// registry to select an encoder without attempting an encoding operation.
type JOSEEncoder interface {
	vapi.Encoder[Key, JOSEEncodeOption]
	SupportsMaterial(material.Material) bool
}

// JOSEDecoder decodes a single JOSE key into a candidate. SupportsJOSEKeyType
// allows a codec registry to dispatch using the JOSE kty member.
type JOSEDecoder interface {
	vapi.Decoder[KeyCandidate, JOSEDecodeOption]
	SupportsJOSEKeyType(kty string) bool
}

// SAMLEncoder encodes a single key as SAML. SupportsMaterial allows a codec
// registry to select an encoder without attempting an encoding operation.
type SAMLEncoder interface {
	vapi.Encoder[Key, SAMLEncodeOption]
	SupportsMaterial(material.Material) bool
}

// SAMLDecoder decodes a single SAML key into a candidate. SupportsSAMLKeyType
// allows a codec registry to dispatch using the key representation's XML
// element name.
type SAMLDecoder interface {
	vapi.Decoder[KeyCandidate, SAMLDecodeOption]
	SupportsSAMLKeyType(name xml.Name) bool
}

var _ vapi.Artifact = Key{}
var _ vapi.Artifact = KeyCandidate{}
