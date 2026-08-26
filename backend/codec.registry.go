package backend

import (
	"encoding/xml"
	"errors"
	"sync"

	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

var codecs = struct {
	sync.RWMutex
	joseEncoders []key.JOSEEncoder
	joseDecoders []key.JOSEDecoder
	samlEncoders []key.SAMLEncoder
	samlDecoders []key.SAMLDecoder
}{}

// RegisterJOSEEncoder adds an encoder to the JOSE codec registry. A nil
// encoder is ignored. More recently registered encoders take precedence.
func RegisterJOSEEncoder(encoder key.JOSEEncoder) {
	if encoder == nil {
		return
	}
	codecs.Lock()
	defer codecs.Unlock()
	codecs.joseEncoders = append(codecs.joseEncoders, encoder)
}

// JOSEEncoderFor returns the most recently registered JOSE encoder supporting
// the supplied material.
func JOSEEncoderFor(value material.Material) (key.JOSEEncoder, error) {
	if value == nil {
		return nil, errors.New("nil material")
	}
	codecs.RLock()
	encoders := append([]key.JOSEEncoder(nil), codecs.joseEncoders...)
	codecs.RUnlock()
	for i := len(encoders) - 1; i >= 0; i-- {
		if encoders[i].SupportsMaterial(value) {
			return encoders[i], nil
		}
	}
	return nil, errors.New("JOSE encoder: material is not supported")
}

// RegisterJOSEDecoder adds a decoder to the JOSE codec registry. A nil
// decoder is ignored. More recently registered decoders take precedence.
func RegisterJOSEDecoder(decoder key.JOSEDecoder) {
	if decoder == nil {
		return
	}
	codecs.Lock()
	defer codecs.Unlock()
	codecs.joseDecoders = append(codecs.joseDecoders, decoder)
}

// JOSEDecoderFor returns the most recently registered JOSE decoder supporting
// the supplied JOSE kty value.
func JOSEDecoderFor(kty string) (key.JOSEDecoder, error) {
	codecs.RLock()
	decoders := append([]key.JOSEDecoder(nil), codecs.joseDecoders...)
	codecs.RUnlock()
	for i := len(decoders) - 1; i >= 0; i-- {
		if decoders[i].SupportsJOSEKeyType(kty) {
			return decoders[i], nil
		}
	}
	return nil, errors.New("JOSE decoder: key type is not supported")
}

// RegisterSAMLEncoder adds an encoder to the SAML codec registry. A nil
// encoder is ignored. More recently registered encoders take precedence.
func RegisterSAMLEncoder(encoder key.SAMLEncoder) {
	if encoder == nil {
		return
	}
	codecs.Lock()
	defer codecs.Unlock()
	codecs.samlEncoders = append(codecs.samlEncoders, encoder)
}

// SAMLEncoderFor returns the most recently registered SAML encoder supporting
// the supplied material.
func SAMLEncoderFor(value material.Material) (key.SAMLEncoder, error) {
	if value == nil {
		return nil, errors.New("nil material")
	}
	codecs.RLock()
	encoders := append([]key.SAMLEncoder(nil), codecs.samlEncoders...)
	codecs.RUnlock()
	for i := len(encoders) - 1; i >= 0; i-- {
		if encoders[i].SupportsMaterial(value) {
			return encoders[i], nil
		}
	}
	return nil, errors.New("SAML encoder: material is not supported")
}

// RegisterSAMLDecoder adds a decoder to the SAML codec registry. A nil
// decoder is ignored. More recently registered decoders take precedence.
func RegisterSAMLDecoder(decoder key.SAMLDecoder) {
	if decoder == nil {
		return
	}
	codecs.Lock()
	defer codecs.Unlock()
	codecs.samlDecoders = append(codecs.samlDecoders, decoder)
}

// SAMLDecoderFor returns the most recently registered SAML decoder supporting
// the supplied XML element name.
func SAMLDecoderFor(name xml.Name) (key.SAMLDecoder, error) {
	codecs.RLock()
	decoders := append([]key.SAMLDecoder(nil), codecs.samlDecoders...)
	codecs.RUnlock()
	for i := len(decoders) - 1; i >= 0; i-- {
		if decoders[i].SupportsSAMLKeyType(name) {
			return decoders[i], nil
		}
	}
	return nil, errors.New("SAML decoder: key type is not supported")
}
