package jws

import "github.com/veles-security/vcrypt/key"

type JWS struct {
	Header    []byte
	Claims    []byte
	Signature []byte
	Key       key.KeyDescriptor
	Encoded   []byte
}
