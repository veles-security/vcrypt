package backend

import (
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

type Factory interface {
	Supports(material material.Material) bool
	New(material material.Material) key.Backend
}
