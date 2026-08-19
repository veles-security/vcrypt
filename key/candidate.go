package key

import (
	"time"

	"github.com/veles-security/vcrypt/material"
)

type KeyCandidate struct {
	ID           string
	Owner        string
	Source       string
	Restrictions []Capability
	Status       KeyStatus
	Priority     int
	NotBefore    time.Time
	NotAfter     time.Time
	Material     material.Material
}
