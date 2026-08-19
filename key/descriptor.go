package key

import (
	"time"

	"github.com/veles-security/vcrypt/material"
)

// KeyDescriptor describes a selected key without exposing private or symmetric
// key material. Material is populated when a public key can be derived and may
// be used by protocol packages to produce representations such as JWKs.
type KeyDescriptor struct {
	ID        string
	Owner     string
	Source    string
	Algorithm KeyAlg

	Restrictions []Capability
	Status       KeyStatus
	Priority     int
	NotBefore    time.Time
	NotAfter     time.Time

	Material *material.PublicMaterial
}

// Descriptor returns the key metadata and, when available, its public
// material. Private and symmetric material are never included.
func (key Key) Descriptor(algorithm KeyAlg) KeyDescriptor {
	var public *material.PublicMaterial
	if value := key.Material(); value != nil {
		public = value.Public()
	}

	return KeyDescriptor{
		ID:           key.ID(),
		Owner:        key.Owner(),
		Source:       key.Source(),
		Algorithm:    algorithm,
		Restrictions: key.Restrictions(),
		Status:       key.Status(),
		Priority:     key.Priority(),
		NotBefore:    key.NotBefore(),
		NotAfter:     key.NotAfter(),
		Material:     public,
	}
}
