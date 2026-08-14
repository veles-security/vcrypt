package key

import "time"

type KeyUse string

const (
	KeyUseSigning    KeyUse = "signing"
	KeyUseEncryption KeyUse = "encryption"
)

type KeyOperation string

const (
	KeyOpSign    KeyOperation = "sign"
	KeyOpVerify  KeyOperation = "verify"
	KeyOpEncrypt KeyOperation = "encrypt"
	KeyOpDecrypt KeyOperation = "decrypt"
)

type KeyStatus string

const (
	KeyStatusActive   KeyStatus = "active"
	KeyStatusPassive  KeyStatus = "passive"
	KeyStatusDisabled KeyStatus = "disabled"
)

type Key struct {
	ID     string
	Owner  string
	Source string

	Uses       []KeyUse
	Operations []KeyOperation
	Algorithms []string

	Status    KeyStatus
	Priority  int
	NotBefore time.Time
	NotAfter  time.Time

	Material KeyMaterial
}
