package key

import (
	"testing"

	"github.com/veles-security/vcrypt/material"
)

func Test_Key_Material(t *testing.T) {
	input := []byte("secret")
	stored := New(KeyCandidate{Material: &material.SymmetricMaterial{Key: input}}, nil)

	assertIndependent := func(t *testing.T, got material.Material) {
		gotKey := got.(*material.SymmetricMaterial).Key
		input[0] ^= 0xff
		if gotKey[0] == input[0] {
			t.Error("Material() shared bytes with constructor input")
		}
		gotKey[1] ^= 0xff
		again := stored.Material().(*material.SymmetricMaterial).Key
		if again[1] == gotKey[1] {
			t.Error("Material() exposed stored key bytes")
		}
	}
	tests := []struct {
		name      string
		assertion func(*testing.T, material.Material)
	}{
		{name: "Independent Copy", assertion: assertIndependent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, stored.Material())
		})
	}
}
