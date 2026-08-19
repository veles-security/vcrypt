package randomsource

import (
	"testing"
	"time"

	"github.com/veles-security/vcrypt/key"
)

func TestLoadPublishesThreeEpochsAndRetainsKeys(t *testing.T) {
	source, err := New("rotating", ECDSAP256, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	source.now = func() time.Time { return now }

	keys, err := source.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	wantStatuses := []key.KeyStatus{key.KeyStatusPassive, key.KeyStatusActive, key.KeyStatusPassive}
	for i, want := range wantStatuses {
		if keys[i].Status() != want {
			t.Errorf("key %d status = %q, want %q", i, keys[i].Status(), want)
		}
		if got := keys[i].NotAfter().Sub(keys[i].NotBefore()); got != 2*time.Hour {
			t.Errorf("key %d lifetime = %v", i, got)
		}
	}
	if !keys[0].NotBefore().Equal(now.Add(-time.Hour)) || !keys[1].NotBefore().Equal(now) || !keys[2].NotBefore().Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected validity windows: %v, %v, %v", keys[0].NotBefore(), keys[1].NotBefore(), keys[2].NotBefore())
	}

	oldCurrent := keys[1]
	now = now.Add(time.Hour)
	keys, err = source.Load()
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].ID() != oldCurrent.ID() {
		t.Errorf("old active key was not retained: got %q, want %q", keys[0].ID(), oldCurrent.ID())
	}
	if keys[0].Material() != oldCurrent.Material() {
		t.Error("rotation regenerated the old key material")
	}
	if keys[0].Status() != key.KeyStatusPassive {
		t.Errorf("old key status = %q", keys[0].Status())
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		id       string
		typ      KeyType
		lifetime time.Duration
	}{{"", RSA2048, time.Hour}, {"id", "bad", time.Hour}, {"id", RSA2048, 0}} {
		if _, err := New(test.id, test.typ, test.lifetime); err == nil {
			t.Errorf("New(%q, %q, %v) succeeded", test.id, test.typ, test.lifetime)
		}
	}
}
