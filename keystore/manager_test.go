package keystore

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veles-security/vcrypt/key"
)

type testSource struct {
	id    string
	load  func() ([]key.Key, error)
	loads atomic.Int32
}

func (s *testSource) ID() string { return s.id }
func (s *testSource) Load() ([]key.Key, error) {
	s.loads.Add(1)
	return s.load()
}

type selfRefreshingTestSource struct {
	*testSource
	callback func([]key.Key) error
}

func (s *selfRefreshingTestSource) SetRefreshCallback(callback func([]key.Key) error) {
	s.callback = callback
}

func TestNewManagerLoadsSourcesConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	source := func(id string) *testSource {
		return &testSource{
			id: id,
			load: func() ([]key.Key, error) {
				started <- struct{}{}
				<-release
				return []key.Key{{ID: id, Source: id}}, nil
			},
		}
	}

	done := make(chan error, 1)
	go func() {
		_, err := NewManager(&store{}, source("one"), source("two"))
		done <- err
	}()
	waitForStarts(t, started, 2)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRefreshAllLoadsSourcesConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	source := func(id string) *testSource {
		var calls atomic.Int32
		return &testSource{
			id: id,
			load: func() ([]key.Key, error) {
				if calls.Add(1) == 1 {
					return nil, nil
				}
				started <- struct{}{}
				<-release
				return nil, nil
			},
		}
	}
	m, err := NewManager(&store{}, source("one"), source("two"))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- m.RefreshAll() }()
	waitForStarts(t, started, 2)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBindLoadsSourceAndRollsBackOnFailure(t *testing.T) {
	m, err := NewManager(&store{})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("load failed")
	source := &testSource{
		id:   "source",
		load: func() ([]key.Key, error) { return nil, want },
	}
	if err := m.Bind(source); !errors.Is(err, want) {
		t.Fatalf("Bind error = %v, want %v", err, want)
	}
	source.load = func() ([]key.Key, error) { return nil, nil }
	if err := m.Bind(source); err != nil {
		t.Fatalf("Bind after failed load: %v", err)
	}
}

func TestManagerRejectsEmptySourceID(t *testing.T) {
	source := &testSource{
		id:   "  ",
		load: func() ([]key.Key, error) { return nil, nil },
	}
	if _, err := NewManager(&store{}, source); err == nil {
		t.Fatal("NewManager accepted an empty source ID")
	}
	m, err := NewManager(&store{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Bind(source); err == nil {
		t.Fatal("Bind accepted an empty source ID")
	}
}

func TestRefreshAllSkipsSelfRefreshingSource(t *testing.T) {
	source := &selfRefreshingTestSource{
		testSource: &testSource{
			id:   "source",
			load: func() ([]key.Key, error) { return []key.Key{{ID: "initial"}}, nil },
		},
	}
	m, err := NewManager(&store{}, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RefreshAll(); err != nil {
		t.Fatal(err)
	}
	if got := source.loads.Load(); got != 1 {
		t.Fatalf("Load calls = %d, want 1", got)
	}
	if source.callback == nil {
		t.Fatal("refresh callback was not set")
	}
	if err := source.callback([]key.Key{{ID: "refreshed", Source: "source"}}); err != nil {
		t.Fatal(err)
	}
	keys, err := m.(*manager).store.Find(t.Context(), WithSource("source"))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != "refreshed" {
		t.Fatalf("stored keys = %#v, want refreshed key", keys)
	}
}

func waitForStarts(t *testing.T, started <-chan struct{}, count int) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for range count {
		select {
		case <-started:
		case <-timer.C:
			t.Fatal("sources did not start concurrently")
		}
	}
}

var _ interface {
	SetRefreshCallback(func([]key.Key) error)
} = (*selfRefreshingTestSource)(nil)
